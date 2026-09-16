from datetime import UTC, datetime, timedelta
import unittest
from unittest.mock import Mock

from botocore.exceptions import ClientError, NoCredentialsError

from cloudguard.aws_context import (
    AWSContextConfig,
    ContextDiagnosticCode,
    ContextStatus,
    ReadOnlyAWSContextProvider,
)
from cloudguard.domain import AWSResource, Architecture, EvidenceType


class MutableClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)
        self.monotonic_value = 100.0

    def now(self) -> datetime:
        return self.value

    def monotonic(self) -> float:
        return self.monotonic_value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)
        self.monotonic_value += seconds


class FakeSession:
    def __init__(self, clients) -> None:
        self.clients = clients
        self.requests = []

    def client(self, service, **kwargs):
        self.requests.append((service, kwargs))
        return self.clients[service]


def architecture(*resources: AWSResource) -> Architecture:
    return Architecture(
        id="architecture.context-test",
        name="context-test",
        resources=tuple(resources),
    )


class AWSContextProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = MutableClock()

    def provider(self, clients, *, ttl=300):
        session = FakeSession(clients)
        provider = ReadOnlyAWSContextProvider(
            AWSContextConfig("ap-south-1", cache_ttl_seconds=ttl),
            session_factory=lambda region: session,
            clock=self.clock.now,
            monotonic=self.clock.monotonic,
        )
        return provider, session

    def test_collects_rds_facts_with_source_region_and_timestamp(self) -> None:
        rds = Mock()
        rds.describe_db_instances.return_value = {
            "DBInstances": [
                {
                    "PubliclyAccessible": False,
                    "MultiAZ": True,
                    "StorageEncrypted": True,
                    "BackupRetentionPeriod": 7,
                    "AvailabilityZone": "ap-south-1a",
                    "DBInstanceStatus": "available",
                }
            ]
        }
        provider, session = self.provider({"rds": rds})
        database = AWSResource(
            id="terraform.aws_db_instance.primary",
            resource_type="aws_db_instance",
            name="primary",
            properties={"identifier": "production-db"},
        )

        result = provider.collect(architecture(database))

        self.assertEqual(result.status, ContextStatus.COMPLETE)
        self.assertEqual(len(result.facts), 6)
        self.assertTrue(
            all(fact.source == "aws:ap-south-1:rds:describe_db_instances" for fact in result.facts)
        )
        self.assertTrue(
            all(fact.observed_at == self.clock.value for fact in result.facts)
        )
        self.assertTrue(all(fact.region == "ap-south-1" for fact in result.facts))
        rds.describe_db_instances.assert_called_once_with(
            DBInstanceIdentifier="production-db"
        )
        self.assertEqual(session.requests[0][1]["region_name"], "ap-south-1")

        generated = result.evidence()
        self.assertTrue(all(item.evidence_type is EvidenceType.OBSERVED for item in generated))
        self.assertTrue(all(item.collected_at == self.clock.value for item in generated))

    def test_caches_successful_responses_until_ttl_expires(self) -> None:
        ec2 = Mock()
        ec2.describe_volumes.return_value = {
            "Volumes": [
                {
                    "Encrypted": True,
                    "AvailabilityZone": "ap-south-1a",
                    "State": "in-use",
                    "Size": 100,
                    "VolumeType": "gp3",
                }
            ]
        }
        provider, _ = self.provider({"ec2": ec2}, ttl=60)
        volume = AWSResource(
            id="terraform.aws_ebs_volume.data",
            resource_type="aws_ebs_volume",
            name="data",
            properties={"volume_id": "vol-0123456789abcdef0"},
        )

        provider.collect(architecture(volume))
        self.clock.advance(30)
        provider.collect(architecture(volume))
        self.assertEqual(ec2.describe_volumes.call_count, 1)

        self.clock.advance(31)
        provider.collect(architecture(volume))
        self.assertEqual(ec2.describe_volumes.call_count, 2)

    def test_missing_credentials_returns_diagnostic_and_no_negative_fact(self) -> None:
        rds = Mock()
        rds.describe_db_instances.side_effect = NoCredentialsError()
        provider, _ = self.provider({"rds": rds})
        database = AWSResource(
            id="terraform.aws_db_instance.primary",
            resource_type="aws_db_instance",
            name="primary",
            properties={"identifier": "production-db"},
        )

        result = provider.collect(architecture(database))

        self.assertEqual(result.status, ContextStatus.UNAVAILABLE)
        self.assertEqual(result.facts, ())
        self.assertEqual(
            result.diagnostics[0].code,
            ContextDiagnosticCode.CREDENTIALS_UNAVAILABLE,
        )

    def test_access_denied_is_graceful_and_not_cached(self) -> None:
        ec2 = Mock()
        ec2.describe_security_groups.side_effect = ClientError(
            {
                "Error": {
                    "Code": "UnauthorizedOperation",
                    "Message": "not authorized",
                }
            },
            "DescribeSecurityGroups",
        )
        provider, _ = self.provider({"ec2": ec2})
        group = AWSResource(
            id="terraform.aws_security_group.web",
            resource_type="aws_security_group",
            name="web",
            properties={"group_id": "sg-0123456789abcdef0"},
        )

        first = provider.collect(architecture(group))
        second = provider.collect(architecture(group))

        self.assertEqual(first.status, ContextStatus.UNAVAILABLE)
        self.assertEqual(first.facts, ())
        self.assertEqual(
            first.diagnostics[0].code, ContextDiagnosticCode.ACCESS_DENIED
        )
        self.assertEqual(ec2.describe_security_groups.call_count, 2)
        self.assertEqual(second.facts, ())

    def test_missing_deployed_identifier_does_not_call_aws(self) -> None:
        rds = Mock()
        provider, _ = self.provider({"rds": rds})
        database = AWSResource(
            id="terraform.aws_db_instance.primary",
            resource_type="aws_db_instance",
            name="primary",
        )

        result = provider.collect(architecture(database))

        self.assertEqual(result.status, ContextStatus.UNAVAILABLE)
        self.assertEqual(result.facts, ())
        self.assertEqual(
            result.diagnostics[0].code,
            ContextDiagnosticCode.IDENTIFIER_UNAVAILABLE,
        )
        rds.describe_db_instances.assert_not_called()

    def test_empty_success_response_is_not_proof_of_absence(self) -> None:
        logs = Mock()
        logs.describe_log_groups.return_value = {"logGroups": []}
        provider, _ = self.provider({"logs": logs})
        log_group = AWSResource(
            id="terraform.aws_cloudwatch_log_group.api",
            resource_type="aws_cloudwatch_log_group",
            name="api",
            properties={"name": "/service/api"},
        )

        result = provider.collect(architecture(log_group))

        self.assertEqual(result.facts, ())
        self.assertEqual(
            result.diagnostics[0].code,
            ContextDiagnosticCode.RESOURCE_NOT_OBSERVED,
        )
        self.assertIn("not treated as proof", result.diagnostics[0].message)

    def test_partial_result_preserves_successful_facts(self) -> None:
        ec2 = Mock()
        ec2.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceType": "t3.small",
                            "State": {"Name": "running"},
                            "Placement": {"AvailabilityZone": "ap-south-1a"},
                        }
                    ]
                }
            ]
        }
        rds = Mock()
        rds.describe_db_instances.side_effect = NoCredentialsError()
        provider, _ = self.provider({"ec2": ec2, "rds": rds})
        instance = AWSResource(
            id="terraform.aws_instance.worker",
            resource_type="aws_instance",
            name="worker",
            properties={"instance_id": "i-0123456789abcdef0"},
        )
        database = AWSResource(
            id="terraform.aws_db_instance.primary",
            resource_type="aws_db_instance",
            name="primary",
            properties={"identifier": "production-db"},
        )

        result = provider.collect(architecture(instance, database))

        self.assertEqual(result.status, ContextStatus.PARTIAL)
        self.assertTrue(result.facts)
        self.assertTrue(result.diagnostics)

    def test_allowlist_contains_only_describe_operations(self) -> None:
        provider, _ = self.provider({})
        self.assertTrue(provider.allowed_operations)
        self.assertTrue(
            all(operation.startswith("describe_") for _, operation in provider.allowed_operations)
        )

    def test_invalid_region_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "valid AWS region"):
            AWSContextConfig("not-a-region")


if __name__ == "__main__":
    unittest.main()
