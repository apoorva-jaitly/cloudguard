from datetime import UTC, datetime
import unittest

from cloudguard.aws_context import (
    AWSContextResult,
    AWSFact,
    ContextStatus,
)
from cloudguard.domain import (
    AWSResource,
    Architecture,
    Effort,
    Evidence,
    EvidenceType,
    Finding,
    FindingStatus,
    Pillar,
    Recommendation,
    Severity,
)
from cloudguard.evidence import (
    EvidenceAggregationConfig,
    EvidenceAggregator,
    EvidenceKind,
    EvidencePackageTooLarge,
)


NOW = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)


def recommendation() -> Recommendation:
    return Recommendation(
        id="recommendation.test",
        title="Remove the secret",
        description="Move password=super-secret-value into a managed secret.",
        verification_steps=("Confirm the literal is absent.",),
    )


class EvidenceAggregationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.database = AWSResource(
            id="terraform.aws_db_instance.primary",
            resource_type="aws_db_instance",
            name="primary",
            properties={
                "identifier": "production-db",
                "username": "admin",
                "password": "super-secret-value",
                "unrelated_setting": "not-needed",
            },
            source_location="main.tf:10:1-20:2",
        )
        self.unrelated = AWSResource(
            id="terraform.aws_instance.unrelated",
            resource_type="aws_instance",
            name="unrelated",
            properties={"instance_type": "m7i.large"},
            source_location="main.tf:30:1-35:2",
        )
        self.architecture = Architecture(
            id="architecture.production",
            name="production",
            resources=(self.database, self.unrelated),
        )
        self.parsed = Evidence(
            id="evidence.database",
            evidence_type=EvidenceType.DECLARED,
            source="main.tf:10:1-20:2",
            description="Database includes password=super-secret-value.",
            value={
                "attributes": self.database.properties,
                "access_key": "AKIAABCDEFGHIJKLMNOP",
            },
            resource_ids=(self.database.id,),
        )
        self.unrelated_evidence = Evidence(
            id="evidence.unrelated",
            evidence_type=EvidenceType.DECLARED,
            source="main.tf:30:1-35:2",
            description="Unrelated instance.",
            value={"instance_type": "m7i.large"},
            resource_ids=(self.unrelated.id,),
        )
        self.finding = Finding(
            id="finding.plaintext-secret",
            pillar=Pillar.SECURITY,
            severity=Severity.CRITICAL,
            title="Potential plaintext secret",
            description="A password=super-secret-value literal is present.",
            evidence_ids=(self.parsed.id,),
            affected_resource_ids=(self.database.id,),
            confidence=1.0,
            recommendation=recommendation(),
            estimated_effort=Effort.SMALL,
            estimated_cost_impact=None,
            status=FindingStatus.OPEN,
        )
        self.aws_context = AWSContextResult(
            status=ContextStatus.COMPLETE,
            facts=(
                AWSFact(
                    id="fact.database-encrypted",
                    resource_id=self.database.id,
                    name="storage_encrypted",
                    value=True,
                    source="aws:ap-south-1:rds:describe_db_instances",
                    observed_at=NOW,
                    region="ap-south-1",
                ),
                AWSFact(
                    id="fact.unrelated-state",
                    resource_id=self.unrelated.id,
                    name="state",
                    value="running",
                    source="aws:ap-south-1:ec2:describe_instances",
                    observed_at=NOW,
                    region="ap-south-1",
                ),
            ),
            diagnostics=(),
            region="ap-south-1",
            started_at=NOW,
            completed_at=NOW,
        )

    def aggregator(self, config=None) -> EvidenceAggregator:
        return EvidenceAggregator(config, clock=lambda: NOW)

    def test_redacts_sensitive_keys_and_values(self) -> None:
        package = self.aggregator().aggregate(
            self.architecture,
            (self.finding,),
            (self.parsed, self.unrelated_evidence),
            self.aws_context,
        )

        serialized = package.to_json()
        self.assertNotIn("super-secret-value", serialized)
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", serialized)
        self.assertIn("[REDACTED]", serialized)
        parsed = next(
            item for item in package.evidence if item.kind is EvidenceKind.PARSED
        )
        attributes = parsed.content["value"]["attributes"]
        self.assertEqual(attributes["password"], "[REDACTED]")
        self.assertEqual(parsed.content["value"]["access_key"], "[REDACTED]")

    def test_preserves_parsed_and_aws_provenance(self) -> None:
        package = self.aggregator().aggregate(
            self.architecture,
            (self.finding,),
            (self.parsed,),
            self.aws_context,
        )

        parsed = next(
            item for item in package.evidence if item.kind is EvidenceKind.PARSED
        )
        observed = next(
            item
            for item in package.evidence
            if item.kind is EvidenceKind.AWS_OBSERVED
        )
        self.assertEqual(parsed.source, "main.tf:10:1-20:2")
        self.assertIsNone(parsed.timestamp)
        self.assertEqual(parsed.affected_resource_id, self.database.id)
        self.assertEqual(
            observed.source,
            "aws:ap-south-1:rds:describe_db_instances",
        )
        self.assertEqual(observed.timestamp, NOW)
        self.assertEqual(observed.affected_resource_id, self.database.id)
        self.assertEqual(package.resources[0].source_location, "main.tf:10:1-20:2")

    def test_excludes_irrelevant_resources_and_evidence(self) -> None:
        package = self.aggregator().aggregate(
            self.architecture,
            (self.finding,),
            (self.parsed, self.unrelated_evidence),
            self.aws_context,
        )

        self.assertEqual(
            {item.resource_id for item in package.resources},
            {self.database.id},
        )
        self.assertNotIn(self.unrelated.id, package.to_json())
        self.assertNotIn(self.unrelated_evidence.id, package.to_json())
        self.assertNotIn("fact.unrelated-state", package.to_json())

    def test_large_item_is_replaced_with_bounded_summary(self) -> None:
        oversized = Evidence(
            id="evidence.oversized",
            evidence_type=EvidenceType.DECLARED,
            source="main.tf:10:1",
            description="Large evidence.",
            value={"policy": "x" * 20_000},
            resource_ids=(self.database.id,),
        )
        finding = Finding(
            id="finding.oversized",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            title="Oversized",
            description="Oversized evidence test.",
            evidence_ids=(oversized.id,),
            affected_resource_ids=(self.database.id,),
            confidence=1.0,
            recommendation=recommendation(),
            estimated_effort=Effort.SMALL,
            estimated_cost_impact=None,
            status=FindingStatus.OPEN,
        )
        config = EvidenceAggregationConfig(
            max_context_bytes=8_000,
            max_item_bytes=512,
            max_string_characters=5_000,
        )

        package = self.aggregator(config).aggregate(
            self.architecture, (finding,), (oversized,)
        )

        self.assertLessEqual(package.serialized_size_bytes, 8_000)
        self.assertTrue(package.evidence[0].content["content_omitted"])

    def test_total_context_limit_omits_excess_evidence(self) -> None:
        facts = tuple(
            AWSFact(
                id=f"fact.context-{index}",
                resource_id=self.database.id,
                name=f"fact_{index}",
                value="v" * 300,
                source="aws:ap-south-1:rds:describe_db_instances",
                observed_at=NOW,
                region="ap-south-1",
            )
            for index in range(20)
        )
        context = AWSContextResult(
            ContextStatus.COMPLETE,
            facts,
            (),
            "ap-south-1",
            NOW,
            NOW,
        )
        config = EvidenceAggregationConfig(
            max_context_bytes=4_000,
            max_item_bytes=1_000,
        )

        package = self.aggregator(config).aggregate(
            self.architecture,
            (self.finding,),
            (self.parsed,),
            context,
        )

        self.assertLessEqual(package.serialized_size_bytes, 4_000)
        self.assertGreater(package.omitted_evidence_count, 0)

    def test_required_metadata_over_limit_fails_explicitly(self) -> None:
        finding = Finding(
            id="finding.large-metadata",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            title="T" * 500,
            description="D" * 4_000,
            evidence_ids=(self.parsed.id,),
            affected_resource_ids=(self.database.id,),
            confidence=1.0,
            recommendation=recommendation(),
            estimated_effort=Effort.SMALL,
            estimated_cost_impact=None,
            status=FindingStatus.OPEN,
        )
        config = EvidenceAggregationConfig(
            max_context_bytes=1_024,
            max_item_bytes=256,
            max_string_characters=2_000,
        )

        with self.assertRaises(EvidencePackageTooLarge):
            self.aggregator(config).aggregate(
                self.architecture, (finding,), (self.parsed,)
            )


if __name__ == "__main__":
    unittest.main()
