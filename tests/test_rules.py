import unittest

from cloudguard.domain import (
    AWSResource,
    Architecture,
    Evidence,
    EvidenceType,
    Pillar,
)
from cloudguard.rules import RuleEngine, RuleEngineConfig


ALL_RULE_IDS = tuple(rule.id for rule in RuleEngine().rules)


def resource(
    resource_type: str,
    name: str,
    *,
    properties=None,
    tags=None,
) -> AWSResource:
    return AWSResource(
        id=f"terraform.{resource_type}.{name}",
        resource_type=resource_type,
        name=name,
        properties=properties or {},
        tags=tags or {},
        source_location=f"main.tf:{len(name)}:1",
    )


def evidence_for(resources: tuple[AWSResource, ...]) -> tuple[Evidence, ...]:
    return tuple(
        Evidence(
            id=f"evidence.{index:03d}",
            evidence_type=EvidenceType.DECLARED,
            source=item.source_location or "main.tf:1:1",
            description=f"Terraform declares {item.resource_type}.{item.name}.",
            value={"properties": item.properties},
            resource_ids=(item.id,),
        )
        for index, item in enumerate(resources)
    )


def evaluate_only(rule_id: str, resources: tuple[AWSResource, ...]):
    states = {known_id: known_id == rule_id for known_id in ALL_RULE_IDS}
    engine = RuleEngine(RuleEngineConfig(states))
    architecture = Architecture(
        id="architecture.test",
        name="test",
        resources=resources,
    )
    return engine.evaluate(architecture, evidence_for(resources))


class RuleEngineTests(unittest.TestCase):
    def assert_rule_finds(
        self, rule_id: str, resources: tuple[AWSResource, ...]
    ):
        result = evaluate_only(rule_id, resources)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        definition = next(rule for rule in RuleEngine().rules if rule.id == rule_id)
        self.assertEqual(finding.pillar, definition.pillar)
        self.assertEqual(finding.severity, definition.severity)
        self.assertTrue(finding.evidence_ids)
        self.assertTrue(finding.affected_resource_ids)
        self.assertIn(definition.rationale, finding.description)
        self.assertEqual(
            finding.recommendation.description, definition.remediation
        )
        return finding

    def test_rule_catalog_has_stable_unique_metadata(self) -> None:
        rules = RuleEngine().rules
        self.assertEqual(len(rules), 15)
        self.assertEqual(len({rule.id for rule in rules}), len(rules))
        self.assertTrue(all(rule.id.startswith("CG-") for rule in rules))
        self.assertTrue(all(rule.rationale for rule in rules))
        self.assertTrue(all(rule.remediation for rule in rules))

    def test_single_az_critical_stateful_resource(self) -> None:
        self.assert_rule_finds(
            "CG-REL-001",
            (
                resource(
                    "aws_db_instance",
                    "primary",
                    properties={"availability_zone": "us-east-1a"},
                    tags={"Environment": "production"},
                ),
            ),
        )

    def test_missing_backup_configuration(self) -> None:
        self.assert_rule_finds(
            "CG-REL-002",
            (resource("aws_db_instance", "primary", properties={}),),
        )
        passing = evaluate_only(
            "CG-REL-002",
            (
                resource(
                    "aws_db_instance",
                    "primary",
                    properties={"backup_retention_period": 7},
                ),
            ),
        )
        self.assertEqual(passing.findings, ())

    def test_missing_multi_az_database_configuration(self) -> None:
        self.assert_rule_finds(
            "CG-REL-003",
            (
                resource(
                    "aws_db_instance",
                    "primary",
                    properties={"multi_az": False},
                ),
            ),
        )

    def test_missing_health_check(self) -> None:
        self.assert_rule_finds(
            "CG-REL-004", (resource("aws_lb_target_group", "web"),)
        )
        passing = evaluate_only(
            "CG-REL-004",
            (
                resource(
                    "aws_lb_target_group",
                    "web",
                    properties={
                        "_blocks": (
                            {
                                "type": "health_check",
                                "attributes": {"path": "/health"},
                            },
                        )
                    },
                ),
            ),
        )
        self.assertEqual(passing.findings, ())

    def test_missing_scaling_strategy(self) -> None:
        self.assert_rule_finds(
            "CG-REL-005", (resource("aws_ecs_service", "api"),)
        )

    def test_public_rds(self) -> None:
        self.assert_rule_finds(
            "CG-SEC-001",
            (
                resource(
                    "aws_db_instance",
                    "public",
                    properties={"publicly_accessible": True},
                ),
            ),
        )

    def test_unrestricted_security_group_ingress(self) -> None:
        self.assert_rule_finds(
            "CG-SEC-002",
            (
                resource(
                    "aws_security_group_rule",
                    "open",
                    properties={
                        "type": "ingress",
                        "cidr_blocks": ("0.0.0.0/0",),
                    },
                ),
            ),
        )

    def test_wildcard_iam(self) -> None:
        self.assert_rule_finds(
            "CG-SEC-003",
            (
                resource(
                    "aws_iam_policy",
                    "wildcard",
                    properties={
                        "policy": '{"Statement":[{"Action":"*","Resource":"*"}]}'
                    },
                ),
            ),
        )

    def test_missing_or_disabled_encryption(self) -> None:
        self.assert_rule_finds(
            "CG-SEC-004",
            (
                resource(
                    "aws_ebs_volume",
                    "data",
                    properties={"encrypted": False},
                ),
            ),
        )

    def test_plaintext_secret(self) -> None:
        self.assert_rule_finds(
            "CG-SEC-005",
            (
                resource(
                    "aws_db_instance",
                    "primary",
                    properties={"password": "do-not-store-this"},
                ),
            ),
        )
        referenced = evaluate_only(
            "CG-SEC-005",
            (
                resource(
                    "aws_db_instance",
                    "primary",
                    properties={
                        "password": {
                            "expression": "data.aws_secretsmanager_secret_version.db.secret_string"
                        }
                    },
                ),
            ),
        )
        self.assertEqual(referenced.findings, ())

    def test_missing_monitoring(self) -> None:
        self.assert_rule_finds(
            "CG-OPS-001", (resource("aws_lambda_function", "worker"),)
        )

    def test_missing_deployment_rollback(self) -> None:
        self.assert_rule_finds(
            "CG-OPS-002", (resource("aws_ecs_service", "api"),)
        )
        passing = evaluate_only(
            "CG-OPS-002",
            (
                resource(
                    "aws_ecs_service",
                    "api",
                    properties={
                        "_blocks": (
                            {
                                "type": "deployment_circuit_breaker",
                                "attributes": {
                                    "enable": True,
                                    "rollback": True,
                                },
                            },
                        )
                    },
                ),
            ),
        )
        self.assertEqual(passing.findings, ())

    def test_missing_log_retention(self) -> None:
        self.assert_rule_finds(
            "CG-OPS-003", (resource("aws_cloudwatch_log_group", "api"),)
        )

    def test_potentially_expensive_network_pattern(self) -> None:
        self.assert_rule_finds(
            "CG-COST-001", (resource("aws_nat_gateway", "egress"),)
        )

    def test_always_on_compute_candidate(self) -> None:
        self.assert_rule_finds(
            "CG-COST-002", (resource("aws_instance", "worker"),)
        )

    def test_rule_can_be_disabled(self) -> None:
        item = resource(
            "aws_db_instance",
            "public",
            properties={"publicly_accessible": True},
        )
        architecture = Architecture(
            id="architecture.test",
            name="test",
            resources=(item,),
        )
        result = RuleEngine(
            RuleEngineConfig({"CG-SEC-001": False})
        ).evaluate(architecture, evidence_for((item,)))

        self.assertNotIn(
            "CG-SEC-001",
            {
                rule.id
                for rule in RuleEngine().rules
                if any(
                    finding.title == rule.title for finding in result.findings
                )
            },
        )
        self.assertIn("CG-SEC-001", result.disabled_rule_ids)

    def test_finding_ids_are_reproducible(self) -> None:
        resources = (
            resource(
                "aws_db_instance",
                "public",
                properties={"publicly_accessible": True},
            ),
        )
        first = evaluate_only("CG-SEC-001", resources)
        second = evaluate_only("CG-SEC-001", resources)
        self.assertEqual(first.findings[0].id, second.findings[0].id)

    def test_findings_are_not_emitted_without_evidence(self) -> None:
        item = resource(
            "aws_db_instance",
            "public",
            properties={"publicly_accessible": True},
        )
        architecture = Architecture(
            id="architecture.test",
            name="test",
            resources=(item,),
        )
        result = RuleEngine().evaluate(architecture, ())
        self.assertEqual(result.findings, ())

    def test_rule_pillars_cover_requested_domains(self) -> None:
        pillars = {rule.pillar for rule in RuleEngine().rules}
        self.assertTrue(
            {
                Pillar.RELIABILITY,
                Pillar.SECURITY,
                Pillar.OPERATIONAL_EXCELLENCE,
                Pillar.COST_OPTIMIZATION,
            }.issubset(pillars)
        )

    def test_unknown_rule_configuration_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown rule IDs"):
            RuleEngine(RuleEngineConfig({"CG-UNKNOWN-999": False}))


if __name__ == "__main__":
    unittest.main()
