import unittest
from datetime import UTC, datetime

from cloudguard.aws_context import (
    AWSContextDiagnostic,
    AWSContextResult,
    AWSFact,
    ContextDiagnosticCode,
    ContextStatus,
)
from cloudguard.domain import (
    Architecture,
    AWSResource,
    Evidence,
    EvidenceType,
    Severity,
)
from cloudguard.facts import (
    DeclaredFact,
    FactAvailability,
    FactNormalizer,
    FactProvenance,
    FactReconciler,
    FactSourceType,
    ObservedFact,
    ReconciliationStatus,
    UnknownFact,
)
from cloudguard.rules import RuleEngine, RuleEngineConfig

NOW = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)
RESOURCE_ID = "terraform.aws_db_instance.primary"


def provenance(source_type: FactSourceType) -> FactProvenance:
    return FactProvenance(
        source_type,
        "main.tf:1:1" if source_type is FactSourceType.DECLARED else "aws:rds",
        ("evidence.database",),
        NOW if source_type is FactSourceType.OBSERVED else None,
    )


def declared(value=True) -> DeclaredFact:
    return DeclaredFact(
        "declared-fact.public",
        RESOURCE_ID,
        "publicly_accessible",
        value,
        provenance(FactSourceType.DECLARED),
    )


def observed(value=True) -> ObservedFact:
    return ObservedFact(
        "observed-fact.public",
        RESOURCE_ID,
        "publicly_accessible",
        value,
        provenance(FactSourceType.OBSERVED),
    )


def architecture_and_evidence(publicly_accessible=True):
    resource = AWSResource(
        id=RESOURCE_ID,
        resource_type="aws_db_instance",
        name="primary",
        properties={
            "publicly_accessible": publicly_accessible,
            "_cloudguard": {
                "attribute_sources": {
                    "publicly_accessible": "main.tf:3:3-3:29"
                }
            },
        },
        source_location="main.tf:1:1-5:2",
    )
    architecture = Architecture(
        id="architecture.fact-test",
        name="fact-test",
        resources=(resource,),
    )
    evidence = (
        Evidence(
            id="evidence.database",
            evidence_type=EvidenceType.DECLARED,
            source="main.tf:1:1-5:2",
            description="Terraform declares the database.",
            value={"publicly_accessible": publicly_accessible},
            resource_ids=(resource.id,),
        ),
    )
    return architecture, evidence


class NormalizedFactTests(unittest.TestCase):
    def test_declared_fact_preserves_value_and_provenance(self) -> None:
        fact = declared(False)

        self.assertFalse(fact.value)
        self.assertEqual(fact.availability, FactAvailability.AVAILABLE)
        self.assertEqual(fact.provenance.source_type, FactSourceType.DECLARED)
        self.assertEqual(fact.provenance.evidence_ids, ("evidence.database",))

    def test_observed_fact_requires_timestamped_provenance(self) -> None:
        fact = observed(False)

        self.assertFalse(fact.value)
        self.assertEqual(fact.provenance.source_type, FactSourceType.OBSERVED)
        self.assertEqual(fact.provenance.timestamp, NOW)

    def test_unknown_fact_explicitly_represents_unavailability(self) -> None:
        fact = UnknownFact(
            "unknown-fact.public",
            RESOURCE_ID,
            "publicly_accessible",
            "AWS context was unavailable.",
            FactProvenance(
                FactSourceType.AWS_DIAGNOSTIC,
                "aws:rds:describe_db_instances",
                timestamp=NOW,
            ),
        )

        self.assertEqual(fact.availability, FactAvailability.UNAVAILABLE)
        self.assertNotEqual(fact, False)

    def test_declared_and_observed_agreement(self) -> None:
        normalized = FactReconciler().reconcile(
            (declared(True),), (observed(True),)
        )

        item = normalized.reconciliation(RESOURCE_ID, "publicly_accessible")
        self.assertIsNotNone(item)
        assert item is not None
        self.assertEqual(item.status, ReconciliationStatus.AGREEMENT)
        self.assertTrue(item.policy_value)
        self.assertEqual(normalized.conflicts, ())

    def test_declared_and_observed_conflict_preserves_declared_precedence(self) -> None:
        normalized = FactReconciler().reconcile(
            (declared(True),), (observed(False),)
        )

        item = normalized.reconciliation(RESOURCE_ID, "publicly_accessible")
        self.assertIsNotNone(item)
        assert item is not None
        self.assertEqual(item.status, ReconciliationStatus.CONFLICT)
        self.assertTrue(item.policy_value)
        self.assertEqual(len(normalized.conflicts), 1)
        self.assertTrue(normalized.conflicts[0].declared.value)
        self.assertFalse(normalized.conflicts[0].observed.value)

    def test_unavailable_aws_context_produces_unknown_not_negative_fact(self) -> None:
        architecture, evidence = architecture_and_evidence(True)
        context = AWSContextResult(
            ContextStatus.UNAVAILABLE,
            (),
            (
                AWSContextDiagnostic(
                    ContextDiagnosticCode.CREDENTIALS_UNAVAILABLE,
                    "AWS credentials are unavailable.",
                    "aws:ap-south-1:rds:describe_db_instances",
                    NOW,
                    RESOURCE_ID,
                ),
            ),
            "ap-south-1",
            NOW,
            NOW,
        )

        normalized = FactNormalizer().normalize(architecture, evidence, context)

        self.assertEqual(normalized.observed, ())
        self.assertEqual(len(normalized.unknown), 1)
        self.assertEqual(
            normalized.unknown[0].availability,
            FactAvailability.UNAVAILABLE,
        )
        self.assertTrue(
            normalized.declared_value(RESOURCE_ID, "publicly_accessible")
        )

    def test_normalizer_preserves_declared_and_observed_provenance(self) -> None:
        architecture, evidence = architecture_and_evidence(False)
        context = AWSContextResult(
            ContextStatus.COMPLETE,
            (
                AWSFact(
                    "fact.public-access",
                    RESOURCE_ID,
                    "publicly_accessible",
                    False,
                    "aws:ap-south-1:rds:describe_db_instances",
                    NOW,
                    "ap-south-1",
                ),
            ),
            (),
            "ap-south-1",
            NOW,
            NOW,
        )

        normalized = FactNormalizer().normalize(architecture, evidence, context)

        declared_fact = normalized.declared_fact(
            RESOURCE_ID, "publicly_accessible"
        )
        self.assertIsNotNone(declared_fact)
        assert declared_fact is not None
        self.assertEqual(
            declared_fact.provenance.source_identifier,
            "main.tf:3:3-3:29",
        )
        self.assertEqual(
            declared_fact.provenance.evidence_ids,
            ("evidence.database",),
        )
        self.assertEqual(
            normalized.observed[0].provenance.source_identifier,
            "aws:ap-south-1:rds:describe_db_instances",
        )
        self.assertEqual(
            normalized.observed[0].provenance.evidence_ids,
            ("fact.public-access",),
        )

    def test_observed_conflict_does_not_change_finding_or_severity(self) -> None:
        architecture, evidence = architecture_and_evidence(True)
        context = AWSContextResult(
            ContextStatus.COMPLETE,
            (
                AWSFact(
                    "fact.public-access",
                    RESOURCE_ID,
                    "publicly_accessible",
                    False,
                    "aws:ap-south-1:rds:describe_db_instances",
                    NOW,
                    "ap-south-1",
                ),
            ),
            (),
            "ap-south-1",
            NOW,
            NOW,
        )
        states = {
            rule.id: rule.id == "CG-SEC-001" for rule in RuleEngine().rules
        }

        result = RuleEngine(RuleEngineConfig(states)).evaluate(
            architecture, evidence, aws_context=context
        )

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].severity, Severity.CRITICAL)
        reconciliation = result.normalized_facts.reconciliation(
            RESOURCE_ID, "publicly_accessible"
        )
        self.assertIsNotNone(reconciliation)
        assert reconciliation is not None
        self.assertEqual(reconciliation.status, ReconciliationStatus.CONFLICT)

    def test_terraform_only_rule_behavior_is_unchanged(self) -> None:
        architecture, evidence = architecture_and_evidence(True)
        states = {
            rule.id: rule.id == "CG-SEC-001" for rule in RuleEngine().rules
        }
        engine = RuleEngine(RuleEngineConfig(states))

        baseline = engine.evaluate(architecture, evidence)
        explicit_declared_facts = FactNormalizer().normalize(
            architecture, evidence
        )
        normalized = engine.evaluate(
            architecture,
            evidence,
            normalized_facts=explicit_declared_facts,
        )

        self.assertEqual(baseline.findings, normalized.findings)
        self.assertEqual(
            baseline.evaluated_rule_ids, normalized.evaluated_rule_ids
        )


if __name__ == "__main__":
    unittest.main()
