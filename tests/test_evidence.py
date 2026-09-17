import unittest
from datetime import UTC, datetime

from cloudguard.aws_context import (
    AWSContextResult,
    AWSFact,
    ContextStatus,
)
from cloudguard.domain import (
    Architecture,
    AWSResource,
    Effort,
    Evidence,
    EvidenceType,
    Finding,
    FindingStatus,
    Pillar,
    Recommendation,
    RelationshipType,
    ResourceRelationship,
    Severity,
)
from cloudguard.evidence import (
    EvidenceAggregationConfig,
    EvidenceAggregator,
    EvidenceKind,
    EvidencePackageTooLarge,
)

NOW = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)


def synthetic_aws_access_key() -> str:
    return "".join(  # noqa: FLY002 - keep credential-shaped fixture out of source
        ("AK", "IA", "ABCD", "EFGH", "IJKL", "MNOP")
    )


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
                "access_key": synthetic_aws_access_key(),
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
        self.assertNotIn(synthetic_aws_access_key(), serialized)
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

    def test_inventory_includes_resources_beyond_findings(self) -> None:
        package = self.aggregator().aggregate(
            self.architecture,
            (self.finding,),
            (self.parsed, self.unrelated_evidence),
            self.aws_context,
        )

        self.assertEqual(
            {item.resource_id for item in package.resources},
            {self.database.id, self.unrelated.id},
        )
        self.assertIn(self.unrelated_evidence.id, package.to_json())
        self.assertIn("fact.unrelated-state", package.to_json())

    def test_clean_architecture_produces_non_empty_inventory(self) -> None:
        package = self.aggregator().aggregate(
            self.architecture,
            (),
            (self.parsed, self.unrelated_evidence),
        )

        self.assertEqual(package.findings, ())
        self.assertEqual(len(package.resources), 2)
        self.assertTrue(package.evidence)
        database = next(
            item for item in package.resources if item.resource_id == self.database.id
        )
        self.assertEqual(database.resource_type, "aws_db_instance")
        self.assertEqual(database.source_location, "main.tf:10:1-20:2")
        self.assertEqual(database.attributes["identifier"], "production-db")

    def test_relationships_are_included_when_parser_established_them(self) -> None:
        relationship = ResourceRelationship(
            id="relationship.instance-database",
            source_resource_id=self.unrelated.id,
            target_resource_id=self.database.id,
            relationship_type=RelationshipType.DEPENDS_ON,
            evidence_ids=(self.unrelated_evidence.id,),
        )
        architecture = Architecture(
            self.architecture.id,
            self.architecture.name,
            self.architecture.resources,
            (relationship,),
        )

        package = self.aggregator().aggregate(
            architecture,
            (),
            (self.parsed, self.unrelated_evidence),
        )

        self.assertEqual(len(package.relationships), 1)
        self.assertEqual(
            package.relationships[0].relationship_type,
            RelationshipType.DEPENDS_ON.value,
        )
        self.assertEqual(
            package.relationships[0].evidence_ids,
            (self.unrelated_evidence.id,),
        )

    def test_positive_controls_are_preserved_but_not_invented(self) -> None:
        controlled = AWSResource(
            id="terraform.aws_s3_bucket.logs",
            resource_type="aws_s3_bucket",
            name="logs",
            properties={"versioning_enabled": True},
            source_location="storage.tf:1:1-5:2",
        )
        package = self.aggregator().aggregate(
            Architecture("architecture.controls", "controls", (controlled,)),
            (),
            (),
        )

        attributes = package.resources[0].attributes
        self.assertIs(attributes["versioning_enabled"], True)
        self.assertNotIn("encryption_enabled", attributes)

    def test_package_id_is_reproducible_across_generation_times(self) -> None:
        first = self.aggregator().aggregate(
            self.architecture, (), (self.parsed, self.unrelated_evidence)
        )
        later = EvidenceAggregator(
            clock=lambda: datetime(2026, 9, 17, 12, 0, tzinfo=UTC)
        ).aggregate(self.architecture, (), (self.parsed, self.unrelated_evidence))

        self.assertEqual(first.package_id, later.package_id)

    def test_trace_metadata_does_not_change_deterministic_package_id(self) -> None:
        first = self.aggregator().aggregate(
            self.architecture,
            (),
            (self.parsed,),
            review_id="review.11111111111111111111111111111111",
            correlation_id="request-one",
        )
        second = self.aggregator().aggregate(
            self.architecture,
            (),
            (self.parsed,),
            review_id="review.22222222222222222222222222222222",
            correlation_id="request-two",
        )

        self.assertEqual(first.package_id, second.package_id)
        self.assertEqual(first.review_id, "review.11111111111111111111111111111111")
        self.assertEqual(second.correlation_id, "request-two")

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
