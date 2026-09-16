from datetime import UTC, datetime
from decimal import Decimal
from types import MappingProxyType
import unittest

from cloudguard.domain import (
    AWSResource,
    Architecture,
    CostDirection,
    CostImpact,
    CostPeriod,
    Effort,
    Evidence,
    EvidenceType,
    Finding,
    FindingStatus,
    Pillar,
    Recommendation,
    RelationshipType,
    RemediationItem,
    RemediationStatus,
    ResourceRelationship,
    Review,
    ReviewStatus,
    Severity,
)


class DomainModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bucket = AWSResource(
            id="resource.bucket",
            resource_type="AWS::S3::Bucket",
            name="audit-bucket",
            properties={"VersioningConfiguration": {"Status": "Suspended"}},
            account_id="123456789012",
            region="us-east-1",
            tags={"Environment": "production"},
        )
        self.role = AWSResource(
            id="resource.role",
            resource_type="AWS::IAM::Role",
            name="writer-role",
        )
        self.evidence = Evidence(
            id="evidence.versioning",
            evidence_type=EvidenceType.DECLARED,
            source="template.yaml#/Resources/AuditBucket",
            description="Bucket versioning is suspended.",
            value={"status": "Suspended"},
            resource_ids=(self.bucket.id,),
        )
        self.relationship = ResourceRelationship(
            id="relationship.writes",
            source_resource_id=self.role.id,
            target_resource_id=self.bucket.id,
            relationship_type=RelationshipType.WRITES_TO,
            evidence_ids=(self.evidence.id,),
            confidence=1.0,
        )
        self.architecture = Architecture(
            id="architecture.production",
            name="Production",
            resources=(self.bucket, self.role),
            relationships=(self.relationship,),
        )
        self.recommendation = Recommendation(
            id="recommendation.enable-versioning",
            title="Enable bucket versioning",
            description="Enable versioning to improve recovery from unintended changes.",
            verification_steps=("Confirm the bucket reports versioning as enabled.",),
        )
        self.finding = Finding(
            id="finding.s3-versioning",
            pillar=Pillar.RELIABILITY,
            severity=Severity.HIGH,
            title="Bucket versioning is disabled",
            description="The production audit bucket does not have versioning enabled.",
            evidence_ids=(self.evidence.id,),
            affected_resource_ids=(self.bucket.id,),
            confidence=1.0,
            recommendation=self.recommendation,
            estimated_effort=Effort.SMALL,
            estimated_cost_impact=CostImpact(
                direction=CostDirection.INCREASE,
                minimum=Decimal("1.00"),
                maximum=Decimal("10.00"),
                period=CostPeriod.MONTHLY,
                rationale="Retained object versions consume additional storage.",
            ),
            status=FindingStatus.OPEN,
        )
        self.remediation = RemediationItem(
            id="remediation.enable-versioning",
            recommendation=self.recommendation,
            finding_ids=(self.finding.id,),
            priority=1,
            status=RemediationStatus.PROPOSED,
        )

    def test_constructs_valid_review(self) -> None:
        review = Review(
            id="review.production",
            architecture=self.architecture,
            evidence=(self.evidence,),
            findings=(self.finding,),
            remediation_items=(self.remediation,),
            status=ReviewStatus.COMPLETED,
            created_at=datetime(2026, 9, 16, 8, tzinfo=UTC),
            completed_at=datetime(2026, 9, 16, 8, 5, tzinfo=UTC),
        )

        self.assertEqual(review.findings[0].severity, Severity.HIGH)
        self.assertEqual(
            review.findings[0].estimated_cost_impact.maximum, Decimal("10.00")
        )

    def test_finding_requires_evidence(self) -> None:
        with self.assertRaisesRegex(ValueError, "evidence_ids must not be empty"):
            Finding(
                id="finding.invalid",
                pillar=Pillar.SECURITY,
                severity=Severity.HIGH,
                title="Invalid finding",
                description="A finding without evidence must be rejected.",
                evidence_ids=(),
                affected_resource_ids=(self.bucket.id,),
                confidence=0.9,
                recommendation=self.recommendation,
                estimated_effort=Effort.SMALL,
                estimated_cost_impact=None,
                status=FindingStatus.OPEN,
            )

    def test_rejects_out_of_range_confidence(self) -> None:
        with self.assertRaisesRegex(ValueError, "between 0.0 and 1.0"):
            ResourceRelationship(
                id="relationship.invalid",
                source_resource_id=self.role.id,
                target_resource_id=self.bucket.id,
                relationship_type=RelationshipType.WRITES_TO,
                evidence_ids=(),
                confidence=1.1,
            )

    def test_rejects_malformed_reference_id(self) -> None:
        with self.assertRaisesRegex(ValueError, "evidence_ids must be"):
            ResourceRelationship(
                id="relationship.invalid",
                source_resource_id=self.role.id,
                target_resource_id=self.bucket.id,
                relationship_type=RelationshipType.WRITES_TO,
                evidence_ids=("contains spaces",),
            )

    def test_rejects_invalid_account_id(self) -> None:
        with self.assertRaisesRegex(ValueError, "exactly 12 digits"):
            AWSResource(
                id="resource.invalid",
                resource_type="AWS::S3::Bucket",
                name="invalid",
                account_id="1234",
            )

    def test_rejects_non_json_resource_properties(self) -> None:
        with self.assertRaisesRegex(TypeError, "non-JSON value"):
            AWSResource(
                id="resource.invalid",
                resource_type="AWS::S3::Bucket",
                name="invalid",
                properties={"bad": object()},
            )

    def test_resource_properties_and_tags_are_immutable(self) -> None:
        self.assertIsInstance(self.bucket.properties, MappingProxyType)
        self.assertIsInstance(self.bucket.tags, MappingProxyType)
        with self.assertRaises(TypeError):
            self.bucket.tags["Environment"] = "development"  # type: ignore[index]

    def test_architecture_rejects_unknown_relationship_resource(self) -> None:
        relationship = ResourceRelationship(
            id="relationship.unknown",
            source_resource_id=self.role.id,
            target_resource_id="resource.missing",
            relationship_type=RelationshipType.WRITES_TO,
            evidence_ids=(),
        )
        with self.assertRaisesRegex(ValueError, "unknown target resource"):
            Architecture(
                id="architecture.invalid",
                name="Invalid",
                resources=(self.bucket, self.role),
                relationships=(relationship,),
            )

    def test_observed_evidence_requires_collection_time(self) -> None:
        with self.assertRaisesRegex(ValueError, "must include collected_at"):
            Evidence(
                id="evidence.observed",
                evidence_type=EvidenceType.OBSERVED,
                source="aws:s3",
                description="Observed bucket configuration.",
                value={},
            )

    def test_review_rejects_unknown_finding_evidence(self) -> None:
        finding = Finding(
            id="finding.unknown-evidence",
            pillar=Pillar.RELIABILITY,
            severity=Severity.MEDIUM,
            title="Unknown evidence",
            description="This finding references evidence outside the review.",
            evidence_ids=("evidence.missing",),
            affected_resource_ids=(self.bucket.id,),
            confidence=0.8,
            recommendation=self.recommendation,
            estimated_effort=Effort.SMALL,
            estimated_cost_impact=None,
            status=FindingStatus.OPEN,
        )
        with self.assertRaisesRegex(ValueError, "references unknown IDs"):
            Review(
                id="review.invalid",
                architecture=self.architecture,
                evidence=(self.evidence,),
                findings=(finding,),
                remediation_items=(),
                status=ReviewStatus.DRAFT,
                created_at=datetime(2026, 9, 16, tzinfo=UTC),
            )

    def test_terminal_review_requires_completion_time(self) -> None:
        with self.assertRaisesRegex(ValueError, "requires completed_at"):
            Review(
                id="review.invalid",
                architecture=self.architecture,
                evidence=(self.evidence,),
                findings=(self.finding,),
                remediation_items=(self.remediation,),
                status=ReviewStatus.COMPLETED,
                created_at=datetime(2026, 9, 16, tzinfo=UTC),
            )

    def test_neutral_cost_impact_requires_zero_range(self) -> None:
        with self.assertRaisesRegex(ValueError, "zero range"):
            CostImpact(
                direction=CostDirection.NEUTRAL,
                minimum=Decimal("1"),
                maximum=Decimal("1"),
                period=CostPeriod.MONTHLY,
            )


if __name__ == "__main__":
    unittest.main()
