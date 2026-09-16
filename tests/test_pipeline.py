import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from cloudguard.aws_context import (
    AWSContextDiagnostic,
    AWSContextResult,
    AWSFact,
    ContextDiagnosticCode,
    ContextStatus,
)
from cloudguard.bedrock_review import (
    BedrockReview,
    BedrockReviewResult,
    BedrockReviewStatus,
    PrioritizedFinding,
    ReviewPriority,
)
from cloudguard.evidence import EvidenceAggregator
from cloudguard.iac import IaCDocument, IaCInput
from cloudguard.pipeline import (
    PipelineFailureKind,
    PipelineState,
    ReviewPipeline,
    ReviewPipelineInput,
)
from cloudguard.reports import ReportGenerator
from cloudguard.repository import ReviewRepository
from cloudguard.terraform import TerraformAdapter

NOW = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)
TERRAFORM = """
resource "aws_db_instance" "primary" {
  identifier          = "production-db"
  publicly_accessible = true
  storage_encrypted   = false
}
"""


class ContextProvider:
    region = "ap-south-1"

    def __init__(self, result: AWSContextResult | Exception) -> None:
        self.result = result

    def collect(self, architecture):
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class SuccessfulAIProvider:
    def __init__(self) -> None:
        self.calls = 0

    def review(self, evidence_package):
        self.calls += 1
        finding = evidence_package.findings[0]
        evidence = evidence_package.evidence[0]
        review = BedrockReview(
            "2.0",
            evidence_package.package_id,
            (
                PrioritizedFinding(
                    finding.finding_id,
                    ReviewPriority.P0,
                    "Review the cited deterministic finding first.",
                    (evidence.evidence_id,),
                    '"publicly_accessible":true',
                    None,
                ),
            ),
        )
        return BedrockReviewResult(
            BedrockReviewStatus.SUCCEEDED,
            review,
            None,
            "end_turn",
            {},
        )


class InvalidAIProvider:
    def review(self, evidence_package):
        return BedrockReviewResult(
            BedrockReviewStatus.INVALID_OUTPUT,
            None,
            "unsupported evidence reference",
            "end_turn",
            {},
        )


class FailingIaCAdapter:
    adapter_id = "failing-test-adapter"

    def parse(self, iac_input):
        raise RuntimeError("adapter failed")


class FailingEvidenceAggregator(EvidenceAggregator):
    def aggregate(self, *args, **kwargs):
        raise ValueError("evidence failed")


class FailingReportGenerator(ReportGenerator):
    def generate(self, *args, **kwargs):
        raise ValueError("report failed")


class FailingCompleteRepository:
    def __init__(self, delegate: ReviewRepository) -> None:
        self.delegate = delegate

    def create_or_get(self, **kwargs):
        return self.delegate.create_or_get(**kwargs)

    def complete(self, *args, **kwargs):
        raise RuntimeError("database unavailable")

    def start_processing(self, *args, **kwargs):
        return self.delegate.start_processing(*args, **kwargs)

    def fail(self, *args, **kwargs):
        return self.delegate.fail(*args, **kwargs)


class ReviewPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repository = ReviewRepository(Path(self.temp.name) / "reviews.db")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def pipeline_input(self, **changes) -> ReviewPipelineInput:
        values = {
            "review_id": "review.11111111111111111111111111111111",
            "correlation_id": "correlation.test",
            "idempotency_key": "pipeline-test",
            "request_hash": "a" * 64,
            "iac_input": IaCInput((IaCDocument("main.tf", TERRAFORM),)),
            "rule_states": {},
            "enable_aws_context": False,
            "enable_bedrock": False,
        }
        values.update(changes)
        return ReviewPipelineInput(**values)

    def pipeline(self, **kwargs) -> ReviewPipeline:
        return ReviewPipeline(
            self.repository,
            TerraformAdapter(),
            clock=lambda: NOW,
            **kwargs,
        )

    def test_terraform_only_review_completes_offline(self) -> None:
        result = self.pipeline().run(self.pipeline_input())

        self.assertEqual(result.state, PipelineState.COMPLETED)
        self.assertIsNone(result.aws_context)
        self.assertIsNone(result.ai_interpretation)
        self.assertTrue(result.deterministic_findings)
        self.assertTrue(result.evidence_package.resources)
        self.assertIsNotNone(result.report)
        self.assertEqual(result.stored_review.status, "completed")

    def test_aws_context_available_is_reconciled(self) -> None:
        context = AWSContextResult(
            ContextStatus.COMPLETE,
            (
                AWSFact(
                    "fact.database-encryption",
                    "terraform.aws_db_instance.primary",
                    "storage_encrypted",
                    True,
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
        result = self.pipeline(
            aws_context_provider=ContextProvider(context)
        ).run(self.pipeline_input(enable_aws_context=True))

        self.assertEqual(result.aws_context.status, ContextStatus.COMPLETE)
        self.assertTrue(result.normalized_facts.observed)
        self.assertTrue(result.normalized_facts.conflicts)

    def test_aws_context_unavailable_becomes_unknown_not_absent(self) -> None:
        offline = self.pipeline().run(
            self.pipeline_input(
                review_id="review.33333333333333333333333333333333",
                idempotency_key="offline-baseline",
            )
        )
        result = self.pipeline(
            aws_context_provider=ContextProvider(RuntimeError("offline"))
        ).run(self.pipeline_input(enable_aws_context=True, request_hash="b" * 64))

        self.assertEqual(result.state, PipelineState.PARTIAL)
        self.assertEqual(result.stored_review.status, "partial")
        self.assertEqual(result.aws_context.status, ContextStatus.UNAVAILABLE)
        self.assertTrue(result.normalized_facts.unknown)
        self.assertTrue(result.deterministic_findings)
        self.assertIn("not inferred", result.aws_context.diagnostics[0].message)
        self.assertEqual(
            [
                (item.id, item.affected_resource_ids, item.severity)
                for item in result.deterministic_findings
            ],
            [
                (item.id, item.affected_resource_ids, item.severity)
                for item in offline.deterministic_findings
            ],
        )

    def test_aws_context_partial_failure_is_explicit(self) -> None:
        context = AWSContextResult(
            ContextStatus.PARTIAL,
            (
                AWSFact(
                    "fact.database-encryption",
                    "terraform.aws_db_instance.primary",
                    "storage_encrypted",
                    True,
                    "aws:ap-south-1:rds:describe_db_instances",
                    NOW,
                    "ap-south-1",
                ),
            ),
            (
                AWSContextDiagnostic(
                    ContextDiagnosticCode.ACCESS_DENIED,
                    "A secondary observation was denied.",
                    "aws:ap-south-1:rds",
                    NOW,
                    "terraform.aws_db_instance.primary",
                ),
            ),
            "ap-south-1",
            NOW,
            NOW,
        )
        result = self.pipeline(
            aws_context_provider=ContextProvider(context)
        ).run(self.pipeline_input(enable_aws_context=True))

        self.assertEqual(result.state, PipelineState.PARTIAL)
        self.assertEqual(result.stored_review.status, "partial")
        self.assertTrue(result.aws_context.facts)
        self.assertTrue(
            any(item.code == "access_denied" for item in result.diagnostics)
        )

    def test_bedrock_disabled_keeps_deterministic_report(self) -> None:
        provider = SuccessfulAIProvider()
        result = self.pipeline(bedrock_provider=provider).run(
            self.pipeline_input(enable_bedrock=False)
        )

        self.assertEqual(result.state, PipelineState.COMPLETED)
        self.assertIsNone(result.ai_interpretation)
        self.assertTrue(result.report.json_report["findings_by_pillar"])
        self.assertEqual(provider.calls, 0)

    def test_bedrock_enabled_uses_mocked_validated_provider(self) -> None:
        result = self.pipeline(
            bedrock_provider=SuccessfulAIProvider()
        ).run(self.pipeline_input(enable_bedrock=True))

        self.assertEqual(result.state, PipelineState.COMPLETED)
        self.assertIsNotNone(result.ai_interpretation)
        self.assertEqual(
            result.ai_interpretation.evidence_package_id,
            result.evidence_package.package_id,
        )

    def test_ai_validation_failure_is_partial_and_findings_remain_authoritative(
        self,
    ) -> None:
        result = self.pipeline(
            bedrock_provider=InvalidAIProvider()
        ).run(self.pipeline_input(enable_bedrock=True))

        self.assertEqual(result.state, PipelineState.PARTIAL)
        self.assertEqual(result.stored_review.status, "partial")
        self.assertIsNone(result.ai_interpretation)
        self.assertTrue(result.deterministic_findings)
        self.assertEqual(
            len(result.deterministic_findings),
            result.stored_review.finding_count,
        )
        self.assertTrue(
            any(item.code == "bedrock_invalid_output" for item in result.diagnostics)
        )

    def test_parser_failure_is_persisted(self) -> None:
        result = self.pipeline().run(
            self.pipeline_input(
                iac_input=IaCInput(
                    (
                        IaCDocument(
                            "main.tf",
                            'resource "aws_s3_bucket" "broken" {',
                        ),
                    )
                )
            )
        )

        self.assertEqual(result.state, PipelineState.FAILED)
        self.assertEqual(result.failure_kind, PipelineFailureKind.PARSER)
        self.assertEqual(result.stored_review.status, "failed")
        self.assertIsNone(result.report)

    def test_adapter_failure_is_a_parser_stage_failure(self) -> None:
        result = ReviewPipeline(
            self.repository,
            FailingIaCAdapter(),
            clock=lambda: NOW,
        ).run(self.pipeline_input())

        self.assertEqual(result.state, PipelineState.FAILED)
        self.assertEqual(result.failure_kind, PipelineFailureKind.PARSER)
        self.assertEqual(result.stored_review.status, "failed")
        self.assertTrue(
            any(item.code == "iac_adapter_failed" for item in result.diagnostics)
        )

    def test_evidence_generation_failure_is_explicit(self) -> None:
        result = self.pipeline(
            evidence_aggregator=FailingEvidenceAggregator()
        ).run(self.pipeline_input())

        self.assertEqual(result.failure_kind, PipelineFailureKind.EVIDENCE)
        self.assertEqual(result.state, PipelineState.PARTIAL)
        self.assertEqual(result.stored_review.status, "partial")
        self.assertTrue(result.deterministic_findings)

    def test_report_generation_failure_is_explicit(self) -> None:
        result = self.pipeline(
            report_generator=FailingReportGenerator()
        ).run(self.pipeline_input())

        self.assertEqual(result.failure_kind, PipelineFailureKind.REPORT)
        self.assertEqual(result.state, PipelineState.PARTIAL)
        self.assertEqual(result.stored_review.status, "partial")
        self.assertIsNotNone(result.evidence_package)
        self.assertIsNone(result.report)

    def test_persistence_completion_failure_preserves_in_memory_result(self) -> None:
        repository = FailingCompleteRepository(self.repository)
        result = ReviewPipeline(
            repository,
            TerraformAdapter(),
            clock=lambda: NOW,
        ).run(
            self.pipeline_input()
        )

        self.assertEqual(result.failure_kind, PipelineFailureKind.PERSISTENCE)
        self.assertEqual(result.state, PipelineState.FAILED)
        self.assertIsNone(result.stored_review)
        self.assertIsNotNone(result.report)

    def test_review_and_correlation_ids_are_preserved(self) -> None:
        pipeline_input = self.pipeline_input(
            review_id="review.22222222222222222222222222222222",
            correlation_id="request-42",
            idempotency_key="correlation-test",
        )
        result = self.pipeline().run(pipeline_input)

        self.assertEqual(result.review_id, pipeline_input.review_id)
        self.assertEqual(result.correlation_id, "request-42")
        self.assertEqual(result.stored_review.review_id, pipeline_input.review_id)
        self.assertEqual(result.evidence_package.review_id, pipeline_input.review_id)
        self.assertEqual(result.evidence_package.correlation_id, "request-42")
        self.assertEqual(
            result.report.json_report["review_id"], pipeline_input.review_id
        )
        self.assertEqual(
            result.report.json_report["correlation_id"], "request-42"
        )
        self.assertEqual(
            result.stored_review.report_json["review_id"], pipeline_input.review_id
        )
        self.assertIn(PipelineState.REPORTED, result.completed_stages)

    def test_idempotent_replay_uses_persisted_review_id(self) -> None:
        first = self.pipeline().run(self.pipeline_input())
        replay = self.pipeline().run(
            self.pipeline_input(
                review_id="review.44444444444444444444444444444444",
                correlation_id="replay-request",
            )
        )

        self.assertFalse(replay.created)
        self.assertEqual(replay.review_id, first.review_id)
        self.assertEqual(replay.stored_review.review_id, first.review_id)
        self.assertEqual(replay.correlation_id, "replay-request")

    def test_multiple_documents_follow_same_normalized_pipeline(self) -> None:
        result = self.pipeline().run(
            self.pipeline_input(
                iac_input=IaCInput(
                    (
                        IaCDocument(
                            "database.tf",
                            TERRAFORM,
                        ),
                        IaCDocument(
                            "storage.tf",
                            'resource "aws_s3_bucket" "logs" {}',
                        ),
                    )
                )
            )
        )

        self.assertEqual(result.state, PipelineState.COMPLETED)
        self.assertEqual(len(result.architecture.resources), 2)
        self.assertEqual(
            {item.resource_id for item in result.evidence_package.resources},
            {
                "terraform.aws_db_instance.primary",
                "terraform.aws_s3_bucket.logs",
            },
        )


if __name__ == "__main__":
    unittest.main()
