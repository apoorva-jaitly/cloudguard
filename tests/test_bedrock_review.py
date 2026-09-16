from datetime import UTC, datetime
import json
import unittest
from unittest.mock import Mock

from botocore.exceptions import ClientError

from cloudguard.bedrock_review import (
    BedrockReviewConfig,
    BedrockReviewService,
    BedrockReviewStatus,
    REVIEW_JSON_SCHEMA,
)
from cloudguard.evidence import (
    AggregatedEvidenceItem,
    EvidenceFinding,
    EvidenceKind,
    EvidencePackage,
    EvidenceResource,
)


NOW = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)


def package() -> EvidencePackage:
    provisional = EvidencePackage(
        package_id="evidence-package.test",
        architecture_id="architecture.test",
        generated_at=NOW,
        resources=(
            EvidenceResource(
                "terraform.aws_db_instance.primary",
                "aws_db_instance",
                "primary",
                "main.tf:1:1-10:2",
            ),
        ),
        findings=(
            EvidenceFinding(
                "finding.public-rds",
                "security",
                "critical",
                "RDS database is publicly accessible",
                "The submitted configuration enables public access.",
                ("terraform.aws_db_instance.primary",),
                ("evidence.database",),
                "Disable public access.",
            ),
        ),
        evidence=(
            AggregatedEvidenceItem(
                "evidence.database",
                EvidenceKind.PARSED,
                "main.tf:1:1-10:2",
                None,
                "terraform.aws_db_instance.primary",
                {"publicly_accessible": True},
            ),
        ),
        aws_context_status=None,
        aws_context_diagnostics=(),
        omitted_evidence_count=0,
        omitted_evidence_ids=(),
        serialized_size_bytes=0,
    )
    size = len(provisional.to_json().encode("utf-8"))
    while True:
        current = EvidencePackage(
            provisional.package_id,
            provisional.architecture_id,
            provisional.generated_at,
            provisional.resources,
            provisional.findings,
            provisional.evidence,
            provisional.aws_context_status,
            provisional.aws_context_diagnostics,
            provisional.omitted_evidence_count,
            provisional.omitted_evidence_ids,
            size,
        )
        measured = len(current.to_json().encode("utf-8"))
        if measured == size:
            return current
        size = measured


def valid_output() -> dict:
    return {
        "schema_version": "1.0",
        "evidence_package_id": "evidence-package.test",
        "architecture_summary": "The package contains one RDS database finding.",
        "architecture_summary_evidence_ids": ["evidence.database"],
        "facts": [
            {
                "statement": "The submitted configuration enables public access.",
                "evidence_excerpt": '"publicly_accessible":true',
                "evidence_ids": ["evidence.database"],
                "resource_ids": ["terraform.aws_db_instance.primary"],
            }
        ],
        "architectural_implications": [
            {
                "title": "Expanded network exposure",
                "interpretation": "Public accessibility expands the database boundary.",
                "evidence_ids": ["evidence.database"],
                "resource_ids": ["terraform.aws_db_instance.primary"],
                "confidence": 0.9,
                "uncertainty": "Network controls outside this package are unknown.",
            }
        ],
        "prioritized_findings": [
            {
                "finding_id": "finding.public-rds",
                "priority": "P0",
                "rationale": "Address the critical exposure first.",
                "evidence_ids": ["evidence.database"],
            }
        ],
        "tradeoffs": [
            {
                "decision": "Move database access to private connectivity.",
                "benefits": ["Reduces public exposure."],
                "costs_and_risks": ["Requires a private access path."],
                "evidence_ids": ["evidence.database"],
            }
        ],
        "remediations": [
            {
                "title": "Disable public accessibility",
                "action": "Set the desired outcome to private database access.",
                "finding_ids": ["finding.public-rds"],
                "evidence_ids": ["evidence.database"],
                "tradeoffs": "Clients require private connectivity.",
                "verification": "Re-run the deterministic review.",
            }
        ],
        "uncertainties": [
            {
                "description": "Runtime network controls were not observed.",
                "missing_information": ["Observed security-group configuration."],
                "related_resource_ids": ["terraform.aws_db_instance.primary"],
                "related_evidence_ids": ["evidence.database"],
            }
        ],
    }


def response(payload, *, stop_reason="end_turn"):
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return {
        "output": {"message": {"content": [{"text": text}]}},
        "stopReason": stop_reason,
        "usage": {"inputTokens": 100, "outputTokens": 50, "totalTokens": 150},
    }


class BedrockReviewTests(unittest.TestCase):
    def service(self, client):
        return BedrockReviewService(
            BedrockReviewConfig(
                region="ap-south-1",
                model_id="approved.review-model-v1",
            ),
            client=client,
        )

    def test_valid_review_uses_only_evidence_package_and_no_tools(self) -> None:
        client = Mock()
        client.converse.return_value = response(valid_output())

        result = self.service(client).review(package())

        self.assertEqual(result.status, BedrockReviewStatus.SUCCEEDED)
        self.assertEqual(result.review.evidence_package_id, package().package_id)
        request = client.converse.call_args.kwargs
        self.assertNotIn("toolConfig", request)
        prompt = request["messages"][0]["content"][0]["text"]
        self.assertIn(package().to_json(), prompt)
        self.assertNotIn("<evidence_package>", prompt)
        delimiter = prompt.splitlines()[1]
        self.assertTrue(delimiter.startswith("<cloudguard-evidence-"))
        self.assertEqual(prompt.count(delimiter), 2)
        self.assertEqual(request["modelId"], "approved.review-model-v1")
        schema = json.loads(
            request["outputConfig"]["textFormat"]["structure"]["jsonSchema"]["schema"]
        )
        self.assertEqual(schema, dict(REVIEW_JSON_SCHEMA))

    def test_malformed_json_is_rejected(self) -> None:
        client = Mock()
        client.converse.return_value = response("{not-json")

        result = self.service(client).review(package())

        self.assertEqual(result.status, BedrockReviewStatus.INVALID_OUTPUT)
        self.assertIsNone(result.review)

    def test_unknown_evidence_reference_is_rejected(self) -> None:
        payload = valid_output()
        payload["facts"][0]["evidence_ids"] = ["evidence.invented"]
        client = Mock()
        client.converse.return_value = response(payload)

        result = self.service(client).review(package())

        self.assertEqual(result.status, BedrockReviewStatus.INVALID_OUTPUT)
        self.assertIn("unsupported IDs", result.error)

    def test_unknown_resource_configuration_claim_is_rejected_by_reference(self) -> None:
        payload = valid_output()
        payload["facts"][0]["resource_ids"] = [
            "terraform.aws_db_instance.invented"
        ]
        client = Mock()
        client.converse.return_value = response(payload)

        result = self.service(client).review(package())

        self.assertEqual(result.status, BedrockReviewStatus.INVALID_OUTPUT)
        self.assertIn("unsupported IDs", result.error)

    def test_unknown_finding_cannot_be_prioritized(self) -> None:
        payload = valid_output()
        payload["prioritized_findings"][0]["finding_id"] = "finding.invented"
        client = Mock()
        client.converse.return_value = response(payload)

        result = self.service(client).review(package())

        self.assertEqual(result.status, BedrockReviewStatus.INVALID_OUTPUT)
        self.assertIn("unsupported ID", result.error)

    def test_extra_output_fields_are_rejected(self) -> None:
        payload = valid_output()
        payload["execute_changes"] = True
        client = Mock()
        client.converse.return_value = response(payload)

        result = self.service(client).review(package())

        self.assertEqual(result.status, BedrockReviewStatus.INVALID_OUTPUT)
        self.assertIn("unsupported execute_changes", result.error)

    def test_factual_claim_requires_evidence(self) -> None:
        payload = valid_output()
        payload["facts"][0]["evidence_ids"] = []
        client = Mock()
        client.converse.return_value = response(payload)

        result = self.service(client).review(package())

        self.assertEqual(result.status, BedrockReviewStatus.INVALID_OUTPUT)
        self.assertIn("must not be empty", result.error)

    def test_factual_excerpt_must_exist_in_cited_evidence(self) -> None:
        payload = valid_output()
        payload["facts"][0]["evidence_excerpt"] = "invented configuration"
        client = Mock()
        client.converse.return_value = response(payload)

        result = self.service(client).review(package())

        self.assertEqual(result.status, BedrockReviewStatus.INVALID_OUTPUT)
        self.assertIn("not present in cited evidence", result.error)

    def test_response_size_budget_is_enforced(self) -> None:
        client = Mock()
        client.converse.return_value = response("x" * 20_000)
        service = BedrockReviewService(
            BedrockReviewConfig(
                region="ap-south-1",
                model_id="approved.review-model-v1",
                max_response_bytes=16_000,
            ),
            client=client,
        )

        result = service.review(package())

        self.assertEqual(result.status, BedrockReviewStatus.INVALID_OUTPUT)
        self.assertIn("max_response_bytes", result.error)

    def test_incomplete_model_output_is_handled(self) -> None:
        client = Mock()
        client.converse.return_value = response(
            valid_output(), stop_reason="max_tokens"
        )

        result = self.service(client).review(package())

        self.assertEqual(result.status, BedrockReviewStatus.MODEL_ERROR)
        self.assertEqual(result.stop_reason, "max_tokens")

    def test_bedrock_client_failure_is_handled(self) -> None:
        client = Mock()
        client.converse.side_effect = ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "denied",
                }
            },
            "Converse",
        )

        result = self.service(client).review(package())

        self.assertEqual(result.status, BedrockReviewStatus.MODEL_ERROR)
        self.assertIn("AccessDeniedException", result.error)
        self.assertIsNone(result.review)


if __name__ == "__main__":
    unittest.main()
