import copy
import unittest
from pathlib import Path

from cloudguard.evaluation import (
    build_evidence_package,
    evaluate_bedrock_output,
    evaluate_scenarios,
    load_scenarios,
    render_regression_report,
)


ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "evaluations" / "scenarios.json"


def grounded_output(package):
    finding = package.findings[0]
    evidence = package.evidence[0]
    resource = package.resources[0]
    return {
        "schema_version": "1.0",
        "evidence_package_id": package.package_id,
        "architecture_summary": "The evidence identifies a publicly accessible database.",
        "architecture_summary_evidence_ids": [evidence.evidence_id],
        "facts": [
            {
                "statement": "Public accessibility is enabled.",
                "evidence_excerpt": '"publicly_accessible":true',
                "evidence_ids": [evidence.evidence_id],
                "resource_ids": [resource.resource_id],
            }
        ],
        "architectural_implications": [
            {
                "title": "Expanded exposure",
                "interpretation": "The declared database exposure boundary is broader.",
                "evidence_ids": [evidence.evidence_id],
                "resource_ids": [resource.resource_id],
                "confidence": 0.95,
                "uncertainty": "Runtime network controls were not observed.",
            }
        ],
        "prioritized_findings": [
            {
                "finding_id": finding.finding_id,
                "priority": "P0",
                "rationale": "The deterministic finding is critical.",
                "evidence_ids": [evidence.evidence_id],
            }
        ],
        "tradeoffs": [
            {
                "decision": "Use private database connectivity.",
                "benefits": ["Reduces public exposure."],
                "costs_and_risks": ["Requires a private client network path."],
                "evidence_ids": [evidence.evidence_id],
            }
        ],
        "remediations": [
            {
                "title": "Disable public database access",
                "action": "Set public accessibility to false and provide private connectivity.",
                "finding_ids": [finding.finding_id],
                "evidence_ids": [evidence.evidence_id],
                "tradeoffs": "Clients need an approved private access path.",
                "verification": "Re-run CloudGuard and verify the finding is absent.",
            }
        ],
        "uncertainties": [
            {
                "description": "Observed runtime controls are unavailable.",
                "missing_information": ["Current security-group and route state."],
                "related_resource_ids": [resource.resource_id],
                "related_evidence_ids": [evidence.evidence_id],
            }
        ],
    }


class EvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scenarios = load_scenarios(SCENARIOS)
        cls.public_rds = next(item for item in cls.scenarios if item.scenario_id == "public-rds")
        cls.package = build_evidence_package(cls.public_rds)

    def test_suite_has_at_least_twenty_unique_scenarios(self):
        self.assertGreaterEqual(len(self.scenarios), 20)
        self.assertEqual(
            len({item.scenario_id for item in self.scenarios}),
            len(self.scenarios),
        )

    def test_deterministic_expected_findings_all_pass(self):
        result = evaluate_scenarios(self.scenarios)

        failures = [item for item in result.results if not item.passed]
        self.assertEqual(failures, [])
        self.assertEqual(result.passed, len(self.scenarios))

    def test_required_risk_scenarios_are_covered(self):
        expected = {
            "public-rds",
            "single-az-rds",
            "wildcard-iam",
            "missing-encryption",
            "unrestricted-security-group",
            "missing-backups",
            "missing-monitoring",
            "weak-scaling",
            "risky-deployment",
            "expensive-network",
        }
        self.assertTrue(expected.issubset({item.scenario_id for item in self.scenarios}))

    def test_grounded_bedrock_output_scores_cleanly(self):
        result = evaluate_bedrock_output(grounded_output(self.package), self.package)

        self.assertTrue(result.schema_valid)
        self.assertEqual(result.factual_grounding, 1.0)
        self.assertEqual(result.evidence_citation, 1.0)
        self.assertEqual(result.severity_consistency, 1.0)
        self.assertEqual(result.recommendation_quality, 1.0)
        self.assertEqual(result.unsupported_claims, 0)

    def test_unsupported_bedrock_claims_are_counted_and_rejected(self):
        payload = copy.deepcopy(grounded_output(self.package))
        payload["facts"][0]["evidence_ids"] = ["evidence.invented"]
        payload["facts"][0]["resource_ids"] = ["terraform.aws_db_instance.invented"]
        payload["facts"][0]["evidence_excerpt"] = '"engine":"oracle"'
        payload["prioritized_findings"][0]["finding_id"] = "finding.invented"

        result = evaluate_bedrock_output(payload, self.package)

        self.assertFalse(result.schema_valid)
        self.assertEqual(result.factual_grounding, 0.0)
        self.assertGreaterEqual(result.unsupported_claims, 4)

    def test_severity_inconsistency_is_detected(self):
        payload = grounded_output(self.package)
        payload["prioritized_findings"][0]["priority"] = "P3"

        result = evaluate_bedrock_output(payload, self.package)

        self.assertTrue(result.schema_valid)
        self.assertEqual(result.severity_consistency, 0.0)

    def test_weak_recommendation_is_scored_independently_of_schema(self):
        payload = grounded_output(self.package)
        payload["remediations"][0]["action"] = "Fix it."
        payload["remediations"][0]["tradeoffs"] = "None."
        payload["remediations"][0]["verification"] = "Check."

        result = evaluate_bedrock_output(payload, self.package)

        self.assertTrue(result.schema_valid)
        self.assertEqual(result.recommendation_quality, 0.0)

    def test_regression_report_contains_both_evaluation_types(self):
        deterministic = evaluate_scenarios(self.scenarios)
        model = evaluate_bedrock_output(grounded_output(self.package), self.package)

        report = render_regression_report(deterministic, {"reference": model})

        self.assertIn("Deterministic rule regression", report)
        self.assertIn("Bedrock review-output regression", report)
        self.assertIn("Live Bedrock status", report)
        self.assertIn("public-rds", report)


if __name__ == "__main__":
    unittest.main()
