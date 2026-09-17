import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime

from cloudguard.bedrock_review import (
    BedrockReview,
    PrioritizedFinding,
    ReviewPriority,
)
from cloudguard.evidence import (
    AggregatedEvidenceItem,
    EvidenceFinding,
    EvidenceKind,
    EvidencePackage,
    EvidenceResource,
)
from cloudguard.reports import ReportGenerator

NOW = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)


def synthetic_aws_access_key() -> str:
    return "".join(  # noqa: FLY002 - keep credential-shaped fixture out of source
        ("AK", "IA", "ABCD", "EFGH", "IJKL", "MNOP")
    )


def package(*, omit_evidence=False) -> EvidencePackage:
    evidence = (
        ()
        if omit_evidence
        else (
            AggregatedEvidenceItem(
                "evidence.database",
                EvidenceKind.PARSED,
                "main.tf:1:1-10:2",
                None,
                "terraform.aws_db_instance.primary",
                {"publicly_accessible": True},
            ),
        )
    )
    provisional = EvidencePackage(
        "evidence-package.test",
        "architecture.test",
        NOW,
        (
            EvidenceResource(
                "terraform.aws_db_instance.primary",
                "aws_db_instance",
                "primary",
                "main.tf:1:1-10:2",
            ),
        ),
        (
            EvidenceFinding(
                "finding.public-rds",
                "security",
                "critical",
                "RDS database is publicly accessible",
                "Public accessibility is enabled.",
                ("terraform.aws_db_instance.primary",),
                ("evidence.database",),
                "Disable public accessibility.",
            ),
        ),
        evidence,
        None,
        (),
        1 if omit_evidence else 0,
        ("evidence.database",) if omit_evidence else (),
        0,
    )
    size = len(provisional.to_json().encode())
    while True:
        result = EvidencePackage(
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
        measured = len(result.to_json().encode())
        if measured == size:
            return result
        size = measured


def review() -> BedrockReview:
    return BedrockReview(
        schema_version="1.0",
        evidence_package_id="evidence-package.test",
        prioritized_findings=(
            PrioritizedFinding(
                "finding.public-rds",
                ReviewPriority.P0,
                "Resolve public exposure first. password=do-not-leak",
                ("evidence.database",),
                '"publicly_accessible":true',
                f"Use private connectivity. {synthetic_aws_access_key()}",
            ),
        ),
    )


class ReportGeneratorTests(unittest.TestCase):
    def test_generates_all_required_json_sections(self) -> None:
        reports = ReportGenerator().generate(package(), review())
        parsed = json.loads(reports.json_text)

        required = {
            "executive_summary",
            "architecture_overview",
            "findings_by_pillar",
            "critical_high_risks",
            "evidence",
            "recommendations",
            "cost_considerations",
            "reliability_considerations",
            "security_considerations",
            "operational_readiness",
            "prioritized_roadmap",
            "assumptions",
            "open_questions",
        }
        self.assertTrue(required.issubset(parsed))
        self.assertEqual(
            parsed["prioritized_roadmap"][0]["priority"],
            "P0",
        )

    def test_every_finding_links_to_evidence_in_markdown(self) -> None:
        reports = ReportGenerator().generate(package(), review())

        self.assertIn(
            "[`evidence.database`](#evidence-evidence-database)",
            reports.markdown,
        )
        self.assertIn('<a id="evidence-evidence-database"></a>', reports.markdown)

    def test_redacts_secrets_from_json_and_markdown(self) -> None:
        reports = ReportGenerator().generate(package(), review())

        for output in (reports.json_text, reports.markdown):
            self.assertNotIn("do-not-leak", output)
            self.assertNotIn(synthetic_aws_access_key(), output)
            self.assertIn("[REDACTED]", output)

    def test_omitted_evidence_gets_linkable_placeholder(self) -> None:
        reports = ReportGenerator().generate(package(omit_evidence=True))
        parsed = json.loads(reports.json_text)

        self.assertEqual(len(parsed["evidence"]), 1)
        self.assertFalse(parsed["evidence"][0]["available"])
        self.assertIn('<a id="evidence-evidence-database"></a>', reports.markdown)

    def test_deterministic_report_uses_severity_for_roadmap(self) -> None:
        reports = ReportGenerator().generate(package())
        parsed = json.loads(reports.json_text)

        self.assertEqual(parsed["prioritized_roadmap"][0]["priority"], "P0")
        self.assertEqual(
            parsed["recommendations"][0]["source"],
            "deterministic_finding",
        )

    def test_rejects_review_for_another_package(self) -> None:
        mismatched = BedrockReview(
            schema_version="2.0",
            evidence_package_id="evidence-package.other",
            prioritized_findings=(),
        )
        with self.assertRaisesRegex(ValueError, "does not match"):
            ReportGenerator().generate(package(), mismatched)

    def test_model_markdown_is_escaped(self) -> None:
        reviewed = review().prioritized_findings[0]
        injected = replace(
            review(),
            prioritized_findings=(
                replace(
                    reviewed,
                    recommendation="[click](javascript:alert(1)) **important**",
                ),
            ),
        )

        reports = ReportGenerator().generate(package(), injected)

        self.assertNotIn("[click](javascript:alert(1))", reports.markdown)
        self.assertIn(r"\[click\]\(javascript:alert\(1\)\)", reports.markdown)


if __name__ == "__main__":
    unittest.main()
