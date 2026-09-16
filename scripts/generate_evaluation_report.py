"""Generate the checked-in CloudGuard evaluation regression report."""

from __future__ import annotations

import copy
from pathlib import Path

from cloudguard.evaluation import (
    build_evidence_package,
    evaluate_bedrock_output,
    evaluate_scenarios,
    load_scenarios,
    render_regression_report,
)


ROOT = Path(__file__).resolve().parents[1]


def reference_output(package):
    finding = package.findings[0]
    evidence = package.evidence[0]
    resource = package.resources[0]
    return {
        "schema_version": "1.0",
        "evidence_package_id": package.package_id,
        "architecture_summary": "The evidence identifies a publicly accessible database.",
        "architecture_summary_evidence_ids": [evidence.evidence_id],
        "facts": [{
            "statement": "Public accessibility is enabled.",
            "evidence_excerpt": '"publicly_accessible":true',
            "evidence_ids": [evidence.evidence_id],
            "resource_ids": [resource.resource_id],
        }],
        "architectural_implications": [{
            "title": "Expanded exposure",
            "interpretation": "The declared database exposure boundary is broader.",
            "evidence_ids": [evidence.evidence_id],
            "resource_ids": [resource.resource_id],
            "confidence": 0.95,
            "uncertainty": "Runtime network controls were not observed.",
        }],
        "prioritized_findings": [{
            "finding_id": finding.finding_id,
            "priority": "P0",
            "rationale": "The deterministic finding is critical.",
            "evidence_ids": [evidence.evidence_id],
        }],
        "tradeoffs": [{
            "decision": "Use private database connectivity.",
            "benefits": ["Reduces public exposure."],
            "costs_and_risks": ["Requires a private client network path."],
            "evidence_ids": [evidence.evidence_id],
        }],
        "remediations": [{
            "title": "Disable public database access",
            "action": "Set public accessibility to false and provide private connectivity.",
            "finding_ids": [finding.finding_id],
            "evidence_ids": [evidence.evidence_id],
            "tradeoffs": "Clients need an approved private access path.",
            "verification": "Re-run CloudGuard and verify the finding is absent.",
        }],
        "uncertainties": [{
            "description": "Observed runtime controls are unavailable.",
            "missing_information": ["Current security-group and route state."],
            "related_resource_ids": [resource.resource_id],
            "related_evidence_ids": [evidence.evidence_id],
        }],
    }


def main() -> None:
    scenarios = load_scenarios(ROOT / "evaluations" / "scenarios.json")
    deterministic = evaluate_scenarios(scenarios)
    package = build_evidence_package(
        next(item for item in scenarios if item.scenario_id == "public-rds")
    )
    reference = reference_output(package)
    adversarial = copy.deepcopy(reference)
    adversarial["facts"][0]["evidence_ids"] = ["evidence.invented"]
    adversarial["facts"][0]["resource_ids"] = ["terraform.aws_db_instance.invented"]
    adversarial["facts"][0]["evidence_excerpt"] = '"engine":"oracle"'
    adversarial["prioritized_findings"][0]["finding_id"] = "finding.invented"
    report = render_regression_report(
        deterministic,
        {
            "grounded synthetic reference": evaluate_bedrock_output(reference, package),
            "adversarial unsupported claims": evaluate_bedrock_output(adversarial, package),
        },
    )
    (ROOT / "docs" / "evaluation-regression.md").write_text(report, encoding="utf-8")


if __name__ == "__main__":
    main()
