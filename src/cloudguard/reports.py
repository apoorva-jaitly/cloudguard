"""Secret-safe JSON and Markdown report generation for CloudGuard."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from cloudguard.bedrock_review import BedrockReview, ReviewPriority
from cloudguard.evidence import EvidencePackage

_SECRET_KEY_RE = re.compile(
    r"(?:^|[_-])(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|"
    r"access[_-]?key|credential|authorization|session[_-]?key)(?:$|[_-])",
    re.IGNORECASE,
)
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|private[_-]?key)"
    r"\s*[:=]\s*([\"']?)[^\s,\"'}]+(?:\2)"
)
_PEM_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----.*?"
    r"-----END [A-Z0-9 ]+PRIVATE KEY-----",
    re.DOTALL,
)
_REDACTED = "[REDACTED]"

_REQUIRED_SECTIONS = (
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
)


@dataclass(frozen=True, slots=True)
class GeneratedReports:
    report_id: str
    json_report: Mapping[str, object]
    json_text: str
    markdown: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "json_report", MappingProxyType(dict(self.json_report)))


class ReportGenerator:
    def generate(
        self,
        evidence_package: EvidencePackage,
        bedrock_review: BedrockReview | None = None,
    ) -> GeneratedReports:
        if not isinstance(evidence_package, EvidencePackage):
            raise TypeError("evidence_package must be an EvidencePackage")
        if bedrock_review is not None:
            if not isinstance(bedrock_review, BedrockReview):
                raise TypeError("bedrock_review must be a BedrockReview or None")
            if bedrock_review.evidence_package_id != evidence_package.package_id:
                raise ValueError("bedrock_review does not match evidence_package")

        evidence_records = _evidence_records(evidence_package)
        findings = _finding_records(evidence_package)
        known_evidence_ids = {item["evidence_id"] for item in evidence_records}
        for finding in findings:
            missing = set(finding["evidence_ids"]) - known_evidence_ids
            if missing:
                raise ValueError(
                    f"finding {finding['finding_id']} has unreportable evidence IDs"
                )

        findings_by_pillar: dict[str, list[dict[str, object]]] = {}
        for finding in findings:
            findings_by_pillar.setdefault(str(finding["pillar"]), []).append(finding)
        findings_by_pillar = {
            pillar: sorted(items, key=_finding_sort_key)
            for pillar, items in sorted(findings_by_pillar.items())
        }

        critical_high = [
            finding
            for finding in findings
            if finding["severity"] in {"critical", "high"}
        ]
        recommendations = _recommendations(evidence_package, bedrock_review)
        roadmap = _roadmap(evidence_package, bedrock_review)
        assumptions = _assumptions(evidence_package)
        open_questions = _open_questions(evidence_package, bedrock_review)

        report_id = _stable_id(
            "report",
            evidence_package.package_id,
            bedrock_review.schema_version if bedrock_review else "deterministic",
        )
        report: dict[str, object] = {
            "report_id": report_id,
            "evidence_package_id": evidence_package.package_id,
            "generated_at": evidence_package.generated_at.isoformat(),
            "executive_summary": _executive_summary(
                evidence_package, bedrock_review
            ),
            "architecture_overview": _architecture_overview(
                evidence_package, bedrock_review
            ),
            "findings_by_pillar": findings_by_pillar,
            "critical_high_risks": critical_high,
            "evidence": evidence_records,
            "recommendations": recommendations,
            "cost_considerations": _pillar_considerations(
                "cost_optimization", findings_by_pillar, bedrock_review
            ),
            "reliability_considerations": _pillar_considerations(
                "reliability", findings_by_pillar, bedrock_review
            ),
            "security_considerations": _pillar_considerations(
                "security", findings_by_pillar, bedrock_review
            ),
            "operational_readiness": _pillar_considerations(
                "operational_excellence", findings_by_pillar, bedrock_review
            ),
            "prioritized_roadmap": roadmap,
            "assumptions": assumptions,
            "open_questions": open_questions,
        }
        report = _redact(report)
        missing_sections = set(_REQUIRED_SECTIONS) - set(report)
        if missing_sections:
            raise RuntimeError(
                "report is missing sections: " + ", ".join(sorted(missing_sections))
            )
        json_text = json.dumps(
            report,
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
        )
        markdown = _render_markdown(report)
        # Defense in depth after rendering protects against future section changes.
        json_text = _redact_text(json_text)
        markdown = _redact_text(markdown)
        return GeneratedReports(report_id, report, json_text, markdown)


def _finding_records(package: EvidencePackage) -> list[dict[str, object]]:
    available = {item.evidence_id for item in package.evidence}
    records = []
    for finding in package.findings:
        evidence_ids = tuple(finding.evidence_ids)
        # Omitted package evidence remains reportable through explicit placeholders.
        if not evidence_ids:
            raise ValueError(f"finding {finding.finding_id} has no evidence IDs")
        records.append(
            {
                "finding_id": finding.finding_id,
                "pillar": finding.pillar,
                "severity": finding.severity,
                "title": finding.title,
                "description": finding.description,
                "affected_resource_ids": list(finding.affected_resource_ids),
                "evidence_ids": list(evidence_ids),
                "evidence_available": all(
                    evidence_id in available for evidence_id in evidence_ids
                ),
                "recommendation": finding.recommendation,
            }
        )
    return sorted(records, key=_finding_sort_key)


def _evidence_records(package: EvidencePackage) -> list[dict[str, object]]:
    records = [
        {
            "evidence_id": item.evidence_id,
            "source": item.source,
            "timestamp": item.timestamp.isoformat() if item.timestamp else None,
            "affected_resource_id": item.affected_resource_id,
            "kind": item.kind.value,
            "content": item.content,
            "available": True,
        }
        for item in package.evidence
    ]
    present = {item["evidence_id"] for item in records}
    referenced = {
        evidence_id
        for finding in package.findings
        for evidence_id in finding.evidence_ids
    }
    for evidence_id in sorted(referenced - present):
        records.append(
            {
                "evidence_id": evidence_id,
                "source": "evidence-package:omitted",
                "timestamp": None,
                "affected_resource_id": next(
                    (
                        finding.affected_resource_ids[0]
                        for finding in package.findings
                        if evidence_id in finding.evidence_ids
                    ),
                    None,
                ),
                "kind": "omitted",
                "content": {
                    "available": False,
                    "reason": "Evidence was omitted by evidence-package size limits.",
                },
                "available": False,
            }
        )
    return sorted(records, key=lambda item: str(item["evidence_id"]))


def _executive_summary(
    package: EvidencePackage, review: BedrockReview | None
) -> dict[str, object]:
    severity_counts: dict[str, int] = {}
    for finding in package.findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
    summary = (
        review.architecture_summary
        if review
        else (
            f"CloudGuard evaluated {len(package.resources)} affected resources "
            f"and retained {len(package.findings)} deterministic findings."
        )
    )
    return {
        "summary": summary,
        "evidence_ids": (
            list(review.architecture_summary_evidence_ids) if review else []
        ),
        "finding_count": len(package.findings),
        "severity_counts": severity_counts,
        "evidence_item_count": len(package.evidence),
        "omitted_evidence_count": package.omitted_evidence_count,
    }


def _architecture_overview(
    package: EvidencePackage, review: BedrockReview | None
) -> dict[str, object]:
    return {
        "architecture_id": package.architecture_id,
        "resources": [
            {
                "resource_id": resource.resource_id,
                "resource_type": resource.resource_type,
                "name": resource.name,
                "source_location": resource.source_location,
            }
            for resource in package.resources
        ],
        "facts": (
            [
                {
                    "statement": fact.statement,
                    "evidence_excerpt": fact.evidence_excerpt,
                    "evidence_ids": list(fact.evidence_ids),
                    "resource_ids": list(fact.resource_ids),
                }
                for fact in review.facts
            ]
            if review
            else []
        ),
        "architectural_implications": (
            [
                {
                    "title": item.title,
                    "interpretation": item.interpretation,
                    "evidence_ids": list(item.evidence_ids),
                    "resource_ids": list(item.resource_ids),
                    "confidence": item.confidence,
                    "uncertainty": item.uncertainty,
                }
                for item in review.architectural_implications
            ]
            if review
            else []
        ),
    }


def _recommendations(
    package: EvidencePackage, review: BedrockReview | None
) -> list[dict[str, object]]:
    if review and review.remediations:
        return [
            {
                "title": item.title,
                "action": item.action,
                "finding_ids": list(item.finding_ids),
                "evidence_ids": list(item.evidence_ids),
                "tradeoffs": item.tradeoffs,
                "verification": item.verification,
                "source": "bedrock_review",
            }
            for item in review.remediations
        ]
    return [
        {
            "title": f"Address {finding.title.lower()}",
            "action": finding.recommendation,
            "finding_ids": [finding.finding_id],
            "evidence_ids": list(finding.evidence_ids),
            "tradeoffs": "Requires implementation planning and validation.",
            "verification": "Re-run CloudGuard and confirm the finding is resolved.",
            "source": "deterministic_finding",
        }
        for finding in package.findings
    ]


def _roadmap(
    package: EvidencePackage, review: BedrockReview | None
) -> list[dict[str, object]]:
    priorities = (
        {item.finding_id: item for item in review.prioritized_findings}
        if review
        else {}
    )
    severity_priority = {
        "critical": ReviewPriority.P0,
        "high": ReviewPriority.P1,
        "medium": ReviewPriority.P2,
        "low": ReviewPriority.P3,
        "informational": ReviewPriority.P3,
    }
    items = []
    for finding in package.findings:
        reviewed = priorities.get(finding.finding_id)
        priority = (
            reviewed.priority
            if reviewed
            else severity_priority.get(finding.severity, ReviewPriority.P3)
        )
        items.append(
            {
                "priority": priority.value,
                "finding_id": finding.finding_id,
                "title": finding.title,
                "rationale": (
                    reviewed.rationale
                    if reviewed
                    else f"Prioritized from deterministic severity {finding.severity}."
                ),
                "recommendation": finding.recommendation,
                "evidence_ids": list(
                    reviewed.evidence_ids if reviewed else finding.evidence_ids
                ),
            }
        )
    return sorted(
        items,
        key=lambda item: (
            item["priority"],
            item["finding_id"],
        ),
    )


def _pillar_considerations(
    pillar: str,
    findings_by_pillar: Mapping[str, list[dict[str, object]]],
    review: BedrockReview | None,
) -> dict[str, object]:
    implications = []
    if review:
        related_evidence = {
            evidence_id
            for finding in findings_by_pillar.get(pillar, [])
            for evidence_id in finding["evidence_ids"]
        }
        implications = [
            {
                "title": item.title,
                "interpretation": item.interpretation,
                "evidence_ids": list(item.evidence_ids),
                "confidence": item.confidence,
                "uncertainty": item.uncertainty,
            }
            for item in review.architectural_implications
            if set(item.evidence_ids) & related_evidence
        ]
    return {
        "finding_count": len(findings_by_pillar.get(pillar, [])),
        "findings": findings_by_pillar.get(pillar, []),
        "interpretations": implications,
    }


def _assumptions(package: EvidencePackage) -> list[str]:
    assumptions = [
        "The report is limited to the validated evidence package.",
        "Deterministic findings remain authoritative; model text is explanatory.",
        "Missing or unavailable AWS context is not proof that a configuration is absent.",
    ]
    if package.aws_context_status is None:
        assumptions.append("No live AWS context was included.")
    elif package.aws_context_status != "complete":
        assumptions.append(
            f"AWS context collection status was {package.aws_context_status}."
        )
    if package.omitted_evidence_count:
        assumptions.append(
            f"{package.omitted_evidence_count} evidence items were omitted by size limits."
        )
    return assumptions


def _open_questions(
    package: EvidencePackage, review: BedrockReview | None
) -> list[dict[str, object]]:
    questions = []
    if review:
        questions.extend(
            {
                "question": item.description,
                "missing_information": list(item.missing_information),
                "resource_ids": list(item.related_resource_ids),
                "evidence_ids": list(item.related_evidence_ids),
            }
            for item in review.uncertainties
        )
    questions.extend(
        {
            "question": diagnostic["message"],
            "missing_information": [diagnostic["code"]],
            "resource_ids": (
                [diagnostic["affected_resource_id"]]
                if diagnostic.get("affected_resource_id")
                else []
            ),
            "evidence_ids": [],
        }
        for diagnostic in package.aws_context_diagnostics
    )
    return questions


def _render_markdown(report: Mapping[str, object]) -> str:
    lines = [
        "# CloudGuard Architecture Review",
        "",
        f"Report ID: `{report['report_id']}`",
        f"Evidence package: `{report['evidence_package_id']}`",
        f"Generated: {report['generated_at']}",
        "",
        "## Executive summary",
        "",
        _md(report["executive_summary"]["summary"]),  # type: ignore[index]
        "",
        "## Architecture overview",
        "",
    ]
    overview = report["architecture_overview"]  # type: ignore[assignment]
    for resource in overview["resources"]:  # type: ignore[index]
        location = resource.get("source_location") or "unknown source"
        lines.append(
            f"- `{resource['resource_id']}` — {_md(resource['resource_type'])} "
            f"at {_md(location)}"
        )
    lines.extend(["", "## Findings by pillar", ""])
    for pillar, findings in report["findings_by_pillar"].items():  # type: ignore[union-attr]
        lines.extend([f"### {_title(pillar)}", ""])
        if not findings:
            lines.extend(["No findings.", ""])
            continue
        for finding in findings:
            lines.extend(_markdown_finding(finding))

    lines.extend(["## Critical and high risks", ""])
    critical = report["critical_high_risks"]
    if critical:
        for finding in critical:  # type: ignore[union-attr]
            lines.append(
                f"- **{finding['severity'].upper()}** "
                f"`{finding['finding_id']}` — {_md(finding['title'])}"
            )
    else:
        lines.append("No critical or high findings are present in the package.")

    lines.extend(["", "## Recommendations", ""])
    for item in report["recommendations"]:  # type: ignore[union-attr]
        lines.extend(
            [
                f"### {_md(item['title'])}",
                "",
                _md(item["action"]),
                "",
                f"Tradeoffs: {_md(item['tradeoffs'])}",
                "",
                f"Verification: {_md(item['verification'])}",
                "",
                "Evidence: " + _evidence_links(item["evidence_ids"]),
                "",
            ]
        )

    for key, heading in (
        ("cost_considerations", "Cost considerations"),
        ("reliability_considerations", "Reliability considerations"),
        ("security_considerations", "Security considerations"),
        ("operational_readiness", "Operational readiness"),
    ):
        section = report[key]
        lines.extend(
            [
                f"## {heading}",
                "",
                f"Findings: {section['finding_count']}",  # type: ignore[index]
                "",
            ]
        )
        for item in section["interpretations"]:  # type: ignore[index]
            lines.extend(
                [
                    f"- **{_md(item['title'])}:** {_md(item['interpretation'])} "
                    f"(evidence: {_evidence_links(item['evidence_ids'])})"
                ]
            )
        lines.append("")

    lines.extend(["## Prioritized roadmap", ""])
    for item in report["prioritized_roadmap"]:  # type: ignore[union-attr]
        lines.extend(
            [
                f"### {item['priority']} — {_md(item['title'])}",
                "",
                f"Finding: `{item['finding_id']}`",
                "",
                _md(item["rationale"]),
                "",
                f"Recommendation: {_md(item['recommendation'])}",
                "",
                "Evidence: " + _evidence_links(item["evidence_ids"]),
                "",
            ]
        )

    lines.extend(["## Assumptions", ""])
    for assumption in report["assumptions"]:  # type: ignore[union-attr]
        lines.append(f"- {_md(assumption)}")

    lines.extend(["", "## Open questions", ""])
    questions = report["open_questions"]
    if questions:
        for question in questions:  # type: ignore[union-attr]
            lines.append(f"- {_md(question['question'])}")
    else:
        lines.append("No additional open questions were generated.")

    lines.extend(["", "## Evidence", ""])
    for item in report["evidence"]:  # type: ignore[union-attr]
        anchor = _evidence_anchor(item["evidence_id"])
        lines.extend(
            [
                f'<a id="{anchor}"></a>',
                f"### Evidence `{item['evidence_id']}`",
                "",
                f"- Source: `{_md(item['source'])}`",
                f"- Timestamp: `{item['timestamp'] or 'not applicable'}`",
                f"- Resource: `{item['affected_resource_id'] or 'unknown'}`",
                f"- Available: `{str(item['available']).lower()}`",
                "",
            ]
        )
        content = json.dumps(
            item["content"], sort_keys=True, indent=2, ensure_ascii=False
        )
        lines.extend(f"    {line}" for line in content.splitlines())
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _markdown_finding(finding: Mapping[str, object]) -> list[str]:
    return [
        f"#### {_md(finding['title'])}",
        "",
        f"- ID: `{finding['finding_id']}`",
        f"- Severity: **{str(finding['severity']).upper()}**",
        "- Affected resources: "
        + ", ".join(f"`{item}`" for item in finding["affected_resource_ids"]),  # type: ignore[union-attr]
        "- Evidence: " + _evidence_links(finding["evidence_ids"]),  # type: ignore[arg-type]
        "",
        _md(finding["description"]),
        "",
        f"Recommendation: {_md(finding['recommendation'])}",
        "",
    ]


def _evidence_links(evidence_ids: list[str]) -> str:
    return ", ".join(
        f"[`{evidence_id}`](#{_evidence_anchor(evidence_id)})"
        for evidence_id in evidence_ids
    )


def _evidence_anchor(evidence_id: str) -> str:
    safe = re.sub(r"[^a-z0-9-]+", "-", evidence_id.lower()).strip("-")
    return f"evidence-{safe}"


def _finding_sort_key(item: Mapping[str, object]) -> tuple[int, str]:
    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "informational": 4,
    }
    return severity_order.get(str(item["severity"]), 99), str(item["finding_id"])


def _redact(value: object, key: str | None = None) -> object:
    if key is not None and _SECRET_KEY_RE.search(key):
        return _REDACTED
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, Mapping):
        return {
            str(item_key): _redact(item_value, str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, (tuple, list)):
        return [_redact(item) for item in value]
    return value


def _redact_text(value: str) -> str:
    value = _PEM_RE.sub(_REDACTED, value)
    value = _AWS_ACCESS_KEY_RE.sub(_REDACTED, value)
    value = _BEARER_RE.sub(f"Bearer {_REDACTED}", value)
    return _ASSIGNMENT_RE.sub(
        lambda match: f"{match.group(1)}={_REDACTED}", value
    )


def _md(value: object) -> str:
    text = (
        str(value)
        .replace("\r", " ")
        .replace("\n", " ")
        .replace("\\", "\\\\")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    for character in ("`", "*", "_", "[", "]", "(", ")", "#", "!", "|"):
        text = text.replace(character, f"\\{character}")
    return text


def _title(value: str) -> str:
    return value.replace("_", " ").title()


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:20]
    return f"{prefix}.{digest}"
