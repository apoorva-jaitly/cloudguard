"""Reproducible deterministic and Bedrock-output evaluation utilities."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Mapping

from cloudguard.bedrock_review import ReviewOutputValidationError, validate_review_output
from cloudguard.domain import AWSResource, Architecture, Evidence, EvidenceType
from cloudguard.evidence import EvidenceAggregator, EvidencePackage
from cloudguard.rules import RuleEngine, RuleEngineConfig


@dataclass(frozen=True, slots=True)
class ArchitectureScenario:
    scenario_id: str
    description: str
    resources: tuple[AWSResource, ...]
    enabled_rule_ids: tuple[str, ...]
    expected_rule_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    scenario_id: str
    expected_rule_ids: tuple[str, ...]
    actual_rule_ids: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return self.expected_rule_ids == self.actual_rule_ids


@dataclass(frozen=True, slots=True)
class DeterministicEvaluation:
    results: tuple[ScenarioResult, ...]

    @property
    def passed(self) -> int:
        return sum(item.passed for item in self.results)


@dataclass(frozen=True, slots=True)
class BedrockEvaluation:
    schema_valid: bool
    factual_grounding: float
    evidence_citation: float
    severity_consistency: float
    recommendation_quality: float
    unsupported_claims: int
    validation_error: str | None


def load_scenarios(path: Path) -> tuple[ArchitectureScenario, ...]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list) or len(payload) < 20:
        raise ValueError("evaluation suite must contain at least 20 scenarios")
    known_rules = {rule.id for rule in RuleEngine().rules}
    scenarios: list[ArchitectureScenario] = []
    seen: set[str] = set()
    for index, raw in enumerate(payload):
        if not isinstance(raw, Mapping):
            raise ValueError(f"scenario[{index}] must be an object")
        scenario_id = _text(raw.get("id"), f"scenario[{index}].id")
        if scenario_id in seen:
            raise ValueError(f"duplicate scenario ID: {scenario_id}")
        seen.add(scenario_id)
        enabled = _string_tuple(raw.get("enabled_rule_ids"), "enabled_rule_ids")
        expected = tuple(sorted(_string_tuple(raw.get("expected_rule_ids"), "expected_rule_ids")))
        unknown = (set(enabled) | set(expected)) - known_rules
        if unknown:
            raise ValueError(f"{scenario_id} references unknown rules: {sorted(unknown)}")
        if not set(expected).issubset(enabled):
            raise ValueError(f"{scenario_id} expects a disabled rule")
        raw_resources = raw.get("resources")
        if not isinstance(raw_resources, list) or not raw_resources:
            raise ValueError(f"{scenario_id} must contain resources")
        resources = tuple(
            _resource(scenario_id, resource_index, item)
            for resource_index, item in enumerate(raw_resources)
        )
        scenarios.append(
            ArchitectureScenario(
                scenario_id,
                _text(raw.get("description"), f"{scenario_id}.description"),
                resources,
                enabled,
                expected,
            )
        )
    return tuple(scenarios)


def evaluate_scenarios(
    scenarios: tuple[ArchitectureScenario, ...],
) -> DeterministicEvaluation:
    all_rule_ids = {rule.id for rule in RuleEngine().rules}
    title_to_id = {rule.title: rule.id for rule in RuleEngine().rules}
    results: list[ScenarioResult] = []
    for scenario in scenarios:
        architecture = Architecture(
            id=f"architecture.{scenario.scenario_id}",
            name=scenario.description,
            resources=scenario.resources,
        )
        evidence = _evidence(scenario)
        enabled = set(scenario.enabled_rule_ids)
        engine = RuleEngine(
            RuleEngineConfig({rule_id: rule_id in enabled for rule_id in all_rule_ids})
        )
        evaluation = engine.evaluate(architecture, evidence)
        actual = tuple(sorted(title_to_id[item.title] for item in evaluation.findings))
        results.append(
            ScenarioResult(
                scenario.scenario_id,
                scenario.expected_rule_ids,
                actual,
            )
        )
    return DeterministicEvaluation(tuple(results))


def build_evidence_package(
    scenario: ArchitectureScenario,
    *,
    clock: datetime = datetime(2026, 9, 16, 12, 0, tzinfo=UTC),
) -> EvidencePackage:
    architecture = Architecture(
        id=f"architecture.{scenario.scenario_id}",
        name=scenario.description,
        resources=scenario.resources,
    )
    evidence = _evidence(scenario)
    all_rules = {rule.id for rule in RuleEngine().rules}
    enabled = set(scenario.enabled_rule_ids)
    findings = RuleEngine(
        RuleEngineConfig({item: item in enabled for item in all_rules})
    ).evaluate(architecture, evidence).findings
    return EvidenceAggregator(clock=lambda: clock).aggregate(
        architecture, findings, evidence
    )


def evaluate_bedrock_output(
    payload: object, evidence_package: EvidencePackage
) -> BedrockEvaluation:
    validation_error: str | None = None
    try:
        validate_review_output(payload, evidence_package)
        schema_valid = True
    except (ReviewOutputValidationError, TypeError, ValueError) as error:
        schema_valid = False
        validation_error = str(error)

    root = payload if isinstance(payload, Mapping) else {}
    known_evidence = {item.evidence_id for item in evidence_package.evidence}
    known_resources = {item.resource_id for item in evidence_package.resources}
    known_findings = {item.finding_id for item in evidence_package.findings}
    evidence_content = {
        item.evidence_id: json.dumps(
            _plain(item.content),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        for item in evidence_package.evidence
    }

    unsupported = 0
    citation_checks: list[bool] = []
    grounding_checks: list[bool] = []
    for section, evidence_key in (
        ("facts", "evidence_ids"),
        ("architectural_implications", "evidence_ids"),
        ("prioritized_findings", "evidence_ids"),
        ("tradeoffs", "evidence_ids"),
        ("remediations", "evidence_ids"),
    ):
        for item in _objects(root.get(section)):
            citations = _strings_or_empty(item.get(evidence_key))
            citation_checks.append(bool(citations) and set(citations) <= known_evidence)
            unsupported += len(set(citations) - known_evidence)

    for fact in _objects(root.get("facts")):
        citations = _strings_or_empty(fact.get("evidence_ids"))
        resources = _strings_or_empty(fact.get("resource_ids"))
        excerpt = fact.get("evidence_excerpt")
        excerpt_supported = isinstance(excerpt, str) and any(
            excerpt in evidence_content.get(evidence_id, "") for evidence_id in citations
        )
        grounded = (
            bool(citations)
            and set(citations) <= known_evidence
            and bool(resources)
            and set(resources) <= known_resources
            and excerpt_supported
        )
        grounding_checks.append(grounded)
        unsupported += len(set(resources) - known_resources)
        if isinstance(excerpt, str) and not excerpt_supported:
            unsupported += 1

    severity_by_finding = {
        item.finding_id: item.severity for item in evidence_package.findings
    }
    allowed_priorities = {
        "critical": {"P0"},
        "high": {"P0", "P1"},
        "medium": {"P1", "P2"},
        "low": {"P2", "P3"},
        "informational": {"P3"},
    }
    severity_checks: list[bool] = []
    for item in _objects(root.get("prioritized_findings")):
        finding_id = item.get("finding_id")
        severity = severity_by_finding.get(finding_id) if isinstance(finding_id, str) else None
        severity_checks.append(
            severity is not None and item.get("priority") in allowed_priorities[severity]
        )
        if isinstance(finding_id, str) and finding_id not in known_findings:
            unsupported += 1

    recommendation_checks: list[bool] = []
    for item in _objects(root.get("remediations")):
        finding_ids = _strings_or_empty(item.get("finding_ids"))
        evidence_ids = _strings_or_empty(item.get("evidence_ids"))
        recommendation_checks.append(
            bool(finding_ids)
            and set(finding_ids) <= known_findings
            and bool(evidence_ids)
            and set(evidence_ids) <= known_evidence
            and _minimum_text(item.get("action"), 20)
            and _minimum_text(item.get("verification"), 10)
            and _minimum_text(item.get("tradeoffs"), 10)
        )
        unsupported += len(set(finding_ids) - known_findings)

    summary_citations = _strings_or_empty(root.get("architecture_summary_evidence_ids"))
    citation_checks.append(
        bool(summary_citations) and set(summary_citations) <= known_evidence
    )
    unsupported += len(set(summary_citations) - known_evidence)

    return BedrockEvaluation(
        schema_valid,
        _ratio(grounding_checks),
        _ratio(citation_checks),
        _ratio(severity_checks),
        _ratio(recommendation_checks),
        unsupported,
        validation_error,
    )


def render_regression_report(
    deterministic: DeterministicEvaluation,
    model_evaluations: Mapping[str, BedrockEvaluation],
) -> str:
    lines = [
        "# CloudGuard Evaluation Regression Report",
        "",
        "Generated from versioned local scenarios. No Terraform or AWS mutation is executed.",
        "",
        "## Deterministic rule regression",
        "",
        f"- Scenarios: {len(deterministic.results)}",
        f"- Passed: {deterministic.passed}",
        f"- Failed: {len(deterministic.results) - deterministic.passed}",
        f"- Pass rate: {_percent(deterministic.passed / len(deterministic.results))}",
        "",
        "| Scenario | Expected | Actual | Result |",
        "|---|---|---|---|",
    ]
    for item in deterministic.results:
        lines.append(
            f"| {item.scenario_id} | {_ids(item.expected_rule_ids)} | "
            f"{_ids(item.actual_rule_ids)} | {'PASS' if item.passed else 'FAIL'} |"
        )
    lines.extend(
        [
            "",
            "## Bedrock review-output regression",
            "",
            "| Case | Schema | Grounding | Citations | Severity | Recommendations | Unsupported |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for name, result in model_evaluations.items():
        lines.append(
            f"| {name} | {'PASS' if result.schema_valid else 'FAIL'} | "
            f"{_percent(result.factual_grounding)} | {_percent(result.evidence_citation)} | "
            f"{_percent(result.severity_consistency)} | "
            f"{_percent(result.recommendation_quality)} | {result.unsupported_claims} |"
        )
    lines.extend(
        [
            "",
            "The grounded reference case is a synthetic contract fixture, not a claim about "
            "a particular foundation model. The adversarial case confirms unsupported IDs "
            "and uncited configuration claims are detected.",
            "",
            "## Live Bedrock status",
            "",
            "Not run. Model-specific quality and latency baselines require an explicitly "
            "approved model ID, AWS credentials, region, and cost authorization. The same "
            "grader can score captured JSON output without granting the model AWS access.",
            "",
            "## Regression policy",
            "",
            "- Deterministic scenarios must remain at 100%.",
            "- Accepted model output must pass the strict Review schema.",
            "- Accepted model output must have 100% evidence citation and zero unsupported claims.",
            "- Severity and recommendation scores are tracked by model ID and prompt version.",
            "",
        ]
    )
    return "\n".join(lines)


def _resource(scenario_id: str, index: int, raw: object) -> AWSResource:
    if not isinstance(raw, Mapping):
        raise ValueError(f"{scenario_id}.resources[{index}] must be an object")
    resource_type = _text(raw.get("resource_type"), "resource_type")
    name = _text(raw.get("name"), "name")
    properties = raw.get("properties", {})
    tags = raw.get("tags", {})
    if not isinstance(properties, Mapping) or not isinstance(tags, Mapping):
        raise ValueError("resource properties and tags must be objects")
    return AWSResource(
        id=f"terraform.{resource_type}.{name}",
        resource_type=resource_type,
        name=name,
        properties=properties,
        tags=tags,  # type: ignore[arg-type]
        source_location=f"evaluations/scenarios.json:{scenario_id}:{index + 1}",
    )


def _evidence(scenario: ArchitectureScenario) -> tuple[Evidence, ...]:
    return tuple(
        Evidence(
            id=f"evidence.{scenario.scenario_id}.{index:03d}",
            evidence_type=EvidenceType.DECLARED,
            source=resource.source_location or "evaluations/scenarios.json",
            description=f"Scenario declares {resource.resource_type}.{resource.name}.",
            value={"properties": resource.properties, "tags": resource.tags},
            resource_ids=(resource.id,),
        )
        for index, resource in enumerate(scenario.resources)
    )


def _text(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{path} must be a non-empty string")
    return value


def _string_tuple(value: object, path: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{path} must be an array of strings")
    if len(value) != len(set(value)):
        raise ValueError(f"{path} contains duplicates")
    return tuple(value)


def _objects(value: object) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, Mapping))


def _strings_or_empty(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _minimum_text(value: object, minimum: int) -> bool:
    return isinstance(value, str) and len(value.strip()) >= minimum


def _ratio(checks: list[bool]) -> float:
    return sum(checks) / len(checks) if checks else 0.0


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


def _ids(values: tuple[str, ...]) -> str:
    return ", ".join(values) if values else "none"


def _percent(value: float) -> str:
    return f"{value * 100:.1f}%"
