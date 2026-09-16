"""Evidence aggregation, minimization, provenance, redaction, and size bounds."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Callable, Mapping

from cloudguard.aws_context import AWSContextResult
from cloudguard.domain import Architecture, Evidence, Finding, JsonValue

_REDACTED = "[REDACTED]"
_SENSITIVE_KEY_RE = re.compile(
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
_URL_CREDENTIAL_RE = re.compile(r"(https?://[^:/\s]+:)[^@\s/]+@")
_PEM_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----.*?"
    r"-----END [A-Z0-9 ]+PRIVATE KEY-----",
    re.DOTALL,
)


class EvidenceKind(StrEnum):
    PARSED = "parsed"
    AWS_OBSERVED = "aws_observed"


@dataclass(frozen=True, slots=True)
class EvidenceAggregationConfig:
    max_context_bytes: int = 64_000
    max_item_bytes: int = 8_000
    max_string_characters: int = 2_000
    max_collection_items: int = 100

    def __post_init__(self) -> None:
        if (
            type(self.max_context_bytes) is not int
            or not 1_024 <= self.max_context_bytes <= 10_000_000
        ):
            raise ValueError("max_context_bytes must be between 1024 and 10000000")
        if (
            type(self.max_item_bytes) is not int
            or not 256 <= self.max_item_bytes <= self.max_context_bytes
        ):
            raise ValueError(
                "max_item_bytes must be between 256 and max_context_bytes"
            )
        if (
            type(self.max_string_characters) is not int
            or not 64 <= self.max_string_characters <= 100_000
        ):
            raise ValueError(
                "max_string_characters must be between 64 and 100000"
            )
        if (
            type(self.max_collection_items) is not int
            or not 1 <= self.max_collection_items <= 10_000
        ):
            raise ValueError("max_collection_items must be between 1 and 10000")


@dataclass(frozen=True, slots=True)
class AggregatedEvidenceItem:
    evidence_id: str
    kind: EvidenceKind
    source: str
    timestamp: datetime | None
    affected_resource_id: str
    content: JsonValue


@dataclass(frozen=True, slots=True)
class EvidenceResource:
    resource_id: str
    resource_type: str
    name: str
    source_location: str | None


@dataclass(frozen=True, slots=True)
class EvidenceFinding:
    finding_id: str
    pillar: str
    severity: str
    title: str
    description: str
    affected_resource_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    recommendation: str


@dataclass(frozen=True, slots=True)
class EvidencePackage:
    package_id: str
    architecture_id: str
    generated_at: datetime
    resources: tuple[EvidenceResource, ...]
    findings: tuple[EvidenceFinding, ...]
    evidence: tuple[AggregatedEvidenceItem, ...]
    aws_context_status: str | None
    aws_context_diagnostics: tuple[Mapping[str, JsonValue], ...]
    omitted_evidence_count: int
    omitted_evidence_ids: tuple[str, ...]
    serialized_size_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "package_id": self.package_id,
            "architecture_id": self.architecture_id,
            "generated_at": self.generated_at.isoformat(),
            "resources": [
                {
                    "resource_id": item.resource_id,
                    "resource_type": item.resource_type,
                    "name": item.name,
                    "source_location": item.source_location,
                }
                for item in self.resources
            ],
            "findings": [
                {
                    "finding_id": item.finding_id,
                    "pillar": item.pillar,
                    "severity": item.severity,
                    "title": item.title,
                    "description": item.description,
                    "affected_resource_ids": list(item.affected_resource_ids),
                    "evidence_ids": list(item.evidence_ids),
                    "recommendation": item.recommendation,
                }
                for item in self.findings
            ],
            "evidence": [
                {
                    "evidence_id": item.evidence_id,
                    "kind": item.kind.value,
                    "source": item.source,
                    "timestamp": (
                        item.timestamp.isoformat() if item.timestamp else None
                    ),
                    "affected_resource_id": item.affected_resource_id,
                    "content": _plain(item.content),
                }
                for item in self.evidence
            ],
            "aws_context_status": self.aws_context_status,
            "aws_context_diagnostics": [
                _plain(item) for item in self.aws_context_diagnostics
            ],
            "omitted_evidence_count": self.omitted_evidence_count,
            "omitted_evidence_ids": list(self.omitted_evidence_ids),
            "serialized_size_bytes": self.serialized_size_bytes,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )


class EvidencePackageTooLarge(ValueError):
    pass


class EvidenceAggregator:
    def __init__(
        self,
        config: EvidenceAggregationConfig | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.config = config or EvidenceAggregationConfig()
        self._clock = clock or (lambda: datetime.now(UTC))

    def aggregate(
        self,
        architecture: Architecture,
        findings: tuple[Finding, ...],
        parsed_evidence: tuple[Evidence, ...],
        aws_context: AWSContextResult | None = None,
    ) -> EvidencePackage:
        self._validate_inputs(architecture, findings, parsed_evidence, aws_context)
        generated_at = self._now()
        affected_ids = {
            resource_id
            for finding in findings
            for resource_id in finding.affected_resource_ids
        }
        architecture_resources = {
            resource.id: resource for resource in architecture.resources
        }
        unknown = sorted(affected_ids - set(architecture_resources))
        if unknown:
            raise ValueError(
                "findings reference resources outside the architecture: "
                + ", ".join(unknown)
            )

        resources = tuple(
            EvidenceResource(
                resource_id,
                architecture_resources[resource_id].resource_type,
                _redact_text(architecture_resources[resource_id].name),
                (
                    _redact_text(architecture_resources[resource_id].source_location)
                    if architecture_resources[resource_id].source_location
                    else None
                ),
            )
            for resource_id in sorted(affected_ids)
        )
        finding_summaries = tuple(
            EvidenceFinding(
                finding.id,
                finding.pillar.value,
                finding.severity.value,
                self._bounded_text(finding.title),
                self._bounded_text(finding.description),
                finding.affected_resource_ids,
                finding.evidence_ids,
                self._bounded_text(finding.recommendation.description),
            )
            for finding in sorted(findings, key=lambda item: item.id)
        )
        referenced_evidence_ids = {
            evidence_id for finding in findings for evidence_id in finding.evidence_ids
        }

        candidates: list[AggregatedEvidenceItem] = []
        for item in sorted(parsed_evidence, key=lambda value: value.id):
            if item.id not in referenced_evidence_ids:
                continue
            for resource_id in sorted(set(item.resource_ids) & affected_ids):
                candidates.append(
                    self._item(
                        evidence_id=item.id,
                        kind=EvidenceKind.PARSED,
                        source=item.source,
                        timestamp=item.collected_at,
                        resource_id=resource_id,
                        content={
                            "description": item.description,
                            "value": item.value,
                        },
                    )
                )

        aws_status: str | None = None
        aws_diagnostics: tuple[Mapping[str, JsonValue], ...] = ()
        if aws_context is not None:
            aws_status = aws_context.status.value
            candidates.extend(
                self._item(
                    evidence_id=fact.id,
                    kind=EvidenceKind.AWS_OBSERVED,
                    source=fact.source,
                    timestamp=fact.observed_at,
                    resource_id=fact.resource_id,
                    content={"name": fact.name, "value": fact.value},
                )
                for fact in sorted(aws_context.facts, key=lambda value: value.id)
                if fact.resource_id in affected_ids
            )
            aws_diagnostics = tuple(
                MappingProxyType(
                    {
                        "code": diagnostic.code.value,
                        "message": self._bounded_text(diagnostic.message),
                        "source": _redact_text(diagnostic.source),
                        "timestamp": diagnostic.observed_at.isoformat(),
                        "affected_resource_id": diagnostic.resource_id,
                    }
                )
                for diagnostic in aws_context.diagnostics
                if diagnostic.resource_id is None
                or diagnostic.resource_id in affected_ids
            )

        package_id = _stable_id(
            "evidence-package",
            architecture.id,
            *(finding.id for finding in findings),
            generated_at.isoformat(),
        )
        included: list[AggregatedEvidenceItem] = []
        omitted: list[str] = []
        for candidate in sorted(
            candidates,
            key=lambda item: (
                item.affected_resource_id,
                item.kind.value,
                item.evidence_id,
            ),
        ):
            trial = self._package(
                package_id,
                architecture.id,
                generated_at,
                resources,
                finding_summaries,
                tuple(included + [candidate]),
                aws_status,
                aws_diagnostics,
                len(omitted),
                tuple(omitted[:20]),
            )
            if trial.serialized_size_bytes <= self.config.max_context_bytes:
                included.append(candidate)
            else:
                omitted.append(candidate.evidence_id)

        package = self._package(
            package_id,
            architecture.id,
            generated_at,
            resources,
            finding_summaries,
            tuple(included),
            aws_status,
            aws_diagnostics,
            len(omitted),
            tuple(omitted[:20]),
        )
        if package.serialized_size_bytes > self.config.max_context_bytes:
            raise EvidencePackageTooLarge(
                "required finding and provenance metadata exceeds max_context_bytes"
            )
        return package

    def _item(
        self,
        *,
        evidence_id: str,
        kind: EvidenceKind,
        source: str,
        timestamp: datetime | None,
        resource_id: str,
        content: JsonValue,
    ) -> AggregatedEvidenceItem:
        redacted = _redact(
            content,
            max_string_characters=self.config.max_string_characters,
            max_collection_items=self.config.max_collection_items,
        )
        if _json_size(redacted) > self.config.max_item_bytes:
            digest = hashlib.sha256(
                _json_bytes(redacted)
            ).hexdigest()
            redacted = {
                "content_omitted": True,
                "reason": "item exceeded max_item_bytes after redaction",
                "redacted_content_sha256": digest,
            }
        return AggregatedEvidenceItem(
            evidence_id,
            kind,
            _redact_text(source),
            timestamp,
            resource_id,
            redacted,
        )

    def _bounded_text(self, value: str) -> str:
        return _redact_text(value)[: self.config.max_string_characters]

    def _package(
        self,
        package_id: str,
        architecture_id: str,
        generated_at: datetime,
        resources: tuple[EvidenceResource, ...],
        findings: tuple[EvidenceFinding, ...],
        evidence: tuple[AggregatedEvidenceItem, ...],
        aws_status: str | None,
        aws_diagnostics: tuple[Mapping[str, JsonValue], ...],
        omitted_count: int,
        omitted_ids: tuple[str, ...],
    ) -> EvidencePackage:
        provisional = EvidencePackage(
            package_id,
            architecture_id,
            generated_at,
            resources,
            findings,
            evidence,
            aws_status,
            aws_diagnostics,
            omitted_count,
            omitted_ids,
            0,
        )
        size = _json_size(provisional.to_dict())
        # Account for the decimal size field itself until it stabilizes.
        while True:
            package = EvidencePackage(
                package_id,
                architecture_id,
                generated_at,
                resources,
                findings,
                evidence,
                aws_status,
                aws_diagnostics,
                omitted_count,
                omitted_ids,
                size,
            )
            measured = _json_size(package.to_dict())
            if measured == size:
                return package
            size = measured

    def _validate_inputs(
        self,
        architecture: Architecture,
        findings: tuple[Finding, ...],
        parsed_evidence: tuple[Evidence, ...],
        aws_context: AWSContextResult | None,
    ) -> None:
        if not isinstance(architecture, Architecture):
            raise TypeError("architecture must be an Architecture")
        if not isinstance(findings, tuple) or any(
            not isinstance(item, Finding) for item in findings
        ):
            raise TypeError("findings must be a tuple of Finding objects")
        if not isinstance(parsed_evidence, tuple) or any(
            not isinstance(item, Evidence) for item in parsed_evidence
        ):
            raise TypeError("parsed_evidence must be a tuple of Evidence objects")
        if aws_context is not None and not isinstance(aws_context, AWSContextResult):
            raise TypeError("aws_context must be an AWSContextResult or None")

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("clock must return a timezone-aware datetime")
        return value.astimezone(UTC)


def _redact(
    value: object,
    *,
    max_string_characters: int,
    max_collection_items: int,
    key: str | None = None,
) -> JsonValue:
    if key is not None and _SENSITIVE_KEY_RE.search(key):
        return _REDACTED
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _redact_text(value)[:max_string_characters]
    if isinstance(value, Mapping):
        redacted: dict[str, JsonValue] = {}
        for index, (item_key, item_value) in enumerate(
            sorted(value.items(), key=lambda item: str(item[0]))
        ):
            if index >= max_collection_items:
                redacted["_truncated"] = True
                break
            string_key = str(item_key)[:256]
            redacted[string_key] = _redact(
                item_value,
                max_string_characters=max_string_characters,
                max_collection_items=max_collection_items,
                key=string_key,
            )
        return MappingProxyType(redacted)
    if isinstance(value, (tuple, list)):
        items = tuple(
            _redact(
                item,
                max_string_characters=max_string_characters,
                max_collection_items=max_collection_items,
            )
            for item in value[:max_collection_items]
        )
        if len(value) > max_collection_items:
            return items + ("[TRUNCATED]",)
        return items
    return _redact_text(str(value))[:max_string_characters]


def _redact_text(value: str) -> str:
    redacted = _PEM_RE.sub(_REDACTED, value)
    redacted = _AWS_ACCESS_KEY_RE.sub(_REDACTED, redacted)
    redacted = _BEARER_RE.sub(f"Bearer {_REDACTED}", redacted)
    redacted = _URL_CREDENTIAL_RE.sub(r"\1[REDACTED]@", redacted)
    redacted = _ASSIGNMENT_RE.sub(
        lambda match: f"{match.group(1)}={_REDACTED}", redacted
    )
    return redacted


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        _plain(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _json_size(value: object) -> int:
    return len(_json_bytes(value))


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:20]
    return f"{prefix}.{digest}"

