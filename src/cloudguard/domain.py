"""Strongly typed, immutable domain models for CloudGuard."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from types import MappingProxyType
from typing import Mapping, TypeAlias

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | tuple["JsonValue", ...] | Mapping[str, "JsonValue"]

_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{2,127}$")
_ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")
_REGION_PATTERN = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
_CURRENCY_PATTERN = re.compile(r"^[A-Z]{3}$")


class Pillar(StrEnum):
    OPERATIONAL_EXCELLENCE = "operational_excellence"
    SECURITY = "security"
    RELIABILITY = "reliability"
    PERFORMANCE_EFFICIENCY = "performance_efficiency"
    COST_OPTIMIZATION = "cost_optimization"
    SUSTAINABILITY = "sustainability"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    SUPPRESSED = "suppressed"
    RESOLVED = "resolved"


class ReviewStatus(StrEnum):
    DRAFT = "draft"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RemediationStatus(StrEnum):
    PROPOSED = "proposed"
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    DEFERRED = "deferred"


class Effort(StrEnum):
    EXTRA_SMALL = "xs"
    SMALL = "s"
    MEDIUM = "m"
    LARGE = "l"
    EXTRA_LARGE = "xl"


class CostDirection(StrEnum):
    INCREASE = "increase"
    DECREASE = "decrease"
    NEUTRAL = "neutral"


class CostPeriod(StrEnum):
    ONE_TIME = "one_time"
    MONTHLY = "monthly"
    ANNUAL = "annual"


class EvidenceType(StrEnum):
    DECLARED = "declared"
    PLANNED = "planned"
    OBSERVED = "observed"
    INFERRED = "inferred"
    USER_ASSERTION = "user_assertion"


class RelationshipType(StrEnum):
    DEPENDS_ON = "depends_on"
    CONTAINS = "contains"
    ROUTES_TO = "routes_to"
    READS_FROM = "reads_from"
    WRITES_TO = "writes_to"
    INVOKES = "invokes"
    ASSUMES_ROLE = "assumes_role"
    ENCRYPTED_BY = "encrypted_by"
    LOGS_TO = "logs_to"
    ATTACHED_TO = "attached_to"
    EXPOSES = "exposes"
    REPLICATES_TO = "replicates_to"


def _require_id(value: object, field_name: str) -> None:
    if not isinstance(value, str) or not _ID_PATTERN.fullmatch(value):
        raise ValueError(
            f"{field_name} must be 3-128 characters and contain only letters, "
            "digits, '.', '_', ':', '/', or '-'"
        )


def _require_text(value: object, field_name: str, *, maximum: int) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    if len(value) > maximum:
        raise ValueError(f"{field_name} must not exceed {maximum} characters")


def _require_tuple_of_strings(
    value: object,
    field_name: str,
    *,
    allow_empty: bool = True,
    values_are_ids: bool = False,
) -> None:
    if not isinstance(value, tuple) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise TypeError(f"{field_name} must be a tuple of non-empty strings")
    if not allow_empty and not value:
        raise ValueError(f"{field_name} must not be empty")
    if len(value) != len(set(value)):
        raise ValueError(f"{field_name} must not contain duplicates")
    if values_are_ids:
        for item in value:
            _require_id(item, field_name)


def _require_enum(value: object, enum_type: type[StrEnum], field_name: str) -> None:
    if not isinstance(value, enum_type):
        raise TypeError(f"{field_name} must be a {enum_type.__name__}")


def _require_aware_utc(value: object, field_name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{field_name} must be a timezone-aware datetime")
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{field_name} must be expressed in UTC")


def _freeze_json(value: object, path: str = "value") -> JsonValue:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} contains a non-finite number")
        return value
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item, f"{path}[]") for item in value)
    if isinstance(value, Mapping):
        frozen: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{path} contains a non-string object key")
            frozen[key] = _freeze_json(item, f"{path}.{key}")
        return MappingProxyType(frozen)
    raise TypeError(f"{path} contains a non-JSON value: {type(value).__name__}")


@dataclass(frozen=True, slots=True)
class CostImpact:
    direction: CostDirection
    minimum: Decimal
    maximum: Decimal
    period: CostPeriod
    currency: str = "USD"
    rationale: str | None = None

    def __post_init__(self) -> None:
        _require_enum(self.direction, CostDirection, "direction")
        _require_enum(self.period, CostPeriod, "period")
        if not isinstance(self.minimum, Decimal) or not isinstance(self.maximum, Decimal):
            raise TypeError("minimum and maximum must be Decimal values")
        if not self.minimum.is_finite() or not self.maximum.is_finite():
            raise ValueError("minimum and maximum must be finite")
        if self.minimum < 0 or self.maximum < self.minimum:
            raise ValueError("cost range must be non-negative and maximum >= minimum")
        if not isinstance(self.currency, str) or not _CURRENCY_PATTERN.fullmatch(
            self.currency
        ):
            raise ValueError("currency must be a three-letter uppercase code")
        if self.direction is CostDirection.NEUTRAL and (
            self.minimum != 0 or self.maximum != 0
        ):
            raise ValueError("neutral cost impact must have a zero range")
        if self.rationale is not None:
            _require_text(self.rationale, "rationale", maximum=2_000)


@dataclass(frozen=True, slots=True)
class AWSResource:
    id: str
    resource_type: str
    name: str
    properties: Mapping[str, JsonValue] = field(default_factory=dict)
    account_id: str | None = None
    region: str | None = None
    source_location: str | None = None
    tags: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_id(self.id, "id")
        _require_text(self.resource_type, "resource_type", maximum=256)
        _require_text(self.name, "name", maximum=512)
        if self.account_id is not None and (
            not isinstance(self.account_id, str)
            or not _ACCOUNT_ID_PATTERN.fullmatch(self.account_id)
        ):
            raise ValueError("account_id must contain exactly 12 digits")
        if self.region is not None and (
            not isinstance(self.region, str)
            or not _REGION_PATTERN.fullmatch(self.region)
        ):
            raise ValueError("region is not a valid AWS region identifier")
        if self.source_location is not None:
            _require_text(self.source_location, "source_location", maximum=2_048)
        if not isinstance(self.tags, Mapping) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in self.tags.items()
        ):
            raise TypeError("tags must be a mapping of strings to strings")
        object.__setattr__(self, "properties", _freeze_json(self.properties, "properties"))
        object.__setattr__(self, "tags", MappingProxyType(dict(self.tags)))


@dataclass(frozen=True, slots=True)
class ResourceRelationship:
    id: str
    source_resource_id: str
    target_resource_id: str
    relationship_type: RelationshipType
    evidence_ids: tuple[str, ...]
    confidence: float = 1.0

    def __post_init__(self) -> None:
        _require_id(self.id, "id")
        _require_id(self.source_resource_id, "source_resource_id")
        _require_id(self.target_resource_id, "target_resource_id")
        if self.source_resource_id == self.target_resource_id:
            raise ValueError("a relationship cannot connect a resource to itself")
        _require_enum(self.relationship_type, RelationshipType, "relationship_type")
        _require_tuple_of_strings(
            self.evidence_ids, "evidence_ids", values_are_ids=True
        )
        _validate_confidence(self.confidence)


@dataclass(frozen=True, slots=True)
class Architecture:
    id: str
    name: str
    resources: tuple[AWSResource, ...]
    relationships: tuple[ResourceRelationship, ...] = ()

    def __post_init__(self) -> None:
        _require_id(self.id, "id")
        _require_text(self.name, "name", maximum=512)
        if not isinstance(self.resources, tuple) or any(
            not isinstance(item, AWSResource) for item in self.resources
        ):
            raise TypeError("resources must be a tuple of AWSResource objects")
        if not isinstance(self.relationships, tuple) or any(
            not isinstance(item, ResourceRelationship) for item in self.relationships
        ):
            raise TypeError(
                "relationships must be a tuple of ResourceRelationship objects"
            )
        resource_ids = _unique_ids(self.resources, "resources")
        _unique_ids(self.relationships, "relationships")
        for relationship in self.relationships:
            if relationship.source_resource_id not in resource_ids:
                raise ValueError(
                    f"relationship {relationship.id} references unknown source resource"
                )
            if relationship.target_resource_id not in resource_ids:
                raise ValueError(
                    f"relationship {relationship.id} references unknown target resource"
                )


@dataclass(frozen=True, slots=True)
class Evidence:
    id: str
    evidence_type: EvidenceType
    source: str
    description: str
    value: JsonValue
    resource_ids: tuple[str, ...] = ()
    collected_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_id(self.id, "id")
        _require_enum(self.evidence_type, EvidenceType, "evidence_type")
        _require_text(self.source, "source", maximum=2_048)
        _require_text(self.description, "description", maximum=4_000)
        _require_tuple_of_strings(
            self.resource_ids, "resource_ids", values_are_ids=True
        )
        if self.evidence_type is EvidenceType.OBSERVED and self.collected_at is None:
            raise ValueError("observed evidence must include collected_at")
        if self.collected_at is not None:
            _require_aware_utc(self.collected_at, "collected_at")
        object.__setattr__(self, "value", _freeze_json(self.value))


@dataclass(frozen=True, slots=True)
class Recommendation:
    id: str
    title: str
    description: str
    verification_steps: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_id(self.id, "id")
        _require_text(self.title, "title", maximum=512)
        _require_text(self.description, "description", maximum=8_000)
        _require_tuple_of_strings(
            self.verification_steps, "verification_steps", allow_empty=False
        )


@dataclass(frozen=True, slots=True)
class Finding:
    id: str
    pillar: Pillar
    severity: Severity
    title: str
    description: str
    evidence_ids: tuple[str, ...]
    affected_resource_ids: tuple[str, ...]
    confidence: float
    recommendation: Recommendation
    estimated_effort: Effort
    estimated_cost_impact: CostImpact | None
    status: FindingStatus

    def __post_init__(self) -> None:
        _require_id(self.id, "id")
        _require_enum(self.pillar, Pillar, "pillar")
        _require_enum(self.severity, Severity, "severity")
        _require_text(self.title, "title", maximum=512)
        _require_text(self.description, "description", maximum=8_000)
        _require_tuple_of_strings(
            self.evidence_ids,
            "evidence_ids",
            allow_empty=False,
            values_are_ids=True,
        )
        _require_tuple_of_strings(
            self.affected_resource_ids,
            "affected_resource_ids",
            allow_empty=False,
            values_are_ids=True,
        )
        _validate_confidence(self.confidence)
        if not isinstance(self.recommendation, Recommendation):
            raise TypeError("recommendation must be a Recommendation")
        _require_enum(self.estimated_effort, Effort, "estimated_effort")
        if self.estimated_cost_impact is not None and not isinstance(
            self.estimated_cost_impact, CostImpact
        ):
            raise TypeError("estimated_cost_impact must be a CostImpact or None")
        _require_enum(self.status, FindingStatus, "status")


@dataclass(frozen=True, slots=True)
class RemediationItem:
    id: str
    recommendation: Recommendation
    finding_ids: tuple[str, ...]
    priority: int
    status: RemediationStatus
    dependencies: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_id(self.id, "id")
        if not isinstance(self.recommendation, Recommendation):
            raise TypeError("recommendation must be a Recommendation")
        _require_tuple_of_strings(
            self.finding_ids,
            "finding_ids",
            allow_empty=False,
            values_are_ids=True,
        )
        if type(self.priority) is not int or not 0 <= self.priority <= 3:
            raise ValueError("priority must be an integer from 0 through 3")
        _require_enum(self.status, RemediationStatus, "status")
        _require_tuple_of_strings(
            self.dependencies, "dependencies", values_are_ids=True
        )
        if self.id in self.dependencies:
            raise ValueError("a remediation item cannot depend on itself")


@dataclass(frozen=True, slots=True)
class Review:
    id: str
    architecture: Architecture
    evidence: tuple[Evidence, ...]
    findings: tuple[Finding, ...]
    remediation_items: tuple[RemediationItem, ...]
    status: ReviewStatus
    created_at: datetime
    completed_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_id(self.id, "id")
        if not isinstance(self.architecture, Architecture):
            raise TypeError("architecture must be an Architecture")
        _require_model_tuple(self.evidence, Evidence, "evidence")
        _require_model_tuple(self.findings, Finding, "findings")
        _require_model_tuple(
            self.remediation_items, RemediationItem, "remediation_items"
        )
        _require_enum(self.status, ReviewStatus, "status")
        _require_aware_utc(self.created_at, "created_at")
        if self.completed_at is not None:
            _require_aware_utc(self.completed_at, "completed_at")
            if self.completed_at < self.created_at:
                raise ValueError("completed_at cannot precede created_at")
        if self.status in {
            ReviewStatus.COMPLETED,
            ReviewStatus.PARTIAL,
            ReviewStatus.FAILED,
            ReviewStatus.CANCELLED,
        } and self.completed_at is None:
            raise ValueError("terminal review status requires completed_at")

        evidence_ids = _unique_ids(self.evidence, "evidence")
        finding_ids = _unique_ids(self.findings, "findings")
        remediation_ids = _unique_ids(self.remediation_items, "remediation_items")
        resource_ids = {resource.id for resource in self.architecture.resources}

        for relationship in self.architecture.relationships:
            _require_known_ids(
                relationship.evidence_ids,
                evidence_ids,
                f"relationship {relationship.id} evidence",
            )
        for item in self.evidence:
            _require_known_ids(
                item.resource_ids, resource_ids, f"evidence {item.id} resources"
            )
        for finding in self.findings:
            _require_known_ids(
                finding.evidence_ids,
                evidence_ids,
                f"finding {finding.id} evidence",
            )
            _require_known_ids(
                finding.affected_resource_ids,
                resource_ids,
                f"finding {finding.id} resources",
            )
        for item in self.remediation_items:
            _require_known_ids(
                item.finding_ids, finding_ids, f"remediation {item.id} findings"
            )
            _require_known_ids(
                item.dependencies,
                remediation_ids,
                f"remediation {item.id} dependencies",
            )


def _validate_confidence(value: object) -> None:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise TypeError("confidence must be a finite number")
    if not 0.0 <= value <= 1.0:
        raise ValueError("confidence must be between 0.0 and 1.0")


def _require_model_tuple(
    value: object, model_type: type[object], field_name: str
) -> None:
    if not isinstance(value, tuple) or any(
        not isinstance(item, model_type) for item in value
    ):
        raise TypeError(f"{field_name} must be a tuple of {model_type.__name__} objects")


def _unique_ids(items: tuple[object, ...], field_name: str) -> set[str]:
    ids = [getattr(item, "id") for item in items]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{field_name} must have unique IDs")
    return set(ids)


def _require_known_ids(
    references: tuple[str, ...], known_ids: set[str], field_name: str
) -> None:
    unknown = sorted(set(references) - known_ids)
    if unknown:
        raise ValueError(f"{field_name} references unknown IDs: {', '.join(unknown)}")
