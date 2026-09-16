"""Normalized declared and observed facts with deterministic reconciliation."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType

from cloudguard.aws_context import AWSContextResult
from cloudguard.domain import (
    Architecture,
    AWSResource,
    Evidence,
    EvidenceType,
    JsonValue,
)


class FactSourceType(StrEnum):
    DECLARED = "declared"
    OBSERVED = "observed"
    AWS_DIAGNOSTIC = "aws_diagnostic"


class FactAvailability(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"


class ReconciliationStatus(StrEnum):
    AGREEMENT = "agreement"
    CONFLICT = "conflict"
    DECLARED_ONLY = "declared_only"
    OBSERVED_ONLY = "observed_only"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class FactProvenance:
    source_type: FactSourceType
    source_identifier: str
    evidence_ids: tuple[str, ...] = ()
    timestamp: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.source_type, FactSourceType):
            raise TypeError("source_type must be a FactSourceType")
        if not isinstance(self.source_identifier, str) or not self.source_identifier:
            raise ValueError("source_identifier must be a non-empty string")
        _string_tuple(self.evidence_ids, "evidence_ids")
        if self.timestamp is not None:
            _utc(self.timestamp, "timestamp")


@dataclass(frozen=True, slots=True)
class DeclaredFact:
    id: str
    resource_id: str
    attribute: str
    value: JsonValue
    provenance: FactProvenance
    confidence: float = 1.0
    availability: FactAvailability = FactAvailability.AVAILABLE

    def __post_init__(self) -> None:
        _fact_fields(self.id, self.resource_id, self.attribute, self.confidence)
        if self.provenance.source_type is not FactSourceType.DECLARED:
            raise ValueError("declared fact provenance must be declared")
        if self.availability is not FactAvailability.AVAILABLE:
            raise ValueError("declared facts must be available")
        object.__setattr__(self, "value", _freeze_json(self.value))


@dataclass(frozen=True, slots=True)
class ObservedFact:
    id: str
    resource_id: str
    attribute: str
    value: JsonValue
    provenance: FactProvenance
    confidence: float = 1.0
    availability: FactAvailability = FactAvailability.AVAILABLE

    def __post_init__(self) -> None:
        _fact_fields(self.id, self.resource_id, self.attribute, self.confidence)
        if self.provenance.source_type is not FactSourceType.OBSERVED:
            raise ValueError("observed fact provenance must be observed")
        if self.provenance.timestamp is None:
            raise ValueError("observed fact provenance requires a timestamp")
        if self.availability is not FactAvailability.AVAILABLE:
            raise ValueError("observed facts must be available")
        object.__setattr__(self, "value", _freeze_json(self.value))


@dataclass(frozen=True, slots=True)
class UnknownFact:
    id: str
    resource_id: str
    attribute: str
    reason: str
    provenance: FactProvenance
    availability: FactAvailability = FactAvailability.UNAVAILABLE

    def __post_init__(self) -> None:
        _fact_fields(self.id, self.resource_id, self.attribute, 1.0)
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("reason must be a non-empty string")
        if self.availability is not FactAvailability.UNAVAILABLE:
            raise ValueError("unknown facts must be unavailable")


@dataclass(frozen=True, slots=True)
class FactConflict:
    id: str
    resource_id: str
    attribute: str
    declared: DeclaredFact
    observed: ObservedFact

    def __post_init__(self) -> None:
        _fact_fields(self.id, self.resource_id, self.attribute, 1.0)
        if self.declared.resource_id != self.resource_id:
            raise ValueError("declared fact resource does not match conflict")
        if self.observed.resource_id != self.resource_id:
            raise ValueError("observed fact resource does not match conflict")
        if self.declared.attribute != self.attribute:
            raise ValueError("declared fact attribute does not match conflict")
        if self.observed.attribute != self.attribute:
            raise ValueError("observed fact attribute does not match conflict")
        if self.declared.value == self.observed.value:
            raise ValueError("a conflict requires different values")


@dataclass(frozen=True, slots=True)
class FactReconciliation:
    resource_id: str
    attribute: str
    status: ReconciliationStatus
    declared: DeclaredFact | None = None
    observed: ObservedFact | None = None
    conflict: FactConflict | None = None
    unknown: UnknownFact | None = None

    @property
    def policy_value(self) -> JsonValue | None:
        """Value available to deterministic policy; observed state never overrides IaC."""
        return self.declared.value if self.declared is not None else None

    def __post_init__(self) -> None:
        _identity(self.resource_id, "resource_id")
        _attribute(self.attribute)
        if not isinstance(self.status, ReconciliationStatus):
            raise TypeError("status must be a ReconciliationStatus")
        if self.status is ReconciliationStatus.AGREEMENT:
            if self.declared is None or self.observed is None:
                raise ValueError("agreement requires declared and observed facts")
            if self.declared.value != self.observed.value:
                raise ValueError("agreement requires equal values")
        elif self.status is ReconciliationStatus.CONFLICT:
            if self.conflict is None:
                raise ValueError("conflict status requires a FactConflict")
        elif self.status is ReconciliationStatus.DECLARED_ONLY:
            if self.declared is None or self.observed is not None:
                raise ValueError("declared_only requires only a declared fact")
        elif self.status is ReconciliationStatus.OBSERVED_ONLY:
            if self.observed is None or self.declared is not None:
                raise ValueError("observed_only requires only an observed fact")
        elif self.status is ReconciliationStatus.UNKNOWN and self.unknown is None:
            raise ValueError("unknown status requires an UnknownFact")


@dataclass(frozen=True, slots=True)
class NormalizedFacts:
    declared: tuple[DeclaredFact, ...]
    observed: tuple[ObservedFact, ...]
    unknown: tuple[UnknownFact, ...]
    conflicts: tuple[FactConflict, ...]
    reconciliations: tuple[FactReconciliation, ...]

    def __post_init__(self) -> None:
        _unique_fact_keys(self.declared, "declared")
        _unique_fact_keys(self.observed, "observed")
        _unique_fact_keys(self.unknown, "unknown", allow_wildcard_duplicates=True)

    def declared_value(self, resource_id: str, attribute: str) -> JsonValue | None:
        fact = self.declared_fact(resource_id, attribute)
        return fact.value if fact is not None else None

    def declared_fact(
        self, resource_id: str, attribute: str
    ) -> DeclaredFact | None:
        return next(
            (
                fact
                for fact in self.declared
                if fact.resource_id == resource_id and fact.attribute == attribute
            ),
            None,
        )

    def reconciliation(
        self, resource_id: str, attribute: str
    ) -> FactReconciliation | None:
        return next(
            (
                item
                for item in self.reconciliations
                if item.resource_id == resource_id and item.attribute == attribute
            ),
            None,
        )


class FactNormalizer:
    """Create normalized facts and reconcile them without changing policy outcomes."""

    def normalize(
        self,
        architecture: Architecture,
        evidence: tuple[Evidence, ...],
        aws_context: AWSContextResult | None = None,
    ) -> NormalizedFacts:
        if not isinstance(architecture, Architecture):
            raise TypeError("architecture must be an Architecture")
        if not isinstance(evidence, tuple) or any(
            not isinstance(item, Evidence) for item in evidence
        ):
            raise TypeError("evidence must be a tuple of Evidence objects")
        if aws_context is not None and not isinstance(aws_context, AWSContextResult):
            raise TypeError("aws_context must be an AWSContextResult or None")

        evidence_by_resource = _evidence_by_resource(evidence)
        declared = tuple(
            fact
            for resource in architecture.resources
            for fact in _declared_facts(
                resource, evidence_by_resource.get(resource.id, ())
            )
        )
        observed = (
            tuple(
                ObservedFact(
                    id=fact.id,
                    resource_id=fact.resource_id,
                    attribute=fact.name,
                    value=fact.value,
                    provenance=FactProvenance(
                        FactSourceType.OBSERVED,
                        fact.source,
                        (fact.id,),
                        fact.observed_at,
                    ),
                )
                for fact in aws_context.facts
            )
            if aws_context is not None
            else ()
        )
        unknown = (
            tuple(
                UnknownFact(
                    id=_stable_id(
                        "unknown-fact",
                        diagnostic.resource_id or architecture.id,
                        diagnostic.code.value,
                        diagnostic.source,
                    ),
                    resource_id=diagnostic.resource_id or architecture.id,
                    attribute="*",
                    reason=diagnostic.message,
                    provenance=FactProvenance(
                        FactSourceType.AWS_DIAGNOSTIC,
                        diagnostic.source,
                        (),
                        diagnostic.observed_at,
                    ),
                )
                for diagnostic in aws_context.diagnostics
            )
            if aws_context is not None
            else ()
        )
        return FactReconciler().reconcile(declared, observed, unknown)


class FactReconciler:
    """Compare declared and observed values using declared-state policy precedence."""

    def reconcile(
        self,
        declared: tuple[DeclaredFact, ...],
        observed: tuple[ObservedFact, ...],
        unknown: tuple[UnknownFact, ...] = (),
    ) -> NormalizedFacts:
        _unique_fact_keys(declared, "declared")
        _unique_fact_keys(observed, "observed")
        declared_by_key = {(item.resource_id, item.attribute): item for item in declared}
        observed_by_key = {(item.resource_id, item.attribute): item for item in observed}
        conflicts: list[FactConflict] = []
        reconciliations: list[FactReconciliation] = []
        for resource_id, attribute in sorted(set(declared_by_key) | set(observed_by_key)):
            declared_fact = declared_by_key.get((resource_id, attribute))
            observed_fact = observed_by_key.get((resource_id, attribute))
            if declared_fact is not None and observed_fact is not None:
                if declared_fact.value == observed_fact.value:
                    reconciliations.append(
                        FactReconciliation(
                            resource_id,
                            attribute,
                            ReconciliationStatus.AGREEMENT,
                            declared=declared_fact,
                            observed=observed_fact,
                        )
                    )
                else:
                    conflict = FactConflict(
                        _stable_id("fact-conflict", resource_id, attribute),
                        resource_id,
                        attribute,
                        declared_fact,
                        observed_fact,
                    )
                    conflicts.append(conflict)
                    reconciliations.append(
                        FactReconciliation(
                            resource_id,
                            attribute,
                            ReconciliationStatus.CONFLICT,
                            declared=declared_fact,
                            observed=observed_fact,
                            conflict=conflict,
                        )
                    )
            elif declared_fact is not None:
                reconciliations.append(
                    FactReconciliation(
                        resource_id,
                        attribute,
                        ReconciliationStatus.DECLARED_ONLY,
                        declared=declared_fact,
                    )
                )
            elif observed_fact is not None:
                reconciliations.append(
                    FactReconciliation(
                        resource_id,
                        attribute,
                        ReconciliationStatus.OBSERVED_ONLY,
                        observed=observed_fact,
                    )
                )
        reconciliations.extend(
            FactReconciliation(
                item.resource_id,
                item.attribute,
                ReconciliationStatus.UNKNOWN,
                unknown=item,
            )
            for item in unknown
        )
        return NormalizedFacts(
            tuple(sorted(declared, key=_fact_key)),
            tuple(sorted(observed, key=_fact_key)),
            tuple(sorted(unknown, key=_fact_key)),
            tuple(sorted(conflicts, key=_fact_key)),
            tuple(
                sorted(
                    reconciliations,
                    key=lambda item: (
                        item.resource_id,
                        item.attribute,
                        item.status.value,
                    ),
                )
            ),
        )


def _declared_facts(
    resource: AWSResource, evidence_ids: tuple[str, ...]
) -> tuple[DeclaredFact, ...]:
    metadata = resource.properties.get("_cloudguard")
    attribute_sources: Mapping[str, JsonValue] = MappingProxyType({})
    if isinstance(metadata, Mapping):
        candidate = metadata.get("attribute_sources")
        if isinstance(candidate, Mapping):
            attribute_sources = candidate
    facts = []
    for attribute, value in sorted(resource.properties.items()):
        if attribute == "_cloudguard":
            continue
        source = attribute_sources.get(attribute)
        source_identifier = (
            source
            if isinstance(source, str)
            else resource.source_location or resource.id
        )
        facts.append(
            DeclaredFact(
                id=_stable_id("declared-fact", resource.id, attribute),
                resource_id=resource.id,
                attribute=attribute,
                value=value,
                provenance=FactProvenance(
                    FactSourceType.DECLARED,
                    source_identifier,
                    evidence_ids,
                ),
            )
        )
    return tuple(facts)


def _evidence_by_resource(
    evidence: tuple[Evidence, ...],
) -> Mapping[str, tuple[str, ...]]:
    result: dict[str, list[str]] = {}
    for item in evidence:
        if item.evidence_type is not EvidenceType.DECLARED:
            continue
        for resource_id in item.resource_ids:
            result.setdefault(resource_id, []).append(item.id)
    return MappingProxyType(
        {
            resource_id: tuple(sorted(set(evidence_ids)))
            for resource_id, evidence_ids in result.items()
        }
    )


def _fact_fields(
    fact_id: str, resource_id: str, attribute: str, confidence: float
) -> None:
    _identity(fact_id, "id")
    _identity(resource_id, "resource_id")
    _attribute(attribute)
    if type(confidence) not in (int, float) or not 0 <= confidence <= 1:
        raise ValueError("confidence must be between 0 and 1")


def _identity(value: object, field_name: str) -> None:
    if not isinstance(value, str) or len(value) < 3:
        raise ValueError(f"{field_name} must be a string of at least 3 characters")


def _attribute(value: object) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("attribute must be a non-empty string")


def _string_tuple(value: object, field_name: str) -> None:
    if not isinstance(value, tuple) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise TypeError(f"{field_name} must be a tuple of strings")
    if len(value) != len(set(value)):
        raise ValueError(f"{field_name} must not contain duplicates")


def _utc(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{field_name} must be expressed in UTC")


def _unique_fact_keys(
    facts: tuple[DeclaredFact | ObservedFact | UnknownFact | FactConflict, ...],
    name: str,
    *,
    allow_wildcard_duplicates: bool = False,
) -> None:
    keys = [
        (item.resource_id, item.attribute)
        for item in facts
        if not (allow_wildcard_duplicates and item.attribute == "*")
    ]
    if len(keys) != len(set(keys)):
        raise ValueError(f"{name} facts must have unique resource/attribute keys")


def _fact_key(
    value: DeclaredFact | ObservedFact | UnknownFact | FactConflict,
) -> tuple[str, str, str]:
    return (
        value.resource_id,
        value.attribute,
        value.id,
    )


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
    raise TypeError(f"{path} contains a non-JSON value")


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:20]
    return f"{prefix}.{digest}"
