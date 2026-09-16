"""Deterministic CloudGuard architecture rules.

Rules operate only on normalized domain objects and parsed evidence. They do
not call AWS, execute infrastructure code, or invoke an AI model.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from cloudguard.aws_context import AWSContextResult
from cloudguard.domain import (
    Architecture,
    AWSResource,
    Effort,
    Evidence,
    Finding,
    FindingStatus,
    JsonValue,
    Pillar,
    Recommendation,
    Severity,
)
from cloudguard.facts import FactNormalizer, NormalizedFacts


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    id: str
    pillar: Pillar
    severity: Severity
    title: str
    rationale: str
    remediation: str
    estimated_effort: Effort


@dataclass(frozen=True, slots=True)
class RuleEngineConfig:
    """Per-rule enablement. Rules are enabled unless explicitly set to false."""

    rule_states: Mapping[str, bool] = field(default_factory=dict)

    def __post_init__(self) -> None:
        states = dict(self.rule_states)
        if any(not isinstance(key, str) or type(value) is not bool for key, value in states.items()):
            raise TypeError("rule_states must map rule IDs to booleans")
        object.__setattr__(self, "rule_states", MappingProxyType(states))

    def is_enabled(self, rule_id: str) -> bool:
        return self.rule_states.get(rule_id, True)


@dataclass(frozen=True, slots=True)
class RuleEvaluation:
    findings: tuple[Finding, ...]
    evaluated_rule_ids: tuple[str, ...]
    disabled_rule_ids: tuple[str, ...]
    normalized_facts: NormalizedFacts


@dataclass(frozen=True, slots=True)
class _Candidate:
    resource_ids: tuple[str, ...]
    description: str
    confidence: float = 1.0


@dataclass(frozen=True, slots=True)
class _Rule:
    definition: RuleDefinition
    evaluate: Callable[[_Context], tuple[_Candidate, ...]]


@dataclass(frozen=True, slots=True)
class _Context:
    architecture: Architecture
    evidence_by_resource: Mapping[str, tuple[str, ...]]
    normalized_facts: NormalizedFacts

    def resources_of_type(self, *resource_types: str) -> tuple[AWSResource, ...]:
        accepted = set(resource_types)
        return tuple(
            resource
            for resource in self.architecture.resources
            if resource.resource_type in accepted
        )

    def declared_property(
        self, resource: AWSResource, *names: str
    ) -> JsonValue | None:
        for name in names:
            fact = self.normalized_facts.declared_fact(resource.id, name)
            if fact is not None:
                return fact.value
        return None


class RuleEngine:
    """Evaluate the immutable, versioned deterministic rule catalog."""

    def __init__(self, config: RuleEngineConfig | None = None) -> None:
        self.config = config or RuleEngineConfig()
        known_ids = {rule.definition.id for rule in _RULES}
        unknown_ids = sorted(set(self.config.rule_states) - known_ids)
        if unknown_ids:
            raise ValueError(f"unknown rule IDs: {', '.join(unknown_ids)}")

    @property
    def rules(self) -> tuple[RuleDefinition, ...]:
        return tuple(rule.definition for rule in _RULES)

    def evaluate(
        self,
        architecture: Architecture,
        evidence: tuple[Evidence, ...],
        *,
        aws_context: AWSContextResult | None = None,
        normalized_facts: NormalizedFacts | None = None,
    ) -> RuleEvaluation:
        if not isinstance(architecture, Architecture):
            raise TypeError("architecture must be an Architecture")
        if not isinstance(evidence, tuple) or any(
            not isinstance(item, Evidence) for item in evidence
        ):
            raise TypeError("evidence must be a tuple of Evidence objects")
        if aws_context is not None and normalized_facts is not None:
            raise ValueError("provide aws_context or normalized_facts, not both")
        facts = normalized_facts or FactNormalizer().normalize(
            architecture, evidence, aws_context
        )
        if not isinstance(facts, NormalizedFacts):
            raise TypeError("normalized_facts must be NormalizedFacts")

        resource_ids = {resource.id for resource in architecture.resources}
        evidence_by_resource: dict[str, list[str]] = {
            resource_id: [] for resource_id in resource_ids
        }
        for item in evidence:
            for resource_id in item.resource_ids:
                if resource_id in evidence_by_resource:
                    evidence_by_resource[resource_id].append(item.id)
        context = _Context(
            architecture,
            MappingProxyType(
                {
                    resource_id: tuple(sorted(set(ids)))
                    for resource_id, ids in evidence_by_resource.items()
                }
            ),
            facts,
        )

        findings: list[Finding] = []
        evaluated: list[str] = []
        disabled: list[str] = []
        for rule in _RULES:
            definition = rule.definition
            if not self.config.is_enabled(definition.id):
                disabled.append(definition.id)
                continue
            evaluated.append(definition.id)
            candidates = sorted(
                rule.evaluate(context),
                key=lambda candidate: (candidate.resource_ids, candidate.description),
            )
            for candidate in candidates:
                evidence_ids = _candidate_evidence(context, candidate.resource_ids)
                # A finding without reproducible evidence is not emitted.
                if not evidence_ids:
                    continue
                recommendation = Recommendation(
                    id=_stable_id("recommendation", definition.id),
                    title=f"Remediate {definition.title.lower()}",
                    description=definition.remediation,
                    verification_steps=(
                        f"Re-run rule {definition.id} and confirm it no longer produces a finding.",
                    ),
                )
                findings.append(
                    Finding(
                        id=_stable_id(
                            "finding",
                            definition.id,
                            *candidate.resource_ids,
                        ),
                        pillar=definition.pillar,
                        severity=definition.severity,
                        title=definition.title,
                        description=(
                            f"{candidate.description} Rationale: {definition.rationale}"
                        ),
                        evidence_ids=evidence_ids,
                        affected_resource_ids=candidate.resource_ids,
                        confidence=candidate.confidence,
                        recommendation=recommendation,
                        estimated_effort=definition.estimated_effort,
                        estimated_cost_impact=None,
                        status=FindingStatus.OPEN,
                    )
                )
        return RuleEvaluation(
            findings=tuple(findings),
            evaluated_rule_ids=tuple(evaluated),
            disabled_rule_ids=tuple(disabled),
            normalized_facts=facts,
        )


def _candidate_evidence(
    context: _Context, resource_ids: tuple[str, ...]
) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                evidence_id
                for resource_id in resource_ids
                for evidence_id in context.evidence_by_resource.get(resource_id, ())
            }
        )
    )


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:20]
    return f"{prefix}.{digest}"


def _definition(
    rule_id: str,
    pillar: Pillar,
    severity: Severity,
    title: str,
    rationale: str,
    remediation: str,
    effort: Effort,
) -> RuleDefinition:
    return RuleDefinition(
        rule_id, pillar, severity, title, rationale, remediation, effort
    )


_STATEFUL_TYPES = {
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_dynamodb_table",
    "aws_efs_file_system",
    "aws_elasticache_cluster",
    "aws_elasticache_replication_group",
    "aws_opensearch_domain",
    "aws_redshift_cluster",
}
_DATABASE_TYPES = {
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_elasticache_cluster",
    "aws_elasticache_replication_group",
    "aws_opensearch_domain",
    "aws_redshift_cluster",
}
_MONITORABLE_TYPES = {
    "aws_instance",
    "aws_autoscaling_group",
    "aws_ecs_service",
    "aws_lambda_function",
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_elasticache_cluster",
    "aws_elasticache_replication_group",
    "aws_opensearch_domain",
    "aws_redshift_cluster",
    "aws_lb",
}
_ENCRYPTABLE_PROPERTIES = {
    "aws_db_instance": ("storage_encrypted",),
    "aws_rds_cluster": ("storage_encrypted",),
    "aws_ebs_volume": ("encrypted",),
    "aws_efs_file_system": ("encrypted",),
    "aws_opensearch_domain": ("encrypt_at_rest", "encrypt_at_rest_enabled"),
    "aws_redshift_cluster": ("encrypted",),
}
_SECRET_NAME_RE = re.compile(
    r"(?:^|_)(?:password|passwd|secret|token|api_key|private_key)(?:$|_)",
    re.IGNORECASE,
)
_WILDCARD_ACTION_RE = re.compile(
    r"(?is)(?:\"?Action\"?\s*[:=]\s*)(?:\"\*\"|\[\s*\"\*\"\s*\])"
)
_WILDCARD_RESOURCE_RE = re.compile(
    r"(?is)(?:\"?Resource\"?\s*[:=]\s*)(?:\"\*\"|\[\s*\"\*\"\s*\])"
)
_OPEN_IPV4_RE = re.compile(r"(?<![0-9.])0\.0\.0\.0/0(?![0-9.])")
_OPEN_IPV6_RE = re.compile(r"(?<![:0-9a-fA-F])::/0(?![:0-9a-fA-F])")


def _single_az_stateful(context: _Context) -> tuple[_Candidate, ...]:
    candidates = []
    for resource in context.architecture.resources:
        if resource.resource_type not in _STATEFUL_TYPES or not _is_critical(resource):
            continue
        availability_zone = context.declared_property(
            resource, "availability_zone", "availabilityZone"
        )
        subnet_ids = context.declared_property(resource, "subnet_ids", "subnetIds")
        explicitly_single_az = isinstance(availability_zone, str) or (
            isinstance(subnet_ids, tuple) and len(subnet_ids) == 1
        )
        if explicitly_single_az:
            candidates.append(
                _Candidate(
                    (resource.id,),
                    "The submitted configuration places a critical stateful resource in one identifiable Availability Zone.",
                )
            )
    return tuple(candidates)


def _backup_configuration(context: _Context) -> tuple[_Candidate, ...]:
    candidates = []
    for resource in context.architecture.resources:
        if resource.resource_type not in _STATEFUL_TYPES:
            continue
        configured = _backup_state(context, resource)
        if configured is not True:
            state = "disabled" if configured is False else "not established"
            candidates.append(
                _Candidate(
                    (resource.id,),
                    f"Backup configuration is {state} in the submitted evidence.",
                    1.0 if configured is False else 0.8,
                )
            )
    return tuple(candidates)


def _database_multi_az(context: _Context) -> tuple[_Candidate, ...]:
    candidates = []
    for resource in context.architecture.resources:
        if resource.resource_type not in _DATABASE_TYPES:
            continue
        state = _multi_az_state(context, resource)
        if state is not True:
            wording = "disabled" if state is False else "not established"
            candidates.append(
                _Candidate(
                    (resource.id,),
                    f"Multi-AZ database configuration is {wording} in the submitted evidence.",
                    1.0 if state is False else 0.8,
                )
            )
    return tuple(candidates)


def _health_check(context: _Context) -> tuple[_Candidate, ...]:
    candidates = []
    for resource in context.resources_of_type(
        "aws_lb_target_group", "aws_elb", "aws_autoscaling_group"
    ):
        has_health_check = _has_property_or_block(
            resource, "health_check", "healthCheck"
        )
        if not has_health_check:
            candidates.append(
                _Candidate(
                    (resource.id,),
                    "No health-check configuration is present in the submitted evidence.",
                    0.85,
                )
            )
    return tuple(candidates)


def _scaling_strategy(context: _Context) -> tuple[_Candidate, ...]:
    scaling_targets = context.resources_of_type(
        "aws_appautoscaling_target",
        "aws_autoscaling_policy",
        "aws_appautoscaling_policy",
    )
    scaling_text = " ".join(_resource_text(resource) for resource in scaling_targets)
    candidates = []
    for resource in context.resources_of_type("aws_ecs_service"):
        address = _terraform_address(resource)
        if address not in scaling_text and resource.name not in scaling_text:
            candidates.append(
                _Candidate(
                    (resource.id,),
                    "No application auto-scaling target or policy referencing this scalable service is present.",
                    0.8,
                )
            )
    return tuple(candidates)


def _public_rds(context: _Context) -> tuple[_Candidate, ...]:
    return tuple(
        _Candidate(
            (resource.id,),
            "The database sets publicly_accessible to true.",
        )
        for resource in context.resources_of_type("aws_db_instance")
        if (
            _literal_bool(
                context.declared_property(resource, "publicly_accessible")
            )
            is True
        )
    )


def _unrestricted_ingress(context: _Context) -> tuple[_Candidate, ...]:
    candidates = []
    for resource in context.resources_of_type(
        "aws_security_group",
        "aws_security_group_rule",
        "aws_vpc_security_group_ingress_rule",
    ):
        text = _resource_text(resource)
        if not (_OPEN_IPV4_RE.search(text) or _OPEN_IPV6_RE.search(text)):
            continue
        if resource.resource_type == "aws_security_group_rule":
            rule_type = context.declared_property(resource, "type")
            if isinstance(rule_type, str) and rule_type != "ingress":
                continue
        candidates.append(
            _Candidate(
                (resource.id,),
                "An ingress rule includes an all-address IPv4 or IPv6 CIDR.",
            )
        )
    return tuple(candidates)


def _wildcard_iam(context: _Context) -> tuple[_Candidate, ...]:
    candidates = []
    for resource in context.resources_of_type(
        "aws_iam_policy",
        "aws_iam_role_policy",
        "aws_iam_user_policy",
        "aws_iam_group_policy",
    ):
        policy_text = _value_text(context.declared_property(resource, "policy"))
        if policy_text and (
            _WILDCARD_ACTION_RE.search(policy_text)
            or _WILDCARD_RESOURCE_RE.search(policy_text)
        ):
            candidates.append(
                _Candidate(
                    (resource.id,),
                    "The submitted IAM policy contains a wildcard Action or Resource.",
                )
            )
    return tuple(candidates)


def _encryption(context: _Context) -> tuple[_Candidate, ...]:
    candidates = []
    for resource in context.architecture.resources:
        property_names = _ENCRYPTABLE_PROPERTIES.get(resource.resource_type)
        if property_names is None:
            continue
        value = context.declared_property(resource, *property_names)
        state = _literal_bool(value)
        if state is not True:
            wording = "explicitly disabled" if state is False else "not established"
            candidates.append(
                _Candidate(
                    (resource.id,),
                    f"Encryption at rest is {wording} in the submitted evidence.",
                    1.0 if state is False else 0.8,
                )
            )
    return tuple(candidates)


def _plaintext_secrets(context: _Context) -> tuple[_Candidate, ...]:
    candidates = []
    for resource in context.architecture.resources:
        exposed = sorted(
            key
            for key, value in resource.properties.items()
            if key != "_cloudguard"
            and _SECRET_NAME_RE.search(key)
            and isinstance(value, str)
            and bool(value.strip())
        )
        if exposed:
            candidates.append(
                _Candidate(
                    (resource.id,),
                    "Potential secret values are present as plaintext literals in attributes: "
                    + ", ".join(exposed)
                    + ".",
                )
            )
    return tuple(candidates)


def _monitoring(context: _Context) -> tuple[_Candidate, ...]:
    alarm_text = " ".join(
        _resource_text(resource)
        for resource in context.resources_of_type(
            "aws_cloudwatch_metric_alarm", "aws_cloudwatch_composite_alarm"
        )
    )
    candidates = []
    for resource in context.architecture.resources:
        if resource.resource_type not in _MONITORABLE_TYPES:
            continue
        address = _terraform_address(resource)
        if address not in alarm_text and resource.name not in alarm_text:
            candidates.append(
                _Candidate(
                    (resource.id,),
                    "No CloudWatch alarm referencing this operational resource is present in the submitted architecture.",
                    0.75,
                )
            )
    return tuple(candidates)


def _deployment_rollback(context: _Context) -> tuple[_Candidate, ...]:
    candidates = []
    for resource in context.resources_of_type("aws_ecs_service"):
        block = _named_block(resource, "deployment_circuit_breaker")
        enabled = (
            _literal_bool(block.get("enable", block.get("enabled")))
            if block
            else None
        )
        rollback = _literal_bool(block.get("rollback")) if block else None
        if enabled is not True or rollback is not True:
            candidates.append(
                _Candidate(
                    (resource.id,),
                    "An enabled ECS deployment circuit breaker with rollback is not established.",
                    0.9,
                )
            )
    return tuple(candidates)


def _log_retention(context: _Context) -> tuple[_Candidate, ...]:
    candidates = []
    for resource in context.resources_of_type("aws_cloudwatch_log_group"):
        retention = _literal_int(
            context.declared_property(resource, "retention_in_days")
        )
        if retention is None or retention <= 0:
            candidates.append(
                _Candidate(
                    (resource.id,),
                    "A positive CloudWatch Logs retention period is not configured.",
                )
            )
    return tuple(candidates)


def _expensive_network(context: _Context) -> tuple[_Candidate, ...]:
    return tuple(
        _Candidate(
            (resource.id,),
            "A NAT gateway is present; its hourly, data-processing, and potential cross-AZ data-transfer usage should be validated against traffic paths.",
            0.7,
        )
        for resource in context.resources_of_type("aws_nat_gateway")
    )


def _always_on_compute(context: _Context) -> tuple[_Candidate, ...]:
    candidates = []
    for resource in context.resources_of_type("aws_instance"):
        schedule = context.declared_property(
            resource, "schedule", "instance_schedule"
        )
        if schedule is None:
            candidates.append(
                _Candidate(
                    (resource.id,),
                    "A directly provisioned EC2 instance has no scheduling or elasticity evidence and is an always-on cost review candidate.",
                    0.7,
                )
            )
    return tuple(candidates)


def _is_critical(resource: AWSResource) -> bool:
    tags = {key.lower(): value.lower() for key, value in resource.tags.items()}
    criticality = str(
        tags.get("criticality")
        or tags.get("tier")
        or resource.properties.get("criticality")
        or ""
    ).lower()
    environment = str(
        tags.get("environment") or resource.properties.get("environment") or ""
    ).lower()
    return criticality in {"critical", "tier-0", "tier0"} or environment in {
        "production",
        "prod",
    }


def _backup_state(context: _Context, resource: AWSResource) -> bool | None:
    if resource.resource_type in {"aws_db_instance", "aws_rds_cluster"}:
        retention = _literal_int(
            context.declared_property(resource, "backup_retention_period")
        )
        return None if retention is None else retention > 0
    if resource.resource_type == "aws_dynamodb_table":
        value = context.declared_property(
            resource,
            "point_in_time_recovery_enabled",
            "point_in_time_recovery",
        )
        return _literal_bool(value)
    return _literal_bool(
        context.declared_property(
            resource,
            "backup_enabled",
            "automated_snapshot_retention_period",
            "snapshot_retention_limit",
        )
    )


def _multi_az_state(context: _Context, resource: AWSResource) -> bool | None:
    if resource.resource_type == "aws_db_instance":
        return _literal_bool(context.declared_property(resource, "multi_az"))
    if resource.resource_type == "aws_rds_cluster":
        zones = context.declared_property(resource, "availability_zones")
        return len(zones) >= 2 if isinstance(zones, tuple) else None
    if resource.resource_type == "aws_elasticache_replication_group":
        return _literal_bool(
            context.declared_property(
                resource,
                "automatic_failover_enabled",
                "multi_az_enabled",
            )
        )
    if resource.resource_type == "aws_elasticache_cluster":
        return False
    if resource.resource_type == "aws_opensearch_domain":
        zone_block = _named_block(resource, "zone_awareness_config")
        count = _literal_int(zone_block.get("availability_zone_count")) if zone_block else None
        enabled = _literal_bool(
            context.declared_property(resource, "zone_awareness_enabled")
        )
        return enabled is True and count is not None and count >= 2
    if resource.resource_type == "aws_redshift_cluster":
        return _literal_bool(context.declared_property(resource, "multi_az"))
    return None


def _literal_bool(value: JsonValue | None) -> bool | None:
    return value if type(value) is bool else None


def _literal_int(value: JsonValue | None) -> int | None:
    return value if type(value) is int else None


def _has_property_or_block(resource: AWSResource, *names: str) -> bool:
    if any(name in resource.properties for name in names):
        return True
    return any(_named_block(resource, name) is not None for name in names)


def _named_block(resource: AWSResource, name: str) -> Mapping[str, JsonValue] | None:
    blocks = resource.properties.get("_blocks")
    if not isinstance(blocks, tuple):
        return None
    for block in blocks:
        if (
            isinstance(block, Mapping)
            and block.get("type") == name
            and isinstance(block.get("attributes"), Mapping)
        ):
            return block["attributes"]  # type: ignore[return-value]
    return None


def _terraform_address(resource: AWSResource) -> str:
    metadata = resource.properties.get("_cloudguard")
    if isinstance(metadata, Mapping):
        address = metadata.get("terraform_address")
        if isinstance(address, str):
            return address
    return f"{resource.resource_type}.{resource.name}"


def _resource_text(resource: AWSResource) -> str:
    return _value_text(resource.properties)


def _value_text(value: JsonValue | None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        return " ".join(
            f"{key} {_value_text(item)}"
            for key, item in sorted(value.items())
        )
    if isinstance(value, tuple):
        return " ".join(_value_text(item) for item in value)
    return json.dumps(value, sort_keys=True)


_RULES: tuple[_Rule, ...] = (
    _Rule(
        _definition(
            "CG-REL-001",
            Pillar.RELIABILITY,
            Severity.HIGH,
            "Critical stateful resource is constrained to one Availability Zone",
            "A single identifiable Availability Zone creates an availability dependency for critical state.",
            "Use a supported multi-AZ design or document and test an equivalent recovery architecture.",
            Effort.LARGE,
        ),
        _single_az_stateful,
    ),
    _Rule(
        _definition(
            "CG-REL-002",
            Pillar.RELIABILITY,
            Severity.HIGH,
            "Backup configuration is missing or unclear",
            "Recoverability cannot be demonstrated without explicit backup or point-in-time recovery evidence.",
            "Configure an appropriate backup mechanism, retention period, restore testing, and ownership.",
            Effort.MEDIUM,
        ),
        _backup_configuration,
    ),
    _Rule(
        _definition(
            "CG-REL-003",
            Pillar.RELIABILITY,
            Severity.HIGH,
            "Multi-AZ database configuration is missing or disabled",
            "A database without demonstrated multi-AZ failover can retain an Availability Zone dependency.",
            "Enable the database engine's supported multi-AZ or failover configuration and test failover behavior.",
            Effort.LARGE,
        ),
        _database_multi_az,
    ),
    _Rule(
        _definition(
            "CG-REL-004",
            Pillar.RELIABILITY,
            Severity.MEDIUM,
            "Health-check evidence is missing",
            "Automated traffic management and recovery require a reliable signal of target health.",
            "Define an application-appropriate health check and verify unhealthy targets are removed safely.",
            Effort.SMALL,
        ),
        _health_check,
    ),
    _Rule(
        _definition(
            "CG-REL-005",
            Pillar.RELIABILITY,
            Severity.MEDIUM,
            "Scaling strategy is missing",
            "A scalable service without an explicit scaling strategy may not adapt to demand or failure conditions.",
            "Define scaling targets, policies, limits, and tests based on measured demand.",
            Effort.MEDIUM,
        ),
        _scaling_strategy,
    ),
    _Rule(
        _definition(
            "CG-SEC-001",
            Pillar.SECURITY,
            Severity.CRITICAL,
            "RDS database is publicly accessible",
            "Public accessibility expands the database network exposure boundary.",
            "Set publicly_accessible to false and provide controlled private connectivity.",
            Effort.MEDIUM,
        ),
        _public_rds,
    ),
    _Rule(
        _definition(
            "CG-SEC-002",
            Pillar.SECURITY,
            Severity.HIGH,
            "Security-group ingress is unrestricted",
            "Ingress from all IPv4 or IPv6 addresses exposes the permitted ports to an unrestricted source range.",
            "Restrict ingress to the smallest required CIDRs, prefix lists, or source security groups.",
            Effort.SMALL,
        ),
        _unrestricted_ingress,
    ),
    _Rule(
        _definition(
            "CG-SEC-003",
            Pillar.SECURITY,
            Severity.HIGH,
            "IAM policy contains wildcard permissions",
            "Wildcard actions or resources can grant permissions beyond the workload's required scope.",
            "Replace wildcards with the minimum required actions and resources, using conditions where appropriate.",
            Effort.MEDIUM,
        ),
        _wildcard_iam,
    ),
    _Rule(
        _definition(
            "CG-SEC-004",
            Pillar.SECURITY,
            Severity.HIGH,
            "Encryption configuration is missing or disabled",
            "Encryption at rest is not demonstrated for a resource type with an explicit encryption control.",
            "Enable the resource's supported encryption-at-rest setting and define key ownership requirements.",
            Effort.MEDIUM,
        ),
        _encryption,
    ),
    _Rule(
        _definition(
            "CG-SEC-005",
            Pillar.SECURITY,
            Severity.CRITICAL,
            "Potential plaintext secret in configuration",
            "Literal secret material in infrastructure source can leak through source control, plans, state, logs, or review artifacts.",
            "Replace literal secret material with a secret reference and rotate any value that may have been exposed.",
            Effort.SMALL,
        ),
        _plaintext_secrets,
    ),
    _Rule(
        _definition(
            "CG-OPS-001",
            Pillar.OPERATIONAL_EXCELLENCE,
            Severity.MEDIUM,
            "Monitoring evidence is missing",
            "Operational resources without associated alarm evidence may fail without timely detection.",
            "Define actionable metrics, thresholds, alarm routing, ownership, and response procedures.",
            Effort.MEDIUM,
        ),
        _monitoring,
    ),
    _Rule(
        _definition(
            "CG-OPS-002",
            Pillar.OPERATIONAL_EXCELLENCE,
            Severity.HIGH,
            "Deployment rollback evidence is missing",
            "A failed deployment can remain stalled or unhealthy without an automatic rollback control.",
            "Enable deployment failure detection and rollback, then test a deliberately failed deployment.",
            Effort.MEDIUM,
        ),
        _deployment_rollback,
    ),
    _Rule(
        _definition(
            "CG-OPS-003",
            Pillar.OPERATIONAL_EXCELLENCE,
            Severity.MEDIUM,
            "Log retention is missing",
            "Without explicit retention, operational and security logs may be retained indefinitely or outside policy.",
            "Set retention_in_days to the approved retention period and align archival requirements.",
            Effort.EXTRA_SMALL,
        ),
        _log_retention,
    ),
    _Rule(
        _definition(
            "CG-COST-001",
            Pillar.COST_OPTIMIZATION,
            Severity.LOW,
            "Potentially expensive network path requires review",
            "NAT gateway usage can add hourly, data-processing, and cross-AZ transfer cost depending on traffic paths.",
            "Measure traffic through the NAT gateway and evaluate same-AZ routing and appropriate service endpoints.",
            Effort.MEDIUM,
        ),
        _expensive_network,
    ),
    _Rule(
        _definition(
            "CG-COST-002",
            Pillar.COST_OPTIMIZATION,
            Severity.LOW,
            "Always-on compute candidate",
            "Directly provisioned compute without scheduling or elasticity evidence may run during periods with no useful demand.",
            "Measure utilization and evaluate scheduling, auto scaling, or a demand-driven compute model.",
            Effort.MEDIUM,
        ),
        _always_on_compute,
    ),
)
