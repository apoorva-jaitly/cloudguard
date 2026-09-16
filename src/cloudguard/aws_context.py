"""Read-only AWS context collection using a fixed boto3 operation allowlist."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Callable, Mapping

import boto3
from botocore.config import Config
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    EndpointConnectionError,
    NoCredentialsError,
    PartialCredentialsError,
)

from cloudguard.domain import AWSResource, Architecture, Evidence, EvidenceType, JsonValue

_REGION_RE = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
_READ_ONLY_OPERATIONS = frozenset(
    {
        ("ec2", "describe_instances"),
        ("ec2", "describe_security_groups"),
        ("ec2", "describe_volumes"),
        ("rds", "describe_db_instances"),
        ("rds", "describe_db_clusters"),
        ("logs", "describe_log_groups"),
        ("ecs", "describe_services"),
    }
)


class ContextStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"


class ContextDiagnosticCode(StrEnum):
    ACCESS_DENIED = "access_denied"
    CREDENTIALS_UNAVAILABLE = "credentials_unavailable"
    ENDPOINT_UNAVAILABLE = "endpoint_unavailable"
    IDENTIFIER_UNAVAILABLE = "identifier_unavailable"
    RESOURCE_NOT_OBSERVED = "resource_not_observed"
    AWS_ERROR = "aws_error"


@dataclass(frozen=True, slots=True)
class AWSContextConfig:
    region: str
    cache_ttl_seconds: int = 300

    def __post_init__(self) -> None:
        if not isinstance(self.region, str) or not _REGION_RE.fullmatch(self.region):
            raise ValueError("region must be a valid AWS region identifier")
        if (
            type(self.cache_ttl_seconds) is not int
            or not 0 <= self.cache_ttl_seconds <= 86_400
        ):
            raise ValueError("cache_ttl_seconds must be between 0 and 86400")


@dataclass(frozen=True, slots=True)
class AWSFact:
    id: str
    resource_id: str
    name: str
    value: JsonValue
    source: str
    observed_at: datetime
    region: str

    def __post_init__(self) -> None:
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() != UTC.utcoffset(
            self.observed_at
        ):
            raise ValueError("observed_at must be timezone-aware UTC")

    def to_evidence(self) -> Evidence:
        return Evidence(
            id=_stable_id(
                "evidence",
                self.resource_id,
                self.name,
                self.source,
                self.observed_at.isoformat(),
            ),
            evidence_type=EvidenceType.OBSERVED,
            source=self.source,
            description=f"AWS reported {self.name} for {self.resource_id}.",
            value={"name": self.name, "value": self.value, "region": self.region},
            resource_ids=(self.resource_id,),
            collected_at=self.observed_at,
        )


@dataclass(frozen=True, slots=True)
class AWSContextDiagnostic:
    code: ContextDiagnosticCode
    message: str
    source: str
    observed_at: datetime
    resource_id: str | None = None


@dataclass(frozen=True, slots=True)
class AWSContextResult:
    status: ContextStatus
    facts: tuple[AWSFact, ...]
    diagnostics: tuple[AWSContextDiagnostic, ...]
    region: str
    started_at: datetime
    completed_at: datetime

    def evidence(self) -> tuple[Evidence, ...]:
        return tuple(fact.to_evidence() for fact in self.facts)


@dataclass(frozen=True, slots=True)
class _CacheEntry:
    expires_at: float
    response: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class _Observation:
    source: str
    values: Mapping[str, JsonValue]


class ReadOnlyAWSContextProvider:
    """Collect selected AWS facts without exposing arbitrary boto3 operations."""

    def __init__(
        self,
        config: AWSContextConfig,
        *,
        session_factory: Callable[[str], Any] | None = None,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
    ) -> None:
        if not isinstance(config, AWSContextConfig):
            raise TypeError("config must be an AWSContextConfig")
        self.config = config
        self._session_factory = session_factory or self._default_session
        self._clock = clock or (lambda: datetime.now(UTC))
        self._monotonic = monotonic or time.monotonic
        self._session: Any | None = None
        self._clients: dict[str, Any] = {}
        self._cache: dict[str, _CacheEntry] = {}
        self._lock = threading.RLock()

    @property
    def region(self) -> str:
        return self.config.region

    @property
    def allowed_operations(self) -> frozenset[tuple[str, str]]:
        return _READ_ONLY_OPERATIONS

    def collect(self, architecture: Architecture) -> AWSContextResult:
        if not isinstance(architecture, Architecture):
            raise TypeError("architecture must be an Architecture")
        started_at = self._now()
        facts: list[AWSFact] = []
        diagnostics: list[AWSContextDiagnostic] = []

        for resource in architecture.resources:
            collector = _COLLECTORS.get(resource.resource_type)
            if collector is None:
                continue
            try:
                observation = collector(self, resource)
            except _CollectionUnavailable as error:
                diagnostics.append(
                    AWSContextDiagnostic(
                        error.code,
                        error.message,
                        error.source,
                        self._now(),
                        resource.id,
                    )
                )
                continue
            if observation is None:
                diagnostics.append(
                    AWSContextDiagnostic(
                        ContextDiagnosticCode.RESOURCE_NOT_OBSERVED,
                        (
                            "AWS returned no matching resource. This is not treated "
                            "as proof that the resource is absent."
                        ),
                        f"aws:{self.config.region}:{resource.resource_type}",
                        self._now(),
                        resource.id,
                    )
                )
                continue
            observed_at = self._now()
            for name, value in sorted(observation.values.items()):
                facts.append(
                    AWSFact(
                        id=_stable_id(
                            "fact",
                            resource.id,
                            name,
                            observation.source,
                            observed_at.isoformat(),
                        ),
                        resource_id=resource.id,
                        name=name,
                        value=value,
                        source=observation.source,
                        observed_at=observed_at,
                        region=self.config.region,
                    )
                )

        completed_at = self._now()
        if diagnostics and not facts:
            status = ContextStatus.UNAVAILABLE
        elif diagnostics:
            status = ContextStatus.PARTIAL
        else:
            status = ContextStatus.COMPLETE
        return AWSContextResult(
            status,
            tuple(facts),
            tuple(diagnostics),
            self.config.region,
            started_at,
            completed_at,
        )

    def clear_cache(self) -> None:
        with self._lock:
            self._cache.clear()

    def _call(
        self, service: str, operation: str, parameters: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        if (service, operation) not in _READ_ONLY_OPERATIONS:
            raise RuntimeError(
                f"operation {service}.{operation} is not in the read-only allowlist"
            )
        cache_key = json.dumps(
            [self.config.region, service, operation, parameters],
            sort_keys=True,
            separators=(",", ":"),
        )
        now = self._monotonic()
        with self._lock:
            cached = self._cache.get(cache_key)
            if cached is not None and cached.expires_at >= now:
                return copy.deepcopy(cached.response)
        source = f"aws:{self.config.region}:{service}:{operation}"
        try:
            client = self._client(service)
            response = getattr(client, operation)(**dict(parameters))
        except (NoCredentialsError, PartialCredentialsError) as error:
            raise _CollectionUnavailable(
                ContextDiagnosticCode.CREDENTIALS_UNAVAILABLE,
                "AWS credentials are unavailable.",
                source,
            ) from error
        except EndpointConnectionError as error:
            raise _CollectionUnavailable(
                ContextDiagnosticCode.ENDPOINT_UNAVAILABLE,
                "The AWS service endpoint is unavailable.",
                source,
            ) from error
        except ClientError as error:
            code = str(error.response.get("Error", {}).get("Code", ""))
            diagnostic_code = (
                ContextDiagnosticCode.ACCESS_DENIED
                if code
                in {
                    "AccessDenied",
                    "AccessDeniedException",
                    "UnauthorizedOperation",
                    "UnrecognizedClientException",
                }
                else ContextDiagnosticCode.AWS_ERROR
            )
            raise _CollectionUnavailable(
                diagnostic_code,
                f"AWS did not return context ({code or 'ClientError'}).",
                source,
            ) from error
        except BotoCoreError as error:
            raise _CollectionUnavailable(
                ContextDiagnosticCode.AWS_ERROR,
                "The AWS SDK could not retrieve context.",
                source,
            ) from error
        if not isinstance(response, Mapping):
            raise _CollectionUnavailable(
                ContextDiagnosticCode.AWS_ERROR,
                "AWS returned an unexpected response.",
                source,
            )
        if self.config.cache_ttl_seconds > 0:
            with self._lock:
                self._cache[cache_key] = _CacheEntry(
                    now + self.config.cache_ttl_seconds,
                    copy.deepcopy(response),
                )
        return response

    def _client(self, service: str) -> Any:
        with self._lock:
            if service in self._clients:
                return self._clients[service]
            if self._session is None:
                self._session = self._session_factory(self.config.region)
            client = self._session.client(
                service,
                region_name=self.config.region,
                config=Config(
                    retries={"max_attempts": 3, "mode": "standard"},
                    connect_timeout=3,
                    read_timeout=10,
                ),
            )
            self._clients[service] = client
            return client

    def _default_session(self, region: str) -> Any:
        return boto3.session.Session(region_name=region)

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("clock must return a timezone-aware datetime")
        return value.astimezone(UTC)


class _CollectionUnavailable(Exception):
    def __init__(
        self, code: ContextDiagnosticCode, message: str, source: str
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.source = source


def _require_identifier(
    resource: AWSResource, source: str, *property_names: str
) -> str:
    for name in property_names:
        value = resource.properties.get(name)
        if isinstance(value, str) and value.strip():
            return value
    raise _CollectionUnavailable(
        ContextDiagnosticCode.IDENTIFIER_UNAVAILABLE,
        (
            "The submitted architecture does not contain a literal deployed "
            f"identifier ({', '.join(property_names)}); AWS was not queried."
        ),
        source,
    )


def _collect_db_instance(
    provider: ReadOnlyAWSContextProvider, resource: AWSResource
) -> _Observation | None:
    source = f"aws:{provider.region}:rds:describe_db_instances"
    identifier = _require_identifier(
        resource, source, "identifier", "db_instance_identifier"
    )
    response = provider._call(
        "rds", "describe_db_instances", {"DBInstanceIdentifier": identifier}
    )
    instances = response.get("DBInstances", ())
    if not isinstance(instances, (list, tuple)) or not instances:
        return None
    item = instances[0]
    return _Observation(
        source,
        MappingProxyType(
            {
                "publicly_accessible": bool(item.get("PubliclyAccessible")),
                "multi_az": bool(item.get("MultiAZ")),
                "storage_encrypted": bool(item.get("StorageEncrypted")),
                "backup_retention_period": int(item.get("BackupRetentionPeriod", 0)),
                "availability_zone": str(item.get("AvailabilityZone", "")),
                "status": str(item.get("DBInstanceStatus", "")),
            }
        ),
    )


def _collect_db_cluster(
    provider: ReadOnlyAWSContextProvider, resource: AWSResource
) -> _Observation | None:
    source = f"aws:{provider.region}:rds:describe_db_clusters"
    identifier = _require_identifier(
        resource, source, "cluster_identifier", "db_cluster_identifier"
    )
    response = provider._call(
        "rds", "describe_db_clusters", {"DBClusterIdentifier": identifier}
    )
    clusters = response.get("DBClusters", ())
    if not isinstance(clusters, (list, tuple)) or not clusters:
        return None
    item = clusters[0]
    zones = item.get("AvailabilityZones", ())
    return _Observation(
        source,
        MappingProxyType(
            {
                "storage_encrypted": bool(item.get("StorageEncrypted")),
                "backup_retention_period": int(item.get("BackupRetentionPeriod", 0)),
                "availability_zones": tuple(str(zone) for zone in zones),
                "status": str(item.get("Status", "")),
            }
        ),
    )


def _collect_instance(
    provider: ReadOnlyAWSContextProvider, resource: AWSResource
) -> _Observation | None:
    source = f"aws:{provider.region}:ec2:describe_instances"
    identifier = _require_identifier(resource, source, "instance_id", "id")
    response = provider._call(
        "ec2", "describe_instances", {"InstanceIds": [identifier]}
    )
    reservations = response.get("Reservations", ())
    instances = [
        item
        for reservation in reservations
        for item in reservation.get("Instances", ())
    ]
    if not instances:
        return None
    item = instances[0]
    placement = item.get("Placement", {})
    state = item.get("State", {})
    return _Observation(
        source,
        MappingProxyType(
            {
                "instance_type": str(item.get("InstanceType", "")),
                "state": str(state.get("Name", "")),
                "availability_zone": str(placement.get("AvailabilityZone", "")),
                "public_ip_assigned": bool(item.get("PublicIpAddress")),
            }
        ),
    )


def _collect_security_group(
    provider: ReadOnlyAWSContextProvider, resource: AWSResource
) -> _Observation | None:
    source = f"aws:{provider.region}:ec2:describe_security_groups"
    identifier = _require_identifier(resource, source, "group_id", "id")
    response = provider._call(
        "ec2", "describe_security_groups", {"GroupIds": [identifier]}
    )
    groups = response.get("SecurityGroups", ())
    if not isinstance(groups, (list, tuple)) or not groups:
        return None
    group = groups[0]
    ingress = tuple(
        {
            "protocol": str(permission.get("IpProtocol", "")),
            "from_port": permission.get("FromPort"),
            "to_port": permission.get("ToPort"),
            "ipv4_cidrs": tuple(
                str(item.get("CidrIp", "")) for item in permission.get("IpRanges", ())
            ),
            "ipv6_cidrs": tuple(
                str(item.get("CidrIpv6", ""))
                for item in permission.get("Ipv6Ranges", ())
            ),
        }
        for permission in group.get("IpPermissions", ())
    )
    return _Observation(
        source,
        MappingProxyType(
            {
                "group_id": str(group.get("GroupId", "")),
                "vpc_id": str(group.get("VpcId", "")),
                "ingress": ingress,
            }
        ),
    )


def _collect_volume(
    provider: ReadOnlyAWSContextProvider, resource: AWSResource
) -> _Observation | None:
    source = f"aws:{provider.region}:ec2:describe_volumes"
    identifier = _require_identifier(resource, source, "volume_id", "id")
    response = provider._call("ec2", "describe_volumes", {"VolumeIds": [identifier]})
    volumes = response.get("Volumes", ())
    if not isinstance(volumes, (list, tuple)) or not volumes:
        return None
    item = volumes[0]
    return _Observation(
        source,
        MappingProxyType(
            {
                "encrypted": bool(item.get("Encrypted")),
                "availability_zone": str(item.get("AvailabilityZone", "")),
                "state": str(item.get("State", "")),
                "size_gib": int(item.get("Size", 0)),
                "volume_type": str(item.get("VolumeType", "")),
            }
        ),
    )


def _collect_log_group(
    provider: ReadOnlyAWSContextProvider, resource: AWSResource
) -> _Observation | None:
    source = f"aws:{provider.region}:logs:describe_log_groups"
    name = _require_identifier(resource, source, "name", "log_group_name")
    response = provider._call(
        "logs", "describe_log_groups", {"logGroupNamePrefix": name, "limit": 50}
    )
    groups = response.get("logGroups", ())
    group = next(
        (
            item
            for item in groups
            if isinstance(item, Mapping) and item.get("logGroupName") == name
        ),
        None,
    )
    if group is None:
        return None
    return _Observation(
        source,
        MappingProxyType(
            {
                "retention_in_days": (
                    int(group["retentionInDays"])
                    if "retentionInDays" in group
                    else None
                ),
                "kms_key_configured": bool(group.get("kmsKeyId")),
                "stored_bytes": int(group.get("storedBytes", 0)),
            }
        ),
    )


def _collect_ecs_service(
    provider: ReadOnlyAWSContextProvider, resource: AWSResource
) -> _Observation | None:
    source = f"aws:{provider.region}:ecs:describe_services"
    service = _require_identifier(resource, source, "name", "service_name")
    cluster = _require_identifier(resource, source, "cluster", "cluster_name")
    response = provider._call(
        "ecs",
        "describe_services",
        {"cluster": cluster, "services": [service]},
    )
    services = response.get("services", ())
    if not isinstance(services, (list, tuple)) or not services:
        return None
    item = services[0]
    deployment = item.get("deploymentConfiguration", {})
    circuit_breaker = deployment.get("deploymentCircuitBreaker", {})
    return _Observation(
        source,
        MappingProxyType(
            {
                "status": str(item.get("status", "")),
                "desired_count": int(item.get("desiredCount", 0)),
                "running_count": int(item.get("runningCount", 0)),
                "circuit_breaker_enabled": bool(circuit_breaker.get("enable")),
                "rollback_enabled": bool(circuit_breaker.get("rollback")),
            }
        ),
    )


_COLLECTORS: Mapping[
    str,
    Callable[[ReadOnlyAWSContextProvider, AWSResource], _Observation | None],
] = MappingProxyType(
    {
        "aws_db_instance": _collect_db_instance,
        "aws_rds_cluster": _collect_db_cluster,
        "aws_instance": _collect_instance,
        "aws_security_group": _collect_security_group,
        "aws_ebs_volume": _collect_volume,
        "aws_cloudwatch_log_group": _collect_log_group,
        "aws_ecs_service": _collect_ecs_service,
    }
)


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:20]
    return f"{prefix}.{digest}"

