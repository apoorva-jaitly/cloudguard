"""Explicit orchestration for the CloudGuard review lifecycle."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from cloudguard.aws_context import (
    AWSContextDiagnostic,
    AWSContextResult,
    ContextDiagnosticCode,
    ContextStatus,
)
from cloudguard.bedrock_review import (
    BedrockReview,
    BedrockReviewResult,
    BedrockReviewStatus,
)
from cloudguard.domain import Architecture, Finding
from cloudguard.evidence import EvidenceAggregator, EvidencePackage
from cloudguard.facts import FactNormalizer, NormalizedFacts
from cloudguard.iac import (
    IaCAdapter,
    IaCDiagnostic,
    IaCDiagnosticSeverity,
    IaCInput,
)
from cloudguard.reports import GeneratedReports, ReportGenerator
from cloudguard.repository import (
    IdempotencyConflict,
    InvalidReviewTransition,
    RetryLimitExceeded,
    ReviewRepository,
    ReviewState,
    StoredReview,
)
from cloudguard.rules import RuleEngine, RuleEngineConfig, RuleEvaluation


class PipelineState(StrEnum):
    RECEIVED = "received"
    PROCESSING = "processing"
    PARSED = "parsed"
    CONTEXT_COLLECTED = "context_collected"
    FACTS_RECONCILED = "facts_reconciled"
    RULES_EVALUATED = "rules_evaluated"
    EVIDENCE_BUILT = "evidence_built"
    AI_REVIEWED = "ai_reviewed"
    REPORTED = "reported"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class PipelineFailureKind(StrEnum):
    PARSER = "parser"
    CONFIGURATION = "configuration"
    EVIDENCE = "evidence"
    REPORT = "report"
    PERSISTENCE = "persistence"
    INTERNAL = "internal"


class PipelineDiagnosticSeverity(StrEnum):
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class PipelineDiagnostic:
    stage: PipelineState
    severity: PipelineDiagnosticSeverity
    code: str
    message: str
    source: str | None = None

    def to_record(self) -> dict[str, str]:
        record = {
            "severity": self.severity.value,
            "message": self.message,
            "source_location": self.source or self.stage.value,
        }
        return record


@dataclass(frozen=True, slots=True)
class ReviewPipelineInput:
    review_id: str
    correlation_id: str
    idempotency_key: str
    request_hash: str
    iac_input: IaCInput
    rule_states: Mapping[str, bool]
    enable_aws_context: bool = False
    enable_bedrock: bool = False


@dataclass(frozen=True, slots=True)
class ReviewPipelineResult:
    review_id: str
    correlation_id: str
    state: PipelineState
    created: bool
    stored_review: StoredReview | None
    architecture: Architecture | None
    normalized_facts: NormalizedFacts | None
    deterministic_findings: tuple[Finding, ...]
    aws_context: AWSContextResult | None
    ai_interpretation: BedrockReview | None
    evidence_package: EvidencePackage | None
    report: GeneratedReports | None
    diagnostics: tuple[PipelineDiagnostic, ...]
    completed_stages: tuple[PipelineState, ...]
    failure_kind: PipelineFailureKind | None = None


class AWSContextProvider(Protocol):
    @property
    def region(self) -> str: ...

    def collect(self, architecture: Architecture) -> AWSContextResult: ...


class AIReviewProvider(Protocol):
    def review(self, evidence_package: EvidencePackage) -> BedrockReviewResult: ...


class ReviewPersistence(Protocol):
    def get(self, review_id: str) -> StoredReview: ...

    def create_or_get(
        self,
        *,
        review_id: str,
        idempotency_key: str,
        request_hash: str,
        filename: str,
        now: datetime,
    ) -> tuple[StoredReview, bool]: ...

    def start_processing(
        self,
        review_id: str,
        *,
        now: datetime,
        max_attempts: int,
    ) -> StoredReview: ...

    def complete(
        self,
        review_id: str,
        *,
        resource_count: int,
        findings: list[dict[str, object]],
        diagnostics: list[dict[str, str]],
        report_json: dict[str, object] | None,
        report_markdown: str | None,
        now: datetime,
        status: ReviewState = ReviewState.COMPLETED,
        error: str | None = None,
    ) -> StoredReview: ...

    def fail(
        self,
        review_id: str,
        *,
        diagnostics: list[dict[str, str]],
        error: str,
        now: datetime,
    ) -> StoredReview: ...


class ReviewPipeline:
    """Compose review services while retaining their individual responsibilities."""

    def __init__(
        self,
        repository: ReviewPersistence | ReviewRepository,
        iac_adapter: IaCAdapter,
        *,
        fact_normalizer: FactNormalizer | None = None,
        evidence_aggregator: EvidenceAggregator | None = None,
        report_generator: ReportGenerator | None = None,
        aws_context_provider: AWSContextProvider | None = None,
        bedrock_provider: AIReviewProvider | None = None,
        clock: Callable[[], datetime] | None = None,
        max_attempts: int = 3,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        self.repository = repository
        self.iac_adapter = iac_adapter
        self.fact_normalizer = fact_normalizer or FactNormalizer()
        self.evidence_aggregator = evidence_aggregator or EvidenceAggregator()
        self.report_generator = report_generator or ReportGenerator()
        self.aws_context_provider = aws_context_provider
        self.bedrock_provider = bedrock_provider
        self._clock = clock or (lambda: datetime.now(UTC))
        self.max_attempts = max_attempts

    def run(self, pipeline_input: ReviewPipelineInput) -> ReviewPipelineResult:
        diagnostics: list[PipelineDiagnostic] = []
        stages = [PipelineState.RECEIVED]
        now = self._now()
        try:
            stored, created = self.repository.create_or_get(
                review_id=pipeline_input.review_id,
                idempotency_key=pipeline_input.idempotency_key,
                request_hash=pipeline_input.request_hash,
                filename=pipeline_input.iac_input.display_name,
                now=now,
            )
        except IdempotencyConflict:
            raise
        except Exception:  # noqa: BLE001 - persistence boundary becomes pipeline state
            diagnostics.append(
                self._error(
                    PipelineState.RECEIVED,
                    "persistence_create_failed",
                    "Review persistence could not create the review.",
                )
            )
            return self._result(
                pipeline_input,
                PipelineState.FAILED,
                False,
                None,
                diagnostics,
                stages,
                failure_kind=PipelineFailureKind.PERSISTENCE,
            )
        if stored.status.terminal or stored.status is ReviewState.PROCESSING:
            return self._result(
                pipeline_input,
                self._stored_state(stored),
                False,
                stored,
                diagnostics,
                stages,
            )
        try:
            stored = self.repository.start_processing(
                stored.review_id,
                now=self._now(),
                max_attempts=self.max_attempts,
            )
        except RetryLimitExceeded:
            exhausted = self.repository.get(stored.review_id)
            return self._result(
                pipeline_input,
                PipelineState.FAILED,
                False,
                exhausted,
                diagnostics,
                stages,
                failure_kind=PipelineFailureKind.INTERNAL,
            )
        except InvalidReviewTransition:
            latest = self.repository.get(stored.review_id)
            return self._result(
                pipeline_input,
                self._stored_state(latest),
                False,
                latest,
                diagnostics,
                stages,
            )

        try:
            parsed = self.iac_adapter.parse(pipeline_input.iac_input)
        except Exception:  # noqa: BLE001 - adapter boundary becomes pipeline state
            diagnostics.append(
                self._error(
                    PipelineState.PARSED,
                    "iac_adapter_failed",
                    "IaC adapter failed to parse the submitted input.",
                    self.iac_adapter.adapter_id,
                )
            )
            return self._fail(
                pipeline_input,
                stored,
                created,
                diagnostics,
                stages,
                PipelineFailureKind.PARSER,
                "IaC parsing failed",
            )
        diagnostics.extend(self._parser_diagnostics(parsed.diagnostics))
        if parsed.has_errors:
            return self._fail(
                pipeline_input,
                stored,
                created,
                diagnostics,
                stages,
                PipelineFailureKind.PARSER,
                "IaC parsing failed",
                architecture=parsed.architecture,
            )
        stages.append(PipelineState.PARSED)

        aws_context = self._collect_context(
            pipeline_input, parsed.architecture, diagnostics
        )
        if pipeline_input.enable_aws_context:
            stages.append(PipelineState.CONTEXT_COLLECTED)

        try:
            facts = self.fact_normalizer.normalize(
                parsed.architecture, parsed.declared_evidence, aws_context
            )
            stages.append(PipelineState.FACTS_RECONCILED)
            evaluation = RuleEngine(
                RuleEngineConfig(pipeline_input.rule_states)
            ).evaluate(
                parsed.architecture,
                parsed.declared_evidence,
                normalized_facts=facts,
            )
            stages.append(PipelineState.RULES_EVALUATED)
        except ValueError:
            diagnostics.append(
                self._error(
                    PipelineState.RULES_EVALUATED,
                    "invalid_review_configuration",
                    "Review rule configuration is invalid.",
                )
            )
            return self._fail(
                pipeline_input,
                stored,
                created,
                diagnostics,
                stages,
                PipelineFailureKind.CONFIGURATION,
                "Review configuration or processing was invalid",
                architecture=parsed.architecture,
            )

        try:
            evidence_package = self.evidence_aggregator.aggregate(
                parsed.architecture,
                evaluation.findings,
                parsed.declared_evidence,
                aws_context,
                review_id=pipeline_input.review_id,
                correlation_id=pipeline_input.correlation_id,
            )
            stages.append(PipelineState.EVIDENCE_BUILT)
        except Exception:  # noqa: BLE001 - component failure becomes pipeline state
            diagnostics.append(
                self._error(
                    PipelineState.EVIDENCE_BUILT,
                    "evidence_generation_failed",
                    "Bounded evidence generation failed.",
                )
            )
            return self._partial(
                pipeline_input,
                stored,
                created,
                diagnostics,
                stages,
                PipelineFailureKind.EVIDENCE,
                "Evidence generation failed",
                architecture=parsed.architecture,
                facts=facts,
                evaluation=evaluation,
                aws_context=aws_context,
            )

        ai_interpretation = self._review_with_ai(
            pipeline_input, evidence_package, diagnostics
        )
        if pipeline_input.enable_bedrock:
            stages.append(PipelineState.AI_REVIEWED)

        try:
            report = self.report_generator.generate(
                evidence_package, ai_interpretation
            )
            stages.append(PipelineState.REPORTED)
        except Exception:  # noqa: BLE001 - component failure becomes pipeline state
            diagnostics.append(
                self._error(
                    PipelineState.REPORTED,
                    "report_generation_failed",
                    "Review report generation failed.",
                )
            )
            return self._partial(
                pipeline_input,
                stored,
                created,
                diagnostics,
                stages,
                PipelineFailureKind.REPORT,
                "Report generation failed",
                architecture=parsed.architecture,
                facts=facts,
                evaluation=evaluation,
                aws_context=aws_context,
                ai_interpretation=ai_interpretation,
                evidence_package=evidence_package,
            )

        partial = any(
            item.severity is PipelineDiagnosticSeverity.WARNING
            for item in diagnostics
        )
        try:
            completed = self.repository.complete(
                pipeline_input.review_id,
                resource_count=len(parsed.architecture.resources),
                findings=[_finding_record(item) for item in evaluation.findings],
                diagnostics=[item.to_record() for item in diagnostics],
                report_json=dict(report.json_report),
                report_markdown=report.markdown,
                now=self._now(),
                status=(
                    ReviewState.PARTIAL
                    if partial
                    else ReviewState.COMPLETED
                ),
            )
        except Exception:  # noqa: BLE001 - persistence boundary becomes pipeline state
            diagnostics.append(
                self._error(
                    PipelineState.COMPLETED,
                    "persistence_complete_failed",
                    "Review results could not be persisted.",
                )
            )
            return self._result(
                pipeline_input,
                PipelineState.FAILED,
                created,
                None,
                diagnostics,
                stages,
                architecture=parsed.architecture,
                facts=facts,
                evaluation=evaluation,
                aws_context=aws_context,
                ai_interpretation=ai_interpretation,
                evidence_package=evidence_package,
                report=report,
                failure_kind=PipelineFailureKind.PERSISTENCE,
            )
        final_state = PipelineState.PARTIAL if partial else PipelineState.COMPLETED
        stages.append(final_state)
        return self._result(
            pipeline_input,
            final_state,
            created,
            completed,
            diagnostics,
            stages,
            architecture=parsed.architecture,
            facts=facts,
            evaluation=evaluation,
            aws_context=aws_context,
            ai_interpretation=ai_interpretation,
            evidence_package=evidence_package,
            report=report,
        )

    def _collect_context(
        self,
        pipeline_input: ReviewPipelineInput,
        architecture: Architecture,
        diagnostics: list[PipelineDiagnostic],
    ) -> AWSContextResult | None:
        if not pipeline_input.enable_aws_context:
            return None
        provider = self.aws_context_provider
        if provider is None:
            result = self._unavailable_context(
                "AWS context was enabled but no provider was configured.",
                "pipeline:aws-context",
            )
        else:
            try:
                result = provider.collect(architecture)
            except Exception:  # noqa: BLE001 - provider failure means unavailable context
                result = self._unavailable_context(
                    "AWS context collection failed; resource absence was not inferred.",
                    f"aws:{provider.region}",
                )
        for item in result.diagnostics:
            diagnostics.append(
                PipelineDiagnostic(
                    PipelineState.CONTEXT_COLLECTED,
                    PipelineDiagnosticSeverity.WARNING,
                    item.code.value,
                    item.message,
                    item.source,
                )
            )
        if result.status is not ContextStatus.COMPLETE and not result.diagnostics:
            diagnostics.append(
                self._warning(
                    PipelineState.CONTEXT_COLLECTED,
                    f"aws_context_{result.status.value}",
                    f"AWS context collection was {result.status.value}.",
                    f"aws:{result.region}",
                )
            )
        return result

    def _review_with_ai(
        self,
        pipeline_input: ReviewPipelineInput,
        evidence_package: EvidencePackage,
        diagnostics: list[PipelineDiagnostic],
    ) -> BedrockReview | None:
        if not pipeline_input.enable_bedrock:
            return None
        if self.bedrock_provider is None:
            diagnostics.append(
                self._warning(
                    PipelineState.AI_REVIEWED,
                    "bedrock_unconfigured",
                    "Bedrock review was enabled but no provider was configured.",
                )
            )
            return None
        try:
            result = self.bedrock_provider.review(evidence_package)
        except Exception:  # noqa: BLE001 - provider failure means partial review
            diagnostics.append(
                self._warning(
                    PipelineState.AI_REVIEWED,
                    "bedrock_invocation_failed",
                    "Bedrock review failed; deterministic results remain authoritative.",
                )
            )
            return None
        if result.status is not BedrockReviewStatus.SUCCEEDED or result.review is None:
            diagnostics.append(
                self._warning(
                    PipelineState.AI_REVIEWED,
                    f"bedrock_{result.status.value}",
                    result.error
                    or "Bedrock output was unavailable or failed validation.",
                )
            )
            return None
        return result.review

    def _unavailable_context(self, message: str, source: str) -> AWSContextResult:
        now = self._now()
        return AWSContextResult(
            ContextStatus.UNAVAILABLE,
            (),
            (
                AWSContextDiagnostic(
                    ContextDiagnosticCode.AWS_ERROR,
                    message,
                    source,
                    now,
                ),
            ),
            source.removeprefix("aws:"),
            now,
            now,
        )

    def _fail(
        self,
        pipeline_input: ReviewPipelineInput,
        stored: StoredReview,
        created: bool,
        diagnostics: list[PipelineDiagnostic],
        stages: list[PipelineState],
        failure_kind: PipelineFailureKind,
        error: str,
        *,
        architecture: Architecture | None = None,
        facts: NormalizedFacts | None = None,
        evaluation: RuleEvaluation | None = None,
        aws_context: AWSContextResult | None = None,
        ai_interpretation: BedrockReview | None = None,
        evidence_package: EvidencePackage | None = None,
    ) -> ReviewPipelineResult:
        try:
            failed = self.repository.fail(
                pipeline_input.review_id,
                diagnostics=[item.to_record() for item in diagnostics],
                error=error,
                now=self._now(),
            )
        except Exception:  # noqa: BLE001 - failure persistence is best effort
            diagnostics.append(
                self._error(
                    PipelineState.FAILED,
                    "persistence_failure_record_failed",
                    "The review failure could not be persisted.",
                )
            )
            failed = None
            failure_kind = PipelineFailureKind.PERSISTENCE
        stages.append(PipelineState.FAILED)
        return self._result(
            pipeline_input,
            PipelineState.FAILED,
            created,
            failed,
            diagnostics,
            stages,
            architecture=architecture,
            facts=facts,
            evaluation=evaluation,
            aws_context=aws_context,
            ai_interpretation=ai_interpretation,
            evidence_package=evidence_package,
            failure_kind=failure_kind,
        )

    def _partial(
        self,
        pipeline_input: ReviewPipelineInput,
        stored: StoredReview,
        created: bool,
        diagnostics: list[PipelineDiagnostic],
        stages: list[PipelineState],
        failure_kind: PipelineFailureKind,
        error: str,
        *,
        architecture: Architecture,
        facts: NormalizedFacts,
        evaluation: RuleEvaluation,
        aws_context: AWSContextResult | None = None,
        ai_interpretation: BedrockReview | None = None,
        evidence_package: EvidencePackage | None = None,
    ) -> ReviewPipelineResult:
        try:
            partial = self.repository.complete(
                stored.review_id,
                resource_count=len(architecture.resources),
                findings=[_finding_record(item) for item in evaluation.findings],
                diagnostics=[item.to_record() for item in diagnostics],
                report_json=None,
                report_markdown=None,
                now=self._now(),
                status=ReviewState.PARTIAL,
                error=error,
            )
        except Exception:  # noqa: BLE001 - persistence boundary becomes pipeline state
            diagnostics.append(
                self._error(
                    PipelineState.PARTIAL,
                    "persistence_partial_failed",
                    "Partial review results could not be persisted.",
                )
            )
            return self._result(
                pipeline_input,
                PipelineState.FAILED,
                created,
                None,
                diagnostics,
                stages,
                architecture=architecture,
                facts=facts,
                evaluation=evaluation,
                aws_context=aws_context,
                ai_interpretation=ai_interpretation,
                evidence_package=evidence_package,
                failure_kind=PipelineFailureKind.PERSISTENCE,
            )
        stages.append(PipelineState.PARTIAL)
        return self._result(
            pipeline_input,
            PipelineState.PARTIAL,
            created,
            partial,
            diagnostics,
            stages,
            architecture=architecture,
            facts=facts,
            evaluation=evaluation,
            aws_context=aws_context,
            ai_interpretation=ai_interpretation,
            evidence_package=evidence_package,
            failure_kind=failure_kind,
        )

    def _result(
        self,
        pipeline_input: ReviewPipelineInput,
        state: PipelineState,
        created: bool,
        stored: StoredReview | None,
        diagnostics: list[PipelineDiagnostic],
        stages: list[PipelineState],
        *,
        architecture: Architecture | None = None,
        facts: NormalizedFacts | None = None,
        evaluation: RuleEvaluation | None = None,
        aws_context: AWSContextResult | None = None,
        ai_interpretation: BedrockReview | None = None,
        evidence_package: EvidencePackage | None = None,
        report: GeneratedReports | None = None,
        failure_kind: PipelineFailureKind | None = None,
    ) -> ReviewPipelineResult:
        return ReviewPipelineResult(
            stored.review_id if stored is not None else pipeline_input.review_id,
            pipeline_input.correlation_id,
            state,
            created,
            stored,
            architecture,
            facts,
            evaluation.findings if evaluation is not None else (),
            aws_context,
            ai_interpretation,
            evidence_package,
            report,
            tuple(diagnostics),
            tuple(stages),
            failure_kind,
        )

    @staticmethod
    def _parser_diagnostics(
        values: tuple[IaCDiagnostic, ...],
    ) -> tuple[PipelineDiagnostic, ...]:
        return tuple(
            PipelineDiagnostic(
                PipelineState.PARSED,
                (
                    PipelineDiagnosticSeverity.ERROR
                    if item.severity is IaCDiagnosticSeverity.ERROR
                    else PipelineDiagnosticSeverity.WARNING
                ),
                f"{item.adapter_id}_parse_error",
                item.message,
                item.source_location,
            )
            for item in values
        )

    @staticmethod
    def _stored_state(stored: StoredReview) -> PipelineState:
        if stored.status is ReviewState.COMPLETED:
            return PipelineState.COMPLETED
        if stored.status is ReviewState.PARTIAL:
            return PipelineState.PARTIAL
        if stored.status is ReviewState.FAILED:
            return PipelineState.FAILED
        if stored.status is ReviewState.PROCESSING:
            return PipelineState.PROCESSING
        return PipelineState.RECEIVED

    @staticmethod
    def _warning(
        stage: PipelineState, code: str, message: str, source: str | None = None
    ) -> PipelineDiagnostic:
        return PipelineDiagnostic(
            stage, PipelineDiagnosticSeverity.WARNING, code, message, source
        )

    @staticmethod
    def _error(
        stage: PipelineState, code: str, message: str, source: str | None = None
    ) -> PipelineDiagnostic:
        return PipelineDiagnostic(
            stage, PipelineDiagnosticSeverity.ERROR, code, message, source
        )

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("clock must return a timezone-aware datetime")
        return value.astimezone(UTC)


def _finding_record(finding: Finding) -> dict[str, object]:
    return {
        "finding_id": finding.id,
        "pillar": finding.pillar.value,
        "severity": finding.severity.value,
        "title": finding.title,
        "description": finding.description,
        "evidence_ids": list(finding.evidence_ids),
        "affected_resource_ids": list(finding.affected_resource_ids),
        "confidence": finding.confidence,
        "recommendation": finding.recommendation.description,
        "estimated_effort": finding.estimated_effort.value,
        "status": finding.status.value,
    }
