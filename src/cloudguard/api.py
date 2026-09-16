"""Local FastAPI application for deterministic CloudGuard reviews."""

from __future__ import annotations

import contextvars
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from cloudguard.api_schemas import (
    ErrorResponse,
    FindingResponse,
    FindingsResponse,
    HealthResponse,
    ReportResponse,
    ReviewResponse,
    ReviewSubmission,
)
from cloudguard.evidence import EvidenceAggregator
from cloudguard.reports import ReportGenerator
from cloudguard.repository import (
    IdempotencyConflict,
    ReviewRepository,
    StoredReview,
)
from cloudguard.rules import RuleEngine, RuleEngineConfig
from cloudguard.terraform import TerraformParser

DEFAULT_MAX_REQUEST_BYTES = 2_100_000
_CORRELATION_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_correlation_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "correlation_id", default="unknown"
)


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname.lower(),
            "event": getattr(record, "event", "application_log"),
            "correlation_id": getattr(
                record, "correlation_id", _correlation_id.get()
            ),
        }
        for field in (
            "method",
            "path",
            "status_code",
            "duration_ms",
            "review_id",
            "error_type",
        ):
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)


logger = logging.getLogger("cloudguard.api")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(_JsonFormatter())
    logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.propagate = False


def create_app(
    *,
    database_path: str | Path | None = None,
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
    api_key: str | None = None,
    max_concurrent_reviews: int = 2,
) -> FastAPI:
    if type(max_request_bytes) is not int or not 1_024 <= max_request_bytes <= 10_000_000:
        raise ValueError("max_request_bytes must be between 1024 and 10000000")
    if (
        type(max_concurrent_reviews) is not int
        or not 1 <= max_concurrent_reviews <= 32
    ):
        raise ValueError("max_concurrent_reviews must be between 1 and 32")
    db_path = Path(
        database_path
        or os.environ.get("CLOUDGUARD_DB_PATH", ".cloudguard/reviews.db")
    )
    effective_api_key = (
        api_key
        or os.environ.get("CLOUDGUARD_API_KEY")
        or _load_or_create_api_key(db_path.parent / "api.key")
    )
    if len(effective_api_key) < 32:
        raise ValueError("api_key must contain at least 32 characters")
    repository = ReviewRepository(db_path)
    parser = TerraformParser(
        max_input_bytes=min(max_request_bytes, 2_000_000)
    )
    app = FastAPI(
        title="CloudGuard Local API",
        version="0.1.0",
        docs_url="/docs",
        redoc_url=None,
    )
    app.state.repository = repository
    app.state.max_request_bytes = max_request_bytes
    app.state.api_key = effective_api_key
    app.state.max_concurrent_reviews = max_concurrent_reviews
    app.state.active_reviews = 0
    app.state.active_reviews_lock = threading.Lock()

    @app.middleware("http")
    async def request_controls(request: Request, call_next):
        started = time.monotonic()
        supplied = request.headers.get("X-Correlation-ID")
        correlation = (
            supplied
            if supplied and _CORRELATION_RE.fullmatch(supplied)
            else str(uuid.uuid4())
        )
        token = _correlation_id.set(correlation)
        response: Response | None = None
        review_slot_acquired = False
        try:
            if request.url.path != "/health":
                authorization = request.headers.get("Authorization", "")
                expected = f"Bearer {effective_api_key}"
                if not hmac.compare_digest(authorization, expected):
                    response = _error_response(
                        401, "authentication required", correlation
                    )
            content_length = request.headers.get("content-length")
            if response is None and content_length is not None:
                try:
                    declared_size = int(content_length)
                except ValueError:
                    response = _error_response(
                        400, "invalid Content-Length", correlation
                    )
                if response is None and declared_size > max_request_bytes:
                    response = _error_response(
                        413, "request body is too large", correlation
                    )
            if (
                response is None
                and request.method == "POST"
                and request.url.path == "/reviews"
            ):
                with app.state.active_reviews_lock:
                    if app.state.active_reviews >= max_concurrent_reviews:
                        response = _error_response(
                            429,
                            "too many reviews are currently processing",
                            correlation,
                        )
                    else:
                        app.state.active_reviews += 1
                        review_slot_acquired = True
            if response is None and request.method in {"POST", "PUT", "PATCH"}:
                body = await request.body()
                if len(body) > max_request_bytes:
                    response = _error_response(
                        413, "request body is too large", correlation
                    )
            if response is None:
                response = await call_next(request)
        except Exception as error:
            logger.exception(
                "",
                extra={
                    "event": "request_failed",
                    "correlation_id": correlation,
                    "method": request.method,
                    "path": request.url.path,
                    "error_type": type(error).__name__,
                },
            )
            response = _error_response(500, "internal server error", correlation)
        finally:
            if review_slot_acquired:
                with app.state.active_reviews_lock:
                    app.state.active_reviews -= 1
            _correlation_id.reset(token)
        assert response is not None
        response.headers["X-Correlation-ID"] = correlation
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        logger.info(
            "",
            extra={
                "event": "request_completed",
                "correlation_id": correlation,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": round((time.monotonic() - started) * 1000, 3),
            },
        )
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, error: RequestValidationError
    ) -> JSONResponse:
        return _error_response(
            422,
            "request validation failed",
            _correlation_id.get(),
        )

    @app.exception_handler(HTTPException)
    async def http_error_handler(
        request: Request, error: HTTPException
    ) -> JSONResponse:
        return _error_response(
            error.status_code,
            str(error.detail),
            _correlation_id.get(),
        )

    @app.post(
        "/reviews",
        response_model=ReviewResponse,
        responses={409: {"model": ErrorResponse}, 413: {"model": ErrorResponse}},
    )
    def create_review(
        submission: ReviewSubmission,
        response: Response,
        idempotency_key: str | None = Header(
            default=None,
            alias="Idempotency-Key",
            max_length=128,
        ),
    ) -> ReviewResponse:
        content_bytes = submission.content.encode("utf-8")
        if len(content_bytes) > parser.max_input_bytes:
            raise HTTPException(413, "Terraform content is too large")
        canonical = json.dumps(
            {
                "filename": submission.filename,
                "content": submission.content,
                "rule_states": submission.rule_states,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        request_hash = hashlib.sha256(canonical).hexdigest()
        key = idempotency_key or f"sha256:{request_hash}"
        if not _IDEMPOTENCY_RE.fullmatch(key):
            raise HTTPException(422, "invalid Idempotency-Key")
        now = datetime.now(UTC)
        review_id = f"review.{uuid.uuid4().hex}"
        try:
            stored, created = repository.create_or_get(
                review_id=review_id,
                idempotency_key=key,
                request_hash=request_hash,
                filename=submission.filename,
                now=now,
            )
        except IdempotencyConflict as error:
            raise HTTPException(409, str(error)) from error
        if not created:
            response.status_code = 200
            return _review_response(stored)

        try:
            parsed = parser.parse_text(
                submission.content,
                filename=submission.filename,
            )
            diagnostics = [
                {
                    "severity": item.severity.value,
                    "message": item.message,
                    "source_location": item.source_location,
                }
                for item in parsed.diagnostics
            ]
            if parsed.has_errors:
                failed = repository.fail(
                    review_id,
                    diagnostics=diagnostics,
                    error="Terraform parsing failed",
                    now=datetime.now(UTC),
                )
                response.status_code = 201
                return _review_response(failed)

            evaluation = RuleEngine(
                RuleEngineConfig(submission.rule_states)
            ).evaluate(parsed.architecture, parsed.evidence)
            evidence_package = EvidenceAggregator().aggregate(
                parsed.architecture,
                evaluation.findings,
                parsed.evidence,
            )
            reports = ReportGenerator().generate(evidence_package)
            findings = [_finding_record(item) for item in evaluation.findings]
            completed = repository.complete(
                review_id,
                resource_count=len(parsed.architecture.resources),
                findings=findings,
                diagnostics=diagnostics,
                report_json=dict(reports.json_report),
                report_markdown=reports.markdown,
                now=datetime.now(UTC),
            )
            response.status_code = 201
            logger.info(
                "",
                extra={
                    "event": "review_completed",
                    "correlation_id": _correlation_id.get(),
                    "review_id": review_id,
                },
            )
            return _review_response(completed)
        except ValueError as error:
            failed = repository.fail(
                review_id,
                diagnostics=[],
                error="Review configuration or processing was invalid",
                now=datetime.now(UTC),
            )
            logger.warning(
                "",
                extra={
                    "event": "review_rejected",
                    "correlation_id": _correlation_id.get(),
                    "review_id": review_id,
                    "error_type": type(error).__name__,
                },
            )
            raise HTTPException(422, "review configuration is invalid") from error
        except Exception as error:
            repository.fail(
                review_id,
                diagnostics=[],
                error="Review processing failed",
                now=datetime.now(UTC),
            )
            logger.exception(
                "",
                extra={
                    "event": "review_failed",
                    "correlation_id": _correlation_id.get(),
                    "review_id": review_id,
                    "error_type": type(error).__name__,
                },
            )
            raise HTTPException(500, "review processing failed") from error

    @app.get("/reviews/{review_id}", response_model=ReviewResponse)
    def get_review(review_id: str) -> ReviewResponse:
        return _review_response(_get(repository, review_id))

    @app.get("/reviews/{review_id}/findings", response_model=FindingsResponse)
    def get_findings(review_id: str) -> FindingsResponse:
        stored = _get(repository, review_id)
        return FindingsResponse(
            review_id=review_id,
            findings=[FindingResponse.model_validate(item) for item in stored.findings],
        )

    @app.get("/reviews/{review_id}/report", response_model=ReportResponse)
    def get_report(review_id: str) -> ReportResponse:
        stored = _get(repository, review_id)
        if stored.report_json is None or stored.report_markdown is None:
            raise HTTPException(409, "report is not available for this review")
        return ReportResponse(
            review_id=review_id,
            json_report=stored.report_json,
            markdown=stored.report_markdown,
        )

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        if not repository.healthy():
            raise HTTPException(503, "review persistence is unavailable")
        return HealthResponse(status="ok", persistence="ok")

    return app


def _finding_record(finding: Any) -> dict[str, Any]:
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


def _review_response(stored: StoredReview) -> ReviewResponse:
    return ReviewResponse(
        review_id=stored.review_id,
        status=stored.status,
        filename=stored.filename,
        created_at=stored.created_at,
        updated_at=stored.updated_at,
        resource_count=stored.resource_count,
        finding_count=stored.finding_count,
        diagnostics=stored.diagnostics,
    )


def _get(repository: ReviewRepository, review_id: str) -> StoredReview:
    if not re.fullmatch(r"review\.[a-f0-9]{32}", review_id):
        raise HTTPException(404, "review not found")
    try:
        return repository.get(review_id)
    except KeyError as error:
        raise HTTPException(404, "review not found") from error


def _error_response(
    status_code: int, detail: str, correlation_id: str
) -> JSONResponse:
    body = ErrorResponse(
        detail=detail,
        correlation_id=correlation_id,
    )
    return JSONResponse(status_code=status_code, content=body.model_dump())


def _load_or_create_api_key(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("API key path must be a regular file")
        value = path.read_text(encoding="utf-8").strip()
        if len(value) < 32:
            raise RuntimeError("stored API key is invalid")
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return value
    value = secrets.token_urlsafe(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, value.encode("utf-8"))
    finally:
        os.close(descriptor)
    return value


app = create_app()


def run() -> None:
    """Run the local development server."""
    import uvicorn

    uvicorn.run(
        "cloudguard.api:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
    )
