"""Strict HTTP request and response schemas for the local CloudGuard API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


class StrictSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class IaCDocumentSubmission(StrictSchema):
    filename: str = Field(min_length=3, max_length=255)
    content: str = Field(min_length=1)

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, value: str) -> str:
        return _terraform_filename(value)


class ReviewSubmission(StrictSchema):
    format: str = "terraform"
    filename: str | None = Field(default=None, min_length=3, max_length=255)
    content: str | None = Field(default=None, min_length=1)
    documents: list[IaCDocumentSubmission] | None = Field(
        default=None,
        min_length=1,
        max_length=100,
    )
    rule_states: dict[str, bool] = Field(default_factory=dict)

    @field_validator("format")
    @classmethod
    def validate_format(cls, value: str) -> str:
        if value != "terraform":
            raise ValueError("unsupported IaC format")
        return value

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, value: str | None) -> str | None:
        return _terraform_filename(value) if value is not None else None

    @model_validator(mode="after")
    def validate_input_shape(self) -> ReviewSubmission:
        has_single = self.filename is not None or self.content is not None
        has_documents = self.documents is not None
        if has_single and has_documents:
            raise ValueError("provide filename/content or documents, not both")
        if has_single:
            if self.filename is None or self.content is None:
                raise ValueError("filename and content must be provided together")
        elif not has_documents:
            raise ValueError("an IaC document is required")
        return self


def _terraform_filename(value: str) -> str:
    if "\x00" in value or "/" in value or "\\" in value:
        raise ValueError("filename must not contain path components")
    if not value.lower().endswith(".tf"):
        raise ValueError("only .tf Terraform files are accepted")
    return value


class DiagnosticResponse(StrictSchema):
    severity: str
    message: str
    source_location: str


class ReviewResponse(StrictSchema):
    review_id: str
    status: str
    filename: str
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    attempt_count: int = Field(ge=0)
    resource_count: int = Field(ge=0)
    finding_count: int = Field(ge=0)
    diagnostics: list[DiagnosticResponse]


class FindingResponse(StrictSchema):
    finding_id: str
    pillar: str
    severity: str
    title: str
    description: str
    evidence_ids: list[str]
    affected_resource_ids: list[str]
    confidence: float = Field(ge=0, le=1)
    recommendation: str
    estimated_effort: str
    status: str


class FindingsResponse(StrictSchema):
    review_id: str
    findings: list[FindingResponse]


class ReportResponse(StrictSchema):
    review_id: str
    json_report: dict[str, Any]
    markdown: str


class HealthResponse(StrictSchema):
    status: str
    persistence: str


class ErrorResponse(StrictSchema):
    detail: str
    correlation_id: str
