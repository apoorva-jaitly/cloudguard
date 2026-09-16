"""Strict HTTP request and response schemas for the local CloudGuard API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ReviewSubmission(StrictSchema):
    filename: str = Field(min_length=3, max_length=255)
    content: str = Field(min_length=1)
    rule_states: dict[str, bool] = Field(default_factory=dict)

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, value: str) -> str:
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

