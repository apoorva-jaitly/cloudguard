"""Format-neutral, bounded input and output contracts for IaC adapters."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from cloudguard.domain import Architecture, Evidence

MAX_IAC_DOCUMENTS = 100
MAX_IAC_DOCUMENT_BYTES = 2_000_000
MAX_IAC_INPUT_BYTES = 2_000_000


class IaCDiagnosticSeverity(StrEnum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True, slots=True)
class IaCDocument:
    name: str
    content: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("document name must be a non-empty string")
        if len(self.name) > 255:
            raise ValueError("document name must not exceed 255 characters")
        if "\x00" in self.name or "/" in self.name or "\\" in self.name:
            raise ValueError("document name must not contain path components")
        if not isinstance(self.content, str) or not self.content.strip():
            raise ValueError("document content must be a non-empty string")
        if len(self.content.encode("utf-8")) > MAX_IAC_DOCUMENT_BYTES:
            raise ValueError(
                f"document content exceeds {MAX_IAC_DOCUMENT_BYTES} bytes"
            )


@dataclass(frozen=True, slots=True)
class IaCInput:
    documents: tuple[IaCDocument, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.documents, tuple) or any(
            not isinstance(item, IaCDocument) for item in self.documents
        ):
            raise TypeError("documents must be a tuple of IaCDocument objects")
        if not self.documents:
            raise ValueError("documents must not be empty")
        if len(self.documents) > MAX_IAC_DOCUMENTS:
            raise ValueError(
                f"documents must not contain more than {MAX_IAC_DOCUMENTS} items"
            )
        names = [item.name for item in self.documents]
        if len(names) != len(set(names)):
            raise ValueError("document names must be unique")
        total_bytes = sum(
            len(item.name.encode("utf-8")) + len(item.content.encode("utf-8"))
            for item in self.documents
        )
        if total_bytes > MAX_IAC_INPUT_BYTES:
            raise ValueError(f"IaC input exceeds {MAX_IAC_INPUT_BYTES} bytes")
        object.__setattr__(
            self,
            "documents",
            tuple(sorted(self.documents, key=lambda item: item.name)),
        )

    @property
    def display_name(self) -> str:
        if len(self.documents) == 1:
            return self.documents[0].name
        return f"{self.documents[0].name} (+{len(self.documents) - 1} documents)"

    @property
    def content_digest(self) -> str:
        digest = hashlib.sha256()
        for document in self.documents:
            digest.update(document.name.encode("utf-8"))
            digest.update(b"\x00")
            digest.update(document.content.encode("utf-8"))
            digest.update(b"\x00")
        return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class IaCDiagnostic:
    severity: IaCDiagnosticSeverity
    message: str
    source_location: str
    adapter_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.severity, IaCDiagnosticSeverity):
            raise TypeError("severity must be an IaCDiagnosticSeverity")
        for value, field_name, maximum in (
            (self.message, "message", 4_000),
            (self.source_location, "source_location", 2_048),
            (self.adapter_id, "adapter_id", 128),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")
            if len(value) > maximum:
                raise ValueError(f"{field_name} must not exceed {maximum} characters")


@dataclass(frozen=True, slots=True)
class IaCParseResult:
    architecture: Architecture
    declared_evidence: tuple[Evidence, ...]
    diagnostics: tuple[IaCDiagnostic, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.architecture, Architecture):
            raise TypeError("architecture must be an Architecture")
        if not isinstance(self.declared_evidence, tuple) or any(
            not isinstance(item, Evidence) for item in self.declared_evidence
        ):
            raise TypeError(
                "declared_evidence must be a tuple of Evidence objects"
            )
        if not isinstance(self.diagnostics, tuple) or any(
            not isinstance(item, IaCDiagnostic) for item in self.diagnostics
        ):
            raise TypeError("diagnostics must be a tuple of IaCDiagnostic objects")

    @property
    def has_errors(self) -> bool:
        return any(
            item.severity is IaCDiagnosticSeverity.ERROR
            for item in self.diagnostics
        )


class IaCAdapter(Protocol):
    @property
    def adapter_id(self) -> str: ...

    def parse(self, iac_input: IaCInput) -> IaCParseResult: ...
