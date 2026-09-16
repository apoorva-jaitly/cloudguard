"""Safe, non-executing parser for Terraform HCL configuration.

The parser intentionally does not evaluate expressions, load providers, fetch
modules, inspect state, or invoke the Terraform CLI. Literal values are decoded
when unambiguous; all other expressions are retained as source text.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Final, Mapping

from cloudguard.domain import (
    AWSResource,
    Architecture,
    Evidence,
    EvidenceType,
    JsonValue,
    RelationshipType,
    ResourceRelationship,
)

_MAX_INPUT_BYTES: Final = 2_000_000
_MAX_TOKENS: Final = 200_000
_MAX_NESTING: Final = 100
_MAX_BLOCKS: Final = 20_000

_REFERENCE_RE = re.compile(
    r"(?<![\w.])(?P<address>(?:module\.[A-Za-z0-9_-]+\.)*"
    r"(?:aws|awscc)_[A-Za-z0-9_]+\.[A-Za-z0-9_-]+)(?![\w-])"
)
_TRAVERSAL_RE = re.compile(
    r"(?<![\w.])(?P<address>(?:module\.[A-Za-z0-9_-]+\.)*"
    r"[A-Za-z_][A-Za-z0-9_-]*\.[A-Za-z0-9_-]+)(?![\w-])"
)


class DiagnosticSeverity(StrEnum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True, slots=True)
class TerraformDiagnostic:
    severity: DiagnosticSeverity
    message: str
    source_location: str


@dataclass(frozen=True, slots=True)
class TerraformModule:
    name: str
    address: str
    source: str | None
    version: str | None
    dependencies: tuple[str, ...]
    attributes: Mapping[str, JsonValue]
    source_location: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))


@dataclass(frozen=True, slots=True)
class TerraformParseResult:
    architecture: Architecture
    evidence: tuple[Evidence, ...]
    modules: tuple[TerraformModule, ...]
    diagnostics: tuple[TerraformDiagnostic, ...]

    @property
    def has_errors(self) -> bool:
        return any(
            diagnostic.severity is DiagnosticSeverity.ERROR
            for diagnostic in self.diagnostics
        )


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str
    value: str
    start: int
    end: int
    line: int
    column: int


@dataclass(frozen=True, slots=True)
class _Attribute:
    name: str
    tokens: tuple[_Token, ...]
    start: _Token
    end: _Token


@dataclass(frozen=True, slots=True)
class _Block:
    block_type: str
    labels: tuple[str, ...]
    attributes: tuple[_Attribute, ...]
    children: tuple["_Block", ...]
    start: _Token
    end: _Token


class _LimitExceeded(ValueError):
    pass


class _Lexer:
    def __init__(self, source: str, filename: str) -> None:
        self.source = source
        self.filename = filename
        self.index = 0
        self.line = 1
        self.column = 1
        self.tokens: list[_Token] = []
        self.diagnostics: list[TerraformDiagnostic] = []

    def lex(self) -> tuple[tuple[_Token, ...], tuple[TerraformDiagnostic, ...]]:
        while self.index < len(self.source):
            if len(self.tokens) >= _MAX_TOKENS:
                raise _LimitExceeded(f"input exceeds {_MAX_TOKENS} tokens")
            char = self.source[self.index]
            if char in " \t\r":
                self._advance()
            elif char == "\n":
                self._emit("NEWLINE", "\n", 1)
            elif self.source.startswith("//", self.index) or char == "#":
                self._skip_line_comment()
            elif self.source.startswith("/*", self.index):
                self._skip_block_comment()
            elif char == '"':
                self._lex_string()
            elif self.source.startswith("<<", self.index):
                self._lex_heredoc()
            elif char.isalpha() or char == "_":
                self._lex_identifier()
            elif char.isdigit() or (
                char == "-"
                and self.index + 1 < len(self.source)
                and self.source[self.index + 1].isdigit()
            ):
                self._lex_number()
            else:
                self._emit(char, char, 1)
        self.tokens.append(
            _Token("EOF", "", self.index, self.index, self.line, self.column)
        )
        return tuple(self.tokens), tuple(self.diagnostics)

    def _advance(self, count: int = 1) -> None:
        for _ in range(count):
            char = self.source[self.index]
            self.index += 1
            if char == "\n":
                self.line += 1
                self.column = 1
            else:
                self.column += 1

    def _emit(self, kind: str, value: str, length: int) -> None:
        token = _Token(
            kind, value, self.index, self.index + length, self.line, self.column
        )
        self.tokens.append(token)
        self._advance(length)

    def _skip_line_comment(self) -> None:
        while self.index < len(self.source) and self.source[self.index] != "\n":
            self._advance()

    def _skip_block_comment(self) -> None:
        start_line, start_column = self.line, self.column
        self._advance(2)
        while self.index < len(self.source) and not self.source.startswith(
            "*/", self.index
        ):
            self._advance()
        if self.index == len(self.source):
            self._diagnostic(
                "unterminated block comment", start_line, start_column
            )
            return
        self._advance(2)

    def _lex_identifier(self) -> None:
        start = self.index
        line, column = self.line, self.column
        while self.index < len(self.source) and (
            self.source[self.index].isalnum()
            or self.source[self.index] in "_-"
        ):
            self._advance()
        self.tokens.append(
            _Token(
                "IDENT",
                self.source[start : self.index],
                start,
                self.index,
                line,
                column,
            )
        )

    def _lex_number(self) -> None:
        start = self.index
        line, column = self.line, self.column
        if self.source[self.index] == "-":
            self._advance()
        while self.index < len(self.source) and (
            self.source[self.index].isdigit()
            or self.source[self.index] in ".eE+-"
        ):
            self._advance()
        self.tokens.append(
            _Token(
                "NUMBER",
                self.source[start : self.index],
                start,
                self.index,
                line,
                column,
            )
        )

    def _lex_string(self) -> None:
        start = self.index
        line, column = self.line, self.column
        self._advance()
        escaped = False
        while self.index < len(self.source):
            char = self.source[self.index]
            if char == "\n":
                self._diagnostic("unterminated quoted string", line, column)
                break
            self._advance()
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                break
        else:
            self._diagnostic("unterminated quoted string", line, column)
        self.tokens.append(
            _Token(
                "STRING",
                self.source[start : self.index],
                start,
                self.index,
                line,
                column,
            )
        )

    def _lex_heredoc(self) -> None:
        start = self.index
        line, column = self.line, self.column
        marker_end = self.source.find("\n", self.index)
        if marker_end == -1:
            self._advance(len(self.source) - self.index)
            self._diagnostic("malformed heredoc marker", line, column)
        else:
            marker_text = self.source[self.index + 2 : marker_end].strip()
            marker = marker_text.removeprefix("-").strip()
            self._advance(marker_end - self.index + 1)
            if not marker or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", marker):
                self._diagnostic("malformed heredoc marker", line, column)
            else:
                closing = re.compile(rf"(?m)^[ \t]*{re.escape(marker)}[ \t]*$")
                match = closing.search(self.source, self.index)
                if match is None:
                    self._advance(len(self.source) - self.index)
                    self._diagnostic("unterminated heredoc", line, column)
                else:
                    self._advance(match.end() - self.index)
        self.tokens.append(
            _Token(
                "HEREDOC",
                self.source[start : self.index],
                start,
                self.index,
                line,
                column,
            )
        )

    def _diagnostic(self, message: str, line: int, column: int) -> None:
        self.diagnostics.append(
            TerraformDiagnostic(
                DiagnosticSeverity.ERROR,
                message,
                f"{self.filename}:{line}:{column}",
            )
        )


class _SyntaxParser:
    def __init__(
        self, tokens: tuple[_Token, ...], filename: str
    ) -> None:
        self.tokens = tokens
        self.filename = filename
        self.index = 0
        self.block_count = 0
        self.diagnostics: list[TerraformDiagnostic] = []

    def parse(self) -> tuple[tuple[_Block, ...], tuple[TerraformDiagnostic, ...]]:
        blocks: list[_Block] = []
        while self._current.kind != "EOF":
            self._skip_newlines()
            if self._current.kind == "EOF":
                break
            block = self._parse_block(0)
            if block is not None:
                blocks.append(block)
            else:
                self._recover_line()
        return tuple(blocks), tuple(self.diagnostics)

    @property
    def _current(self) -> _Token:
        return self.tokens[self.index]

    def _skip_newlines(self) -> None:
        while self._current.kind == "NEWLINE":
            self.index += 1

    def _parse_block(self, depth: int) -> _Block | None:
        if depth > _MAX_NESTING:
            raise _LimitExceeded(f"input exceeds {_MAX_NESTING} levels of nesting")
        if self._current.kind != "IDENT":
            self._error("expected a block type", self._current)
            return None
        start = self._current
        block_type = self._current.value
        self.index += 1
        labels: list[str] = []
        while self._current.kind in {"STRING", "IDENT"}:
            labels.append(_decode_label(self._current))
            self.index += 1
        if self._current.kind != "{":
            self._error(f"expected '{{' after {block_type} block header", self._current)
            return None
        self.index += 1
        self.block_count += 1
        if self.block_count > _MAX_BLOCKS:
            raise _LimitExceeded(f"input exceeds {_MAX_BLOCKS} blocks")

        attributes: list[_Attribute] = []
        children: list[_Block] = []
        while self._current.kind not in {"}", "EOF"}:
            self._skip_newlines()
            if self._current.kind in {"}", "EOF"}:
                break
            if self._current.kind != "IDENT":
                self._error("expected an attribute or nested block", self._current)
                self._recover_line()
                continue
            if self._peek_non_newline(1).kind == "=":
                attribute = self._parse_attribute()
                if attribute is not None:
                    attributes.append(attribute)
            else:
                child = self._parse_block(depth + 1)
                if child is not None:
                    children.append(child)
                else:
                    self._recover_line()
        if self._current.kind == "}":
            end = self._current
            self.index += 1
        else:
            end = self._current
            self._error(f"unterminated {block_type} block", start)
        return _Block(
            block_type,
            tuple(labels),
            tuple(attributes),
            tuple(children),
            start,
            end,
        )

    def _parse_attribute(self) -> _Attribute | None:
        start = self._current
        name = start.value
        self.index += 1
        self._skip_newlines()
        if self._current.kind != "=":
            self._error(f"expected '=' after attribute {name}", self._current)
            return None
        self.index += 1
        self._skip_newlines()
        expression: list[_Token] = []
        stack: list[str] = []
        pairs = {"[": "]", "{": "}", "(": ")"}
        while self._current.kind != "EOF":
            token = self._current
            if not stack and token.kind in {"NEWLINE", "}"}:
                break
            if token.kind in pairs:
                stack.append(pairs[token.kind])
                if len(stack) > _MAX_NESTING:
                    raise _LimitExceeded(
                        f"input exceeds {_MAX_NESTING} levels of nesting"
                    )
            elif token.kind in {"]", "}", ")"}:
                if not stack or stack[-1] != token.kind:
                    self._error(
                        f"unexpected '{token.value}' in attribute {name}", token
                    )
                    if token.kind == "}" and not stack:
                        break
                else:
                    stack.pop()
            expression.append(token)
            self.index += 1
        if stack:
            self._error(f"unterminated expression for attribute {name}", start)
        if not expression:
            self._error(f"attribute {name} has no value", start)
            return None
        return _Attribute(name, tuple(expression), start, expression[-1])

    def _peek_non_newline(self, offset: int) -> _Token:
        index = self.index + offset
        while index < len(self.tokens) and self.tokens[index].kind == "NEWLINE":
            index += 1
        return self.tokens[min(index, len(self.tokens) - 1)]

    def _recover_line(self) -> None:
        while self._current.kind not in {"NEWLINE", "}", "EOF"}:
            self.index += 1
        if self._current.kind == "NEWLINE":
            self.index += 1

    def _error(self, message: str, token: _Token) -> None:
        self.diagnostics.append(
            TerraformDiagnostic(
                DiagnosticSeverity.ERROR,
                message,
                f"{self.filename}:{token.line}:{token.column}",
            )
        )


class TerraformParser:
    """Parse Terraform source without executing or resolving configuration."""

    def __init__(
        self,
        *,
        max_input_bytes: int = _MAX_INPUT_BYTES,
        allowed_root: str | Path | None = None,
    ) -> None:
        if type(max_input_bytes) is not int or not 1 <= max_input_bytes <= _MAX_INPUT_BYTES:
            raise ValueError(
                f"max_input_bytes must be between 1 and {_MAX_INPUT_BYTES}"
            )
        self.max_input_bytes = max_input_bytes
        self.allowed_root = (
            Path(allowed_root).resolve(strict=True)
            if allowed_root is not None
            else None
        )
        if self.allowed_root is not None and not self.allowed_root.is_dir():
            raise ValueError("allowed_root must be a directory")

    def parse_file(self, path: str | Path) -> TerraformParseResult:
        source_path = Path(path)
        if self.allowed_root is not None:
            try:
                resolved_parent = source_path.parent.resolve(strict=True)
                resolved_parent.relative_to(self.allowed_root)
            except (OSError, ValueError):
                return self._empty_result(
                    str(source_path),
                    "Terraform input is outside the configured allowed root",
                )
        if source_path.is_symlink():
            return self._empty_result(
                str(source_path),
                "symbolic links are not accepted as Terraform input",
            )
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(source_path, flags)
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    return self._empty_result(
                        str(source_path),
                        "Terraform input must be a regular file",
                    )
                if metadata.st_size > self.max_input_bytes:
                    return self._empty_result(
                        str(source_path),
                        f"input exceeds {self.max_input_bytes} bytes",
                    )
                payload = os.read(descriptor, self.max_input_bytes + 1)
            finally:
                os.close(descriptor)
            if len(payload) > self.max_input_bytes:
                return self._empty_result(
                    str(source_path),
                    f"input exceeds {self.max_input_bytes} bytes",
                )
            source = payload.decode("utf-8")
        except (OSError, UnicodeError) as error:
            return self._empty_result(
                str(source_path), f"unable to read Terraform input: {error}"
            )
        return self.parse_text(source, filename=str(source_path))

    def parse_text(
        self, source: str, *, filename: str = "<memory>"
    ) -> TerraformParseResult:
        if not isinstance(source, str):
            raise TypeError("source must be a string")
        if not isinstance(filename, str) or not filename:
            raise ValueError("filename must be a non-empty string")
        if len(source.encode("utf-8")) > self.max_input_bytes:
            return self._empty_result(
                filename, f"input exceeds {self.max_input_bytes} bytes"
            )
        try:
            tokens, lexer_diagnostics = _Lexer(source, filename).lex()
            blocks, parser_diagnostics = _SyntaxParser(tokens, filename).parse()
            return self._build_result(
                source,
                filename,
                blocks,
                lexer_diagnostics + parser_diagnostics,
            )
        except _LimitExceeded as error:
            return self._empty_result(filename, str(error))
        except Exception:
            # Parser defects or hostile edge cases must not escape as input-driven
            # crashes. The generic diagnostic deliberately excludes internals.
            return self._empty_result(filename, "unable to parse Terraform input")

    def _build_result(
        self,
        source: str,
        filename: str,
        blocks: tuple[_Block, ...],
        diagnostics: tuple[TerraformDiagnostic, ...],
    ) -> TerraformParseResult:
        resource_blocks = [
            block
            for block in _walk_blocks(blocks)
            if block.block_type == "resource" and len(block.labels) >= 2
        ]
        address_to_id = {
            f"{block.labels[0]}.{block.labels[1]}": _resource_id(
                block.labels[0], block.labels[1]
            )
            for block in resource_blocks
        }
        resources: list[AWSResource] = []
        evidence: list[Evidence] = []
        relationships: list[ResourceRelationship] = []
        modules: list[TerraformModule] = []
        seen_relationships: set[tuple[str, str]] = set()

        for block in resource_blocks:
            resource_type, resource_name = block.labels[:2]
            address = f"{resource_type}.{resource_name}"
            resource_id = address_to_id[address]
            attributes, attribute_sources = _attributes(
                block.attributes, source, filename
            )
            dependencies = _block_dependencies(block, source)
            resolved = tuple(
                sorted(dependency for dependency in dependencies if dependency in address_to_id)
            )
            unresolved = tuple(sorted(set(dependencies) - set(resolved)))
            properties = dict(attributes)
            nested_blocks = _serialize_blocks(block.children, source, filename)
            if nested_blocks:
                properties["_blocks"] = nested_blocks
            properties["_cloudguard"] = {
                "terraform_address": address,
                "module_path": "root",
                "dependencies": resolved,
                "unresolved_dependencies": unresolved,
                "attribute_sources": attribute_sources,
            }
            source_location = _location(filename, block.start, block.end)
            resources.append(
                AWSResource(
                    id=resource_id,
                    resource_type=resource_type,
                    name=resource_name,
                    properties=properties,
                    source_location=source_location,
                    tags=_literal_string_map(attributes.get("tags")),
                )
            )
            resource_evidence_id = _stable_id("evidence", filename, address)
            evidence.append(
                Evidence(
                    id=resource_evidence_id,
                    evidence_type=EvidenceType.DECLARED,
                    source=source_location,
                    description=f"Terraform declares resource {address}.",
                    value={
                        "resource_type": resource_type,
                        "resource_name": resource_name,
                        "attributes": attributes,
                    },
                    resource_ids=(resource_id,),
                )
            )
            for dependency in resolved:
                key = (address, dependency)
                if key in seen_relationships:
                    continue
                seen_relationships.add(key)
                relationship_evidence_id = _stable_id(
                    "evidence", filename, address, dependency
                )
                evidence.append(
                    Evidence(
                        id=relationship_evidence_id,
                        evidence_type=EvidenceType.DECLARED,
                        source=source_location,
                        description=(
                            f"Terraform resource {address} references {dependency}."
                        ),
                        value={
                            "source_address": address,
                            "target_address": dependency,
                        },
                        resource_ids=(
                            resource_id,
                            address_to_id[dependency],
                        ),
                    )
                )
                relationships.append(
                    ResourceRelationship(
                        id=_stable_id("relationship", address, dependency),
                        source_resource_id=resource_id,
                        target_resource_id=address_to_id[dependency],
                        relationship_type=RelationshipType.DEPENDS_ON,
                        evidence_ids=(relationship_evidence_id,),
                        confidence=1.0,
                    )
                )

        for block in _walk_blocks(blocks):
            if block.block_type != "module" or not block.labels:
                continue
            attributes, _ = _attributes(block.attributes, source, filename)
            dependencies = _block_dependencies(block, source)
            modules.append(
                TerraformModule(
                    name=block.labels[0],
                    address=f"module.{block.labels[0]}",
                    source=_literal_string(attributes.get("source")),
                    version=_literal_string(attributes.get("version")),
                    dependencies=tuple(sorted(dependencies)),
                    attributes=attributes,
                    source_location=_location(filename, block.start, block.end),
                )
            )

        architecture_name = Path(filename).stem if filename != "<memory>" else "terraform"
        return TerraformParseResult(
            architecture=Architecture(
                id=_stable_id("architecture", filename),
                name=architecture_name,
                resources=tuple(resources),
                relationships=tuple(relationships),
            ),
            evidence=tuple(evidence),
            modules=tuple(modules),
            diagnostics=diagnostics,
        )

    def _empty_result(self, filename: str, message: str) -> TerraformParseResult:
        return TerraformParseResult(
            architecture=Architecture(
                id=_stable_id("architecture", filename),
                name=Path(filename).stem or "terraform",
                resources=(),
            ),
            evidence=(),
            modules=(),
            diagnostics=(
                TerraformDiagnostic(
                    DiagnosticSeverity.ERROR, message, f"{filename}:1:1"
                ),
            ),
        )


def _walk_blocks(blocks: tuple[_Block, ...]):
    for block in blocks:
        yield block
        yield from _walk_blocks(block.children)


def _attributes(
    attributes: tuple[_Attribute, ...], source: str, filename: str
) -> tuple[dict[str, JsonValue], dict[str, str]]:
    values: dict[str, JsonValue] = {}
    locations: dict[str, str] = {}
    for attribute in attributes:
        raw = source[attribute.tokens[0].start : attribute.tokens[-1].end]
        values[attribute.name] = _decode_expression(attribute.tokens, raw)
        locations[attribute.name] = _location(filename, attribute.start, attribute.end)
    return values, locations


def _decode_expression(tokens: tuple[_Token, ...], raw: str) -> JsonValue:
    compact = tuple(token for token in tokens if token.kind != "NEWLINE")
    if len(compact) == 1:
        token = compact[0]
        if token.kind == "STRING":
            try:
                return json.loads(token.value)
            except (json.JSONDecodeError, UnicodeDecodeError):
                return {"expression": raw}
        if token.kind == "HEREDOC":
            return {"expression": raw}
        if token.kind == "NUMBER":
            try:
                value = float(token.value) if any(c in token.value for c in ".eE") else int(token.value)
                if isinstance(value, float) and not math.isfinite(value):
                    return {"expression": raw}
                return value
            except ValueError:
                return {"expression": raw}
        if token.kind == "IDENT" and token.value in {"true", "false", "null"}:
            return {"true": True, "false": False, "null": None}[token.value]
    if (
        len(compact) >= 2
        and compact[0].kind == "["
        and compact[-1].kind == "]"
    ):
        items = _decode_literal_list(compact[1:-1])
        if items is not None:
            return items
    return {"expression": raw}


def _decode_literal_list(tokens: tuple[_Token, ...]) -> tuple[JsonValue, ...] | None:
    items: list[JsonValue] = []
    current: list[_Token] = []
    for token in tokens + (_Token(",", ",", 0, 0, 0, 0),):
        if token.kind == ",":
            if current:
                raw = "".join(item.value for item in current)
                decoded = _decode_expression(tuple(current), raw)
                if isinstance(decoded, Mapping) and "expression" in decoded:
                    return None
                items.append(decoded)
                current = []
        elif token.kind != "NEWLINE":
            current.append(token)
    return tuple(items)


def _dependencies(attributes: tuple[_Attribute, ...], source: str) -> tuple[str, ...]:
    dependencies: set[str] = set()
    for attribute in attributes:
        raw = source[attribute.tokens[0].start : attribute.tokens[-1].end]
        dependencies.update(match.group("address") for match in _REFERENCE_RE.finditer(raw))
        if attribute.name == "depends_on":
            dependencies.update(
                match.group("address") for match in _TRAVERSAL_RE.finditer(raw)
            )
    return tuple(sorted(dependencies))


def _block_dependencies(block: _Block, source: str) -> tuple[str, ...]:
    dependencies = set(_dependencies(block.attributes, source))
    for child in block.children:
        dependencies.update(_block_dependencies(child, source))
    return tuple(sorted(dependencies))


def _serialize_blocks(
    blocks: tuple[_Block, ...], source: str, filename: str
) -> tuple[JsonValue, ...]:
    serialized: list[JsonValue] = []
    for block in blocks:
        attributes, attribute_sources = _attributes(
            block.attributes, source, filename
        )
        item: dict[str, JsonValue] = {
            "type": block.block_type,
            "labels": block.labels,
            "attributes": attributes,
            "attribute_sources": attribute_sources,
            "source_location": _location(filename, block.start, block.end),
        }
        children = _serialize_blocks(block.children, source, filename)
        if children:
            item["blocks"] = children
        serialized.append(item)
    return tuple(serialized)


def _literal_string(value: JsonValue | None) -> str | None:
    return value if isinstance(value, str) else None


def _literal_string_map(value: JsonValue | None) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {
        key: item
        for key, item in value.items()
        if isinstance(key, str) and isinstance(item, str)
    }


def _decode_label(token: _Token) -> str:
    if token.kind == "STRING":
        try:
            value = json.loads(token.value)
            return value if isinstance(value, str) else token.value
        except json.JSONDecodeError:
            return token.value.strip('"')
    return token.value


def _resource_id(resource_type: str, name: str) -> str:
    return f"terraform.{resource_type}.{name}"


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:20]
    return f"{prefix}.{digest}"


def _location(filename: str, start: _Token, end: _Token) -> str:
    end_column = end.column + max(len(end.value), 1)
    return (
        f"{filename}:{start.line}:{start.column}-"
        f"{end.line}:{end_column}"
    )
