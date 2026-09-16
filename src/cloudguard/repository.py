"""SQLite-backed local review state persistence."""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class IdempotencyConflict(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class StoredReview:
    review_id: str
    idempotency_key: str
    request_hash: str
    status: str
    filename: str
    created_at: datetime
    updated_at: datetime
    resource_count: int
    finding_count: int
    diagnostics: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    report_json: dict[str, Any] | None
    report_markdown: str | None
    error: str | None


class ReviewRepository:
    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.database_path.parent.chmod(0o700)
        except OSError:
            pass
        self._lock = threading.RLock()
        self._initialize()
        try:
            self.database_path.chmod(0o600)
        except OSError:
            pass

    def create_or_get(
        self,
        *,
        review_id: str,
        idempotency_key: str,
        request_hash: str,
        filename: str,
        now: datetime,
    ) -> tuple[StoredReview, bool]:
        timestamp = _iso(now)
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM reviews WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if row is not None:
                existing = _row(row)
                if existing.request_hash != request_hash:
                    raise IdempotencyConflict(
                        "idempotency key was already used for different input"
                    )
                return existing, False
            connection.execute(
                """
                INSERT INTO reviews (
                    review_id, idempotency_key, request_hash, status, filename,
                    created_at, updated_at, resource_count, finding_count,
                    diagnostics_json, findings_json
                ) VALUES (?, ?, ?, 'processing', ?, ?, ?, 0, 0, '[]', '[]')
                """,
                (
                    review_id,
                    idempotency_key,
                    request_hash,
                    filename,
                    timestamp,
                    timestamp,
                ),
            )
            row = connection.execute(
                "SELECT * FROM reviews WHERE review_id = ?", (review_id,)
            ).fetchone()
            return _row(row), True

    def complete(
        self,
        review_id: str,
        *,
        resource_count: int,
        findings: list[dict[str, Any]],
        diagnostics: list[dict[str, Any]],
        report_json: dict[str, Any],
        report_markdown: str,
        now: datetime,
    ) -> StoredReview:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                UPDATE reviews
                SET status = 'completed', updated_at = ?, resource_count = ?,
                    finding_count = ?, diagnostics_json = ?, findings_json = ?,
                    report_json = ?, report_markdown = ?, error = NULL
                WHERE review_id = ?
                """,
                (
                    _iso(now),
                    resource_count,
                    len(findings),
                    json.dumps(diagnostics, separators=(",", ":"), sort_keys=True),
                    json.dumps(findings, separators=(",", ":"), sort_keys=True),
                    json.dumps(report_json, separators=(",", ":"), sort_keys=True),
                    report_markdown,
                    review_id,
                ),
            )
            return self.get(review_id)

    def fail(
        self,
        review_id: str,
        *,
        diagnostics: list[dict[str, Any]],
        error: str,
        now: datetime,
    ) -> StoredReview:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                UPDATE reviews
                SET status = 'failed', updated_at = ?, diagnostics_json = ?,
                    error = ?
                WHERE review_id = ?
                """,
                (
                    _iso(now),
                    json.dumps(diagnostics, separators=(",", ":"), sort_keys=True),
                    error,
                    review_id,
                ),
            )
            return self.get(review_id)

    def get(self, review_id: str) -> StoredReview:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM reviews WHERE review_id = ?", (review_id,)
            ).fetchone()
        if row is None:
            raise KeyError(review_id)
        return _row(row)

    def healthy(self) -> bool:
        try:
            with self._connect() as connection:
                return connection.execute("SELECT 1").fetchone()[0] == 1
        except sqlite3.Error:
            return False

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS reviews (
                    review_id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    request_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    resource_count INTEGER NOT NULL,
                    finding_count INTEGER NOT NULL,
                    diagnostics_json TEXT NOT NULL,
                    findings_json TEXT NOT NULL,
                    report_json TEXT,
                    report_markdown TEXT,
                    error TEXT
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path,
            timeout=5,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection


def _row(row: sqlite3.Row) -> StoredReview:
    return StoredReview(
        review_id=row["review_id"],
        idempotency_key=row["idempotency_key"],
        request_hash=row["request_hash"],
        status=row["status"],
        filename=row["filename"],
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
        resource_count=row["resource_count"],
        finding_count=row["finding_count"],
        diagnostics=json.loads(row["diagnostics_json"]),
        findings=json.loads(row["findings_json"]),
        report_json=(
            json.loads(row["report_json"]) if row["report_json"] is not None else None
        ),
        report_markdown=row["report_markdown"],
        error=row["error"],
    )


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat()
