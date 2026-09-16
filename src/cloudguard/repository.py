"""SQLite-backed local review lifecycle and result persistence."""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any


class IdempotencyConflict(ValueError):
    pass


class InvalidReviewTransition(RuntimeError):
    pass


class RetryLimitExceeded(RuntimeError):
    pass


class ReviewState(StrEnum):
    RECEIVED = "received"
    PROCESSING = "processing"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"

    @property
    def terminal(self) -> bool:
        return self in {
            ReviewState.COMPLETED,
            ReviewState.PARTIAL,
            ReviewState.FAILED,
        }


ALLOWED_TRANSITIONS: dict[ReviewState, frozenset[ReviewState]] = {
    ReviewState.RECEIVED: frozenset({ReviewState.PROCESSING}),
    ReviewState.PROCESSING: frozenset(
        {
            ReviewState.RECEIVED,
            ReviewState.COMPLETED,
            ReviewState.PARTIAL,
            ReviewState.FAILED,
        }
    ),
    ReviewState.COMPLETED: frozenset(),
    ReviewState.PARTIAL: frozenset(),
    ReviewState.FAILED: frozenset(),
}


def validate_transition(current: ReviewState, target: ReviewState) -> None:
    if target not in ALLOWED_TRANSITIONS[current]:
        raise InvalidReviewTransition(
            f"review cannot transition from {current.value} to {target.value}"
        )


@dataclass(frozen=True, slots=True)
class StoredReview:
    review_id: str
    idempotency_key: str
    request_hash: str
    status: ReviewState
    filename: str
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    attempt_count: int
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
            key_row = connection.execute(
                "SELECT * FROM reviews WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if key_row is not None:
                existing = _row(key_row)
                if existing.request_hash != request_hash:
                    raise IdempotencyConflict(
                        "idempotency key was already used for different input"
                    )
                return existing, False
            content_row = connection.execute(
                "SELECT * FROM reviews WHERE request_hash = ?",
                (request_hash,),
            ).fetchone()
            if content_row is not None:
                return _row(content_row), False
            try:
                connection.execute(
                    """
                    INSERT INTO reviews (
                        review_id, idempotency_key, request_hash, status, filename,
                        created_at, updated_at, attempt_count, resource_count,
                        finding_count, diagnostics_json, findings_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, 0, '[]', '[]')
                    """,
                    (
                        review_id,
                        idempotency_key,
                        request_hash,
                        ReviewState.RECEIVED.value,
                        filename,
                        timestamp,
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as error:
                row = connection.execute(
                    """
                    SELECT * FROM reviews
                    WHERE idempotency_key = ? OR request_hash = ?
                    """,
                    (idempotency_key, request_hash),
                ).fetchone()
                if row is None:
                    raise IdempotencyConflict(
                        "deterministic review identity collision"
                    ) from error
                existing = _row(row)
                if existing.request_hash != request_hash:
                    raise IdempotencyConflict(
                        "idempotency key was already used for different input"
                    ) from error
                return existing, False
            row = connection.execute(
                "SELECT * FROM reviews WHERE review_id = ?", (review_id,)
            ).fetchone()
            assert row is not None
            return _row(row), True

    def start_processing(
        self,
        review_id: str,
        *,
        now: datetime,
        max_attempts: int,
    ) -> StoredReview:
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._get_row(connection, review_id)
            validate_transition(current.status, ReviewState.PROCESSING)
            if current.attempt_count >= max_attempts:
                timestamp = _iso(now)
                diagnostic = {
                    "severity": "error",
                    "message": "Review retry capacity was exhausted.",
                    "source_location": "processing",
                }
                connection.execute(
                    """
                    UPDATE reviews
                    SET status = ?, updated_at = ?, completed_at = ?,
                        diagnostics_json = ?, error = ?
                    WHERE review_id = ? AND status = ?
                    """,
                    (
                        ReviewState.FAILED.value,
                        timestamp,
                        timestamp,
                        _json([*current.diagnostics, diagnostic]),
                        "Review retry capacity was exhausted",
                        review_id,
                        ReviewState.RECEIVED.value,
                    ),
                )
                connection.commit()
                raise RetryLimitExceeded(review_id)
            timestamp = _iso(now)
            changed = connection.execute(
                """
                UPDATE reviews
                SET status = ?, started_at = ?, updated_at = ?,
                    completed_at = NULL, attempt_count = attempt_count + 1,
                    error = NULL
                WHERE review_id = ? AND status = ?
                """,
                (
                    ReviewState.PROCESSING.value,
                    timestamp,
                    timestamp,
                    review_id,
                    ReviewState.RECEIVED.value,
                ),
            )
            if changed.rowcount != 1:
                raise InvalidReviewTransition("review processing claim was lost")
            return self._get_row(connection, review_id)

    def complete(
        self,
        review_id: str,
        *,
        resource_count: int,
        findings: list[dict[str, Any]],
        diagnostics: list[dict[str, Any]],
        report_json: dict[str, Any] | None,
        report_markdown: str | None,
        now: datetime,
        status: ReviewState = ReviewState.COMPLETED,
        error: str | None = None,
    ) -> StoredReview:
        if status not in {ReviewState.COMPLETED, ReviewState.PARTIAL}:
            raise ValueError("status must be completed or partial")
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._get_row(connection, review_id)
            validate_transition(current.status, status)
            timestamp = _iso(now)
            changed = connection.execute(
                """
                UPDATE reviews
                SET status = ?, updated_at = ?, completed_at = ?,
                    resource_count = ?, finding_count = ?,
                    diagnostics_json = ?, findings_json = ?, report_json = ?,
                    report_markdown = ?, error = ?
                WHERE review_id = ? AND status = ?
                """,
                (
                    status.value,
                    timestamp,
                    timestamp,
                    resource_count,
                    len(findings),
                    _json(diagnostics),
                    _json(findings),
                    _json(report_json) if report_json is not None else None,
                    report_markdown,
                    error,
                    review_id,
                    ReviewState.PROCESSING.value,
                ),
            )
            if changed.rowcount != 1:
                raise InvalidReviewTransition("review completion claim was lost")
            return self._get_row(connection, review_id)

    def fail(
        self,
        review_id: str,
        *,
        diagnostics: list[dict[str, Any]],
        error: str,
        now: datetime,
    ) -> StoredReview:
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._get_row(connection, review_id)
            validate_transition(current.status, ReviewState.FAILED)
            timestamp = _iso(now)
            changed = connection.execute(
                """
                UPDATE reviews
                SET status = ?, updated_at = ?, completed_at = ?,
                    diagnostics_json = ?, error = ?
                WHERE review_id = ? AND status = ?
                """,
                (
                    ReviewState.FAILED.value,
                    timestamp,
                    timestamp,
                    _json(diagnostics),
                    error,
                    review_id,
                    ReviewState.PROCESSING.value,
                ),
            )
            if changed.rowcount != 1:
                raise InvalidReviewTransition("review failure claim was lost")
            return self._get_row(connection, review_id)

    def recover_stale(
        self,
        *,
        now: datetime,
        stale_after: timedelta,
        max_attempts: int,
    ) -> tuple[StoredReview, ...]:
        if stale_after <= timedelta(0):
            raise ValueError("stale_after must be positive")
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        cutoff = _iso(now - stale_after)
        recovered: list[StoredReview] = []
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """
                SELECT * FROM reviews
                WHERE status = ? AND updated_at <= ?
                ORDER BY created_at, review_id
                """,
                (ReviewState.PROCESSING.value, cutoff),
            ).fetchall()
            for row in rows:
                current = _row(row)
                timestamp = _iso(now)
                if current.attempt_count >= max_attempts:
                    diagnostic = {
                        "severity": "error",
                        "message": "Review retry capacity was exhausted.",
                        "source_location": "processing",
                    }
                    connection.execute(
                        """
                        UPDATE reviews
                        SET status = ?, updated_at = ?, completed_at = ?,
                            diagnostics_json = ?, error = ?
                        WHERE review_id = ? AND status = ? AND updated_at <= ?
                        """,
                        (
                            ReviewState.FAILED.value,
                            timestamp,
                            timestamp,
                            _json([*current.diagnostics, diagnostic]),
                            "Review retry capacity was exhausted",
                            current.review_id,
                            ReviewState.PROCESSING.value,
                            cutoff,
                        ),
                    )
                else:
                    connection.execute(
                        """
                        UPDATE reviews
                        SET status = ?, updated_at = ?
                        WHERE review_id = ? AND status = ? AND updated_at <= ?
                        """,
                        (
                            ReviewState.RECEIVED.value,
                            timestamp,
                            current.review_id,
                            ReviewState.PROCESSING.value,
                            cutoff,
                        ),
                    )
                recovered.append(self._get_row(connection, current.review_id))
        return tuple(recovered)

    def find_stale(
        self, *, now: datetime, stale_after: timedelta
    ) -> tuple[StoredReview, ...]:
        if stale_after <= timedelta(0):
            raise ValueError("stale_after must be positive")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM reviews
                WHERE status = ? AND updated_at <= ?
                ORDER BY created_at, review_id
                """,
                (ReviewState.PROCESSING.value, _iso(now - stale_after)),
            ).fetchall()
        return tuple(_row(row) for row in rows)

    def get(self, review_id: str) -> StoredReview:
        with self._connect() as connection:
            return self._get_row(connection, review_id)

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
                    started_at TEXT,
                    completed_at TEXT,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
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
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(reviews)").fetchall()
            }
            for name, definition in (
                ("started_at", "TEXT"),
                ("completed_at", "TEXT"),
                ("attempt_count", "INTEGER NOT NULL DEFAULT 0"),
            ):
                if name not in columns:
                    connection.execute(
                        f"ALTER TABLE reviews ADD COLUMN {name} {definition}"
                    )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS reviews_request_hash "
                "ON reviews(request_hash)"
            )

    def _get_row(
        self, connection: sqlite3.Connection, review_id: str
    ) -> StoredReview:
        row = connection.execute(
            "SELECT * FROM reviews WHERE review_id = ?", (review_id,)
        ).fetchone()
        if row is None:
            raise KeyError(review_id)
        return _row(row)

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
        status=ReviewState(row["status"]),
        filename=row["filename"],
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
        started_at=(
            datetime.fromisoformat(row["started_at"])
            if row["started_at"] is not None
            else None
        ),
        completed_at=(
            datetime.fromisoformat(row["completed_at"])
            if row["completed_at"] is not None
            else None
        ),
        attempt_count=row["attempt_count"],
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


def _json(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat()
