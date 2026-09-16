import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier

from cloudguard.repository import (
    InvalidReviewTransition,
    RetryLimitExceeded,
    ReviewRepository,
    ReviewState,
    validate_transition,
)

NOW = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)
REVIEW_ID = "review." + ("a" * 32)


class ReviewStateTests(unittest.TestCase):
    def test_valid_transitions(self) -> None:
        validate_transition(ReviewState.RECEIVED, ReviewState.PROCESSING)
        for terminal in (
            ReviewState.COMPLETED,
            ReviewState.PARTIAL,
            ReviewState.FAILED,
        ):
            validate_transition(ReviewState.PROCESSING, terminal)
        validate_transition(ReviewState.PROCESSING, ReviewState.RECEIVED)

    def test_invalid_and_terminal_transitions(self) -> None:
        with self.assertRaises(InvalidReviewTransition):
            validate_transition(ReviewState.RECEIVED, ReviewState.COMPLETED)
        for terminal in (
            ReviewState.COMPLETED,
            ReviewState.PARTIAL,
            ReviewState.FAILED,
        ):
            with self.assertRaises(InvalidReviewTransition):
                validate_transition(terminal, ReviewState.PROCESSING)


class ReviewRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "reviews.db"
        self.repository = ReviewRepository(self.database)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def create(
        self,
        *,
        review_id: str = REVIEW_ID,
        key: str = "test-key",
        request_hash: str = "1" * 64,
        now: datetime = NOW,
    ):
        return self.repository.create_or_get(
            review_id=review_id,
            idempotency_key=key,
            request_hash=request_hash,
            filename="main.tf",
            now=now,
        )

    def test_same_input_returns_same_identity_across_keys(self) -> None:
        first, created = self.create()
        second, duplicated = self.create(
            review_id="review." + ("b" * 32),
            key="another-key",
        )

        self.assertTrue(created)
        self.assertFalse(duplicated)
        self.assertEqual(first.review_id, second.review_id)

    def test_different_input_creates_different_identity(self) -> None:
        first, _ = self.create()
        second, _ = self.create(
            review_id="review." + ("b" * 32),
            key="another-key",
            request_hash="2" * 64,
        )

        self.assertNotEqual(first.review_id, second.review_id)

    def test_concurrent_duplicate_creation_has_one_logical_review(self) -> None:
        barrier = Barrier(2)

        def create(repository: ReviewRepository, review_id: str):
            barrier.wait()
            return repository.create_or_get(
                review_id=review_id,
                idempotency_key="concurrent",
                request_hash="3" * 64,
                filename="main.tf",
                now=NOW,
            )

        repositories = (
            ReviewRepository(self.database),
            ReviewRepository(self.database),
        )
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(
                executor.map(
                    create,
                    repositories,
                    (
                        "review." + ("c" * 32),
                        "review." + ("d" * 32),
                    ),
                )
            )

        self.assertEqual(sum(created for _, created in results), 1)
        self.assertEqual(len({stored.review_id for stored, _ in results}), 1)

    def test_database_uniqueness_enforces_request_hash(self) -> None:
        self.create()
        with (
            sqlite3.connect(self.database) as connection,
            self.assertRaises(sqlite3.IntegrityError),
        ):
            connection.execute(
                    """
                    INSERT INTO reviews (
                        review_id, idempotency_key, request_hash, status, filename,
                        created_at, updated_at, attempt_count, resource_count,
                        finding_count, diagnostics_json, findings_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, 0, '[]', '[]')
                    """,
                    (
                        "review." + ("e" * 32),
                        "different-key",
                        "1" * 64,
                        ReviewState.RECEIVED.value,
                        "main.tf",
                        NOW.isoformat(),
                        NOW.isoformat(),
                    ),
            )

    def test_stale_processing_is_recovered_and_fresh_is_not(self) -> None:
        stored, _ = self.create()
        self.repository.start_processing(stored.review_id, now=NOW, max_attempts=3)

        self.assertEqual(
            self.repository.find_stale(
                now=NOW + timedelta(minutes=4),
                stale_after=timedelta(minutes=5),
            ),
            (),
        )
        stale = self.repository.find_stale(
            now=NOW + timedelta(minutes=6),
            stale_after=timedelta(minutes=5),
        )
        self.assertEqual([item.review_id for item in stale], [stored.review_id])

        recovered = self.repository.recover_stale(
            now=NOW + timedelta(minutes=6),
            stale_after=timedelta(minutes=5),
            max_attempts=3,
        )
        self.assertEqual(recovered[0].status, ReviewState.RECEIVED)
        self.assertEqual(
            self.repository.recover_stale(
                now=NOW + timedelta(minutes=7),
                stale_after=timedelta(minutes=5),
                max_attempts=3,
            ),
            (),
        )

    def test_terminal_reviews_are_not_recovered_or_overwritten(self) -> None:
        stored, _ = self.create()
        self.repository.start_processing(stored.review_id, now=NOW, max_attempts=3)
        completed = self.repository.complete(
            stored.review_id,
            resource_count=0,
            findings=[],
            diagnostics=[],
            report_json={},
            report_markdown="report",
            now=NOW + timedelta(minutes=1),
        )

        self.assertEqual(
            self.repository.recover_stale(
                now=NOW + timedelta(hours=1),
                stale_after=timedelta(minutes=5),
                max_attempts=3,
            ),
            (),
        )
        with self.assertRaises(InvalidReviewTransition):
            self.repository.fail(
                completed.review_id,
                diagnostics=[],
                error="late failure",
                now=NOW + timedelta(hours=1),
            )

    def test_retry_increments_attempt_and_replaces_results(self) -> None:
        stored, _ = self.create()
        first = self.repository.start_processing(
            stored.review_id, now=NOW, max_attempts=3
        )
        self.repository.recover_stale(
            now=NOW + timedelta(minutes=6),
            stale_after=timedelta(minutes=5),
            max_attempts=3,
        )
        second = self.repository.start_processing(
            stored.review_id,
            now=NOW + timedelta(minutes=6),
            max_attempts=3,
        )
        completed = self.repository.complete(
            stored.review_id,
            resource_count=1,
            findings=[{"finding_id": "finding.one"}],
            diagnostics=[],
            report_json={},
            report_markdown="report",
            now=NOW + timedelta(minutes=7),
        )

        self.assertEqual(first.attempt_count, 1)
        self.assertEqual(second.attempt_count, 2)
        self.assertEqual(completed.review_id, stored.review_id)
        self.assertEqual(completed.finding_count, 1)
        self.assertEqual(len(completed.findings), 1)

    def test_exhausted_retry_becomes_failed(self) -> None:
        stored, _ = self.create()
        self.repository.start_processing(stored.review_id, now=NOW, max_attempts=1)
        recovered = self.repository.recover_stale(
            now=NOW + timedelta(minutes=6),
            stale_after=timedelta(minutes=5),
            max_attempts=1,
        )

        self.assertEqual(recovered[0].status, ReviewState.FAILED)
        self.assertIn("retry capacity", recovered[0].error.lower())
        self.assertEqual(recovered[0].attempt_count, 1)

    def test_received_review_cannot_start_beyond_maximum_attempts(self) -> None:
        stored, _ = self.create()
        self.repository.start_processing(stored.review_id, now=NOW, max_attempts=1)
        self.repository.recover_stale(
            now=NOW + timedelta(minutes=6),
            stale_after=timedelta(minutes=5),
            max_attempts=2,
        )

        with self.assertRaises(RetryLimitExceeded):
            self.repository.start_processing(
                stored.review_id,
                now=NOW + timedelta(minutes=7),
                max_attempts=1,
            )
        exhausted = self.repository.get(stored.review_id)
        self.assertEqual(exhausted.status, ReviewState.FAILED)
        self.assertEqual(exhausted.attempt_count, 1)


if __name__ == "__main__":
    unittest.main()
