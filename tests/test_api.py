import io
import json
import logging
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from cloudguard.api import _JsonFormatter, create_app, logger

VALID_TERRAFORM = '''
resource "aws_db_instance" "primary" {
  identifier          = "production-db"
  publicly_accessible = true
  storage_encrypted   = false
  password            = "api-test-super-secret"
}
'''


class LocalAPITests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "reviews.db"
        self.api_key = "test-api-key-" + ("x" * 32)
        self.app = create_app(
            database_path=self.database,
            max_request_bytes=10_000,
            api_key=self.api_key,
        )
        self.client = TestClient(self.app)
        self.client.headers["Authorization"] = f"Bearer {self.api_key}"

    def tearDown(self) -> None:
        self.client.close()
        self.temp.cleanup()

    def submit(self, **kwargs):
        payload = {
            "filename": "main.tf",
            "content": VALID_TERRAFORM,
            "rule_states": {},
        }
        payload.update(kwargs.pop("payload", {}))
        return self.client.post("/reviews", json=payload, **kwargs)

    def test_review_workflow_and_all_endpoints(self) -> None:
        created = self.submit(headers={"X-Correlation-ID": "test-correlation"})

        self.assertEqual(created.status_code, 201)
        self.assertEqual(
            created.headers["X-Correlation-ID"], "test-correlation"
        )
        body = created.json()
        self.assertEqual(body["status"], "completed")
        self.assertGreater(body["finding_count"], 0)
        review_id = body["review_id"]

        review = self.client.get(f"/reviews/{review_id}")
        findings = self.client.get(f"/reviews/{review_id}/findings")
        report = self.client.get(f"/reviews/{review_id}/report")
        health = self.client.get("/health")

        self.assertEqual(review.status_code, 200)
        self.assertEqual(findings.status_code, 200)
        self.assertTrue(findings.json()["findings"])
        self.assertEqual(report.status_code, 200)
        self.assertIn("executive_summary", report.json()["json_report"])
        self.assertIn("# CloudGuard Architecture Review", report.json()["markdown"])
        self.assertEqual(health.json(), {"status": "ok", "persistence": "ok"})

    def test_multi_document_terraform_request(self) -> None:
        response = self.client.post(
            "/reviews",
            json={
                "format": "terraform",
                "documents": [
                    {
                        "filename": "database.tf",
                        "content": VALID_TERRAFORM,
                    },
                    {
                        "filename": "storage.tf",
                        "content": 'resource "aws_s3_bucket" "logs" {}',
                    },
                ],
                "rule_states": {},
            },
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["status"], "completed")
        self.assertEqual(response.json()["resource_count"], 2)

    def test_unsupported_iac_format_is_rejected(self) -> None:
        response = self.client.post(
            "/reviews",
            json={
                "format": "cloudformation",
                "filename": "main.tf",
                "content": VALID_TERRAFORM,
                "rule_states": {},
            },
        )

        self.assertEqual(response.status_code, 422)

    def test_duplicate_submission_is_idempotent(self) -> None:
        headers = {"Idempotency-Key": "same-review"}
        first = self.submit(headers=headers)
        second = self.submit(headers=headers)

        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.json()["review_id"], second.json()["review_id"])

    def test_idempotency_key_conflict_is_rejected(self) -> None:
        headers = {"Idempotency-Key": "conflicting-review"}
        first = self.submit(headers=headers)
        second = self.submit(
            headers=headers,
            payload={"content": 'resource "aws_s3_bucket" "other" {}'},
        )

        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 409)
        self.assertIn("correlation_id", second.json())

    def test_automatic_content_hash_idempotency(self) -> None:
        first = self.submit()
        second = self.submit()
        self.assertEqual(first.json()["review_id"], second.json()["review_id"])

    def test_request_size_limit_is_enforced_before_validation(self) -> None:
        app = create_app(
            database_path=Path(self.temp.name) / "small.db",
            max_request_bytes=1_024,
            api_key=self.api_key,
        )
        with TestClient(app) as client:
            client.headers["Authorization"] = f"Bearer {self.api_key}"
            response = client.post(
                "/reviews",
                json={
                    "filename": "large.tf",
                    "content": "x" * 2_000,
                    "rule_states": {},
                },
            )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json()["detail"], "request body is too large")

    def test_unsafe_filename_is_rejected_without_echoing_input(self) -> None:
        response = self.submit(
            payload={"filename": "../secret.tf"},
            headers={"X-Correlation-ID": "validation-test"},
        )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["detail"], "request validation failed")
        self.assertNotIn("../secret.tf", response.text)
        self.assertEqual(
            response.json()["correlation_id"], "validation-test"
        )

    def test_malformed_terraform_is_persisted_as_failed(self) -> None:
        response = self.submit(
            payload={
                "content": 'resource "aws_s3_bucket" "broken" {',
            }
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["status"], "failed")
        review_id = response.json()["review_id"]
        fetched = self.client.get(f"/reviews/{review_id}")
        report = self.client.get(f"/reviews/{review_id}/report")
        self.assertEqual(fetched.json()["status"], "failed")
        self.assertEqual(report.status_code, 409)

    def test_review_state_survives_app_recreation(self) -> None:
        created = self.submit()
        review_id = created.json()["review_id"]
        self.client.close()

        recreated = create_app(
            database_path=self.database,
            max_request_bytes=10_000,
            api_key=self.api_key,
        )
        with TestClient(recreated) as client:
            client.headers["Authorization"] = f"Bearer {self.api_key}"
            fetched = client.get(f"/reviews/{review_id}")

        self.assertEqual(fetched.status_code, 200)
        self.assertEqual(fetched.json()["review_id"], review_id)

    def test_correlation_id_is_generated_when_invalid(self) -> None:
        response = self.client.get(
            "/health",
            headers={"X-Correlation-ID": "contains spaces"},
        )

        correlation = response.headers["X-Correlation-ID"]
        self.assertNotEqual(correlation, "contains spaces")
        self.assertTrue(correlation)

    def test_structured_logs_and_database_do_not_contain_secret(self) -> None:
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(_JsonFormatter())
        logger.addHandler(handler)
        try:
            response = self.submit(
                headers={"X-Correlation-ID": "log-test"}
            )
        finally:
            logger.removeHandler(handler)

        self.assertEqual(response.status_code, 201)
        log_lines = [
            json.loads(line)
            for line in stream.getvalue().splitlines()
            if line.strip()
        ]
        self.assertTrue(log_lines)
        self.assertTrue(all("event" in line for line in log_lines))
        self.assertTrue(all("correlation_id" in line for line in log_lines))
        self.assertNotIn("api-test-super-secret", stream.getvalue())
        self.assertNotIn(
            b"api-test-super-secret",
            self.database.read_bytes(),
        )
        report = self.client.get(
            f"/reviews/{response.json()['review_id']}/report"
        )
        self.assertNotIn("api-test-super-secret", report.text)

    def test_unknown_review_returns_typed_error(self) -> None:
        response = self.client.get(
            "/reviews/review.00000000000000000000000000000000"
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["detail"], "review not found")
        self.assertIn("correlation_id", response.json())

    def test_review_and_report_endpoints_require_authentication(self) -> None:
        with TestClient(self.app) as unauthenticated:
            response = unauthenticated.get(
                "/reviews/review.00000000000000000000000000000000"
            )
            docs = unauthenticated.get("/docs")
            health = unauthenticated.get("/health")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(docs.status_code, 401)
        self.assertEqual(health.status_code, 200)
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_concurrent_review_limit_returns_429(self) -> None:
        self.app.state.active_reviews = self.app.state.max_concurrent_reviews
        response = self.submit()
        self.app.state.active_reviews = 0

        self.assertEqual(response.status_code, 429)

    def test_database_permissions_are_owner_only(self) -> None:
        mode = self.database.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)


if __name__ == "__main__":
    unittest.main()
