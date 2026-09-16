# Local FastAPI API

CloudGuard's local API runs directly in Python and does not require Docker.

## Start the server

From the project directory:

```bash
source .venv/bin/activate
PYTHONPATH=src uvicorn cloudguard.api:app --host 127.0.0.1 --port 8000
```

The OpenAPI UI is available at `/docs`.

By default, review state is stored in `.cloudguard/reviews.db`. Override it:

```bash
export CLOUDGUARD_DB_PATH=/absolute/path/to/reviews.db
```

## Authentication

All endpoints except `/health` require a bearer API key. Set one explicitly:

```bash
export CLOUDGUARD_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
```

If the variable is absent, CloudGuard creates `.cloudguard/api.key` with owner
read/write permissions. Send the value without logging it:

```bash
curl \
  -H "Authorization: Bearer $(cat .cloudguard/api.key)" \
  http://127.0.0.1:8000/reviews/REVIEW_ID
```

## Submit a review

`POST /reviews` accepts JSON:

```json
{
  "filename": "main.tf",
  "content": "resource \"aws_s3_bucket\" \"logs\" {}",
  "rule_states": {}
}
```

An optional `Idempotency-Key` header makes retries return the original review.
Without the header, CloudGuard uses a digest of the request.

The source is parsed in memory and is not persisted. SQLite stores only its
digest, safe filename, parser diagnostics, findings, and redacted reports.

## Controls

- Only `.tf` filenames without path components are accepted.
- Request and Terraform source sizes are bounded.
- Concurrent review processing is bounded.
- Terraform is never executed.
- Request bodies and headers are not logged.
- Correlation IDs are returned in `X-Correlation-ID`.
- Logs are structured JSON and contain event metadata only.
- Review and report responses use `Cache-Control: no-store`.
- The API key file, SQLite database, and containing directory are restricted to
  the local owner where the operating system supports POSIX permissions.
