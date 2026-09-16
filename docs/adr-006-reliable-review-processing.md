# ADR 006: Reliable local review processing

Status: Accepted

Date: 2026-09-16

## Context

CloudGuard executes reviews synchronously and persists results in SQLite. A
process interruption previously left a review in an unbounded `processing`
state. Lifecycle transitions were not guarded, retries had no persisted
attempt count, and caller-selected idempotency keys allowed the same logical
input to create more than one review.

This decision strengthens the local contract without adding a queue, worker,
distributed lock, container runtime, or new AWS service.

## Decision

The persisted review lifecycle is:

```text
RECEIVED -> PROCESSING -> COMPLETED
                       -> PARTIAL
                       -> FAILED
```

Recovery may perform `PROCESSING(stale) -> RECEIVED`. A later identical
submission can then claim the same review for another processing attempt.
Terminal states have no outgoing transitions.

SQLite transitions run in `BEGIN IMMEDIATE` transactions. Each update checks
the expected current state in the same transaction that writes associated
timestamps, diagnostics, findings, reports, counts, and errors. Illegal or
lost transitions raise an explicit error rather than overwriting state.

## Idempotency

The logical input is canonicalized and hashed with SHA-256. The request hash is
the durable idempotency identity and has a database uniqueness constraint. The
public review identifier is deterministically derived from the first 128 bits
of that hash, retaining the existing `review.<32 hex characters>` format.

A caller-provided idempotency key remains supported. Reusing it for different
content is a conflict. The same content submitted under different keys still
resolves to the existing logical review. A primary-key collision with
different content is rejected rather than silently merged.

## Recovery and retries

`started_at`, `updated_at`, `completed_at`, and `attempt_count` are persisted.
A review is stale when it remains `PROCESSING` and `updated_at` is at or before
the caller-supplied stale threshold.

The explicit recovery operation:

- ignores fresh and terminal reviews;
- returns stale reviews to `RECEIVED` when retry capacity remains;
- marks a stale review `FAILED` with a retry-exhaustion diagnostic when its
  configured maximum attempts have been used; and
- is safe to invoke repeatedly.

CloudGuard does not persist raw IaC source, so recovery does not execute work
by itself. Retrying requires an identical resubmission, which reuses the review
ID and atomically increments the attempt count.

## Partial and failed semantics

`COMPLETED` means all enabled stages succeeded. `PARTIAL` means meaningful
deterministic output exists but optional enrichment or a later required
presentation stage failed. AWS or Bedrock unavailability therefore preserves
deterministic findings. Evidence or report generation failures preserve
deterministic findings when those findings were already produced.

`FAILED` means no valid deterministic review result could be produced, retry
capacity was exhausted, or persistence could not truthfully record a result.

Retries replace the review's result fields atomically. They do not append
findings, evidence, or reports and cannot overwrite terminal reviews.

## SQLite concurrency limitations

SQLite uniqueness constraints and `BEGIN IMMEDIATE` serialize competing review
creation and transition writers across connections. The in-process lock
reduces contention within one repository instance. SQLite still permits only
one writer at a time and uses a bounded busy timeout; it is suitable for this
local API, not high-throughput multi-host processing or tenant isolation.

Distributed queues and workers are intentionally deferred. The lifecycle,
idempotency, recovery, and retry contract can later map onto serverless
execution without changing deterministic review authority or evidence
boundaries.
