# ADR 003: Review pipeline orchestration

Status: Accepted

Date: 2026-09-16

## Context

CloudGuard had separate parser, fact, AWS context, rule, evidence, Bedrock,
reporting, and persistence components, but the HTTP endpoint composed them
directly. This obscured lifecycle state, made optional enrichment difficult to
test, and gave partial failures no common representation.

## Decision

`ReviewPipeline` is the application orchestration boundary. It composes the
existing services in this order:

1. receive input and establish review/correlation identity;
2. create or retrieve the persisted review;
3. parse Terraform without executing it;
4. optionally collect read-only AWS context;
5. normalize and reconcile declared and observed facts;
6. run deterministic rules;
7. build the bounded architecture evidence package;
8. optionally invoke the validated Bedrock review provider;
9. generate the deterministic or AI-enriched report; and
10. persist the final review.

The review and correlation identifiers are propagated into the bounded
evidence package and generated report, then persisted with that report.
They are trace metadata and do not affect deterministic evidence package IDs.

Each component retains its own policy and validation logic. The pipeline
coordinates data and failure semantics; it does not duplicate parsing, rule,
evidence, AI validation, reporting, or repository behavior.

## Authority boundary

Deterministic rules remain authoritative for finding existence, affected
resources, evidence sufficiency, and baseline severity. Bedrock receives only
the bounded validated evidence package. Accepted AI output may summarize,
interpret, prioritize, and discuss tradeoffs, but cannot add deterministic
findings or alter their baseline severity.

## States and failure semantics

The pipeline records completed stages and ends as:

- `completed`: all enabled stages succeeded;
- `partial`: deterministic review and report succeeded, but optional AWS or AI
  enrichment was unavailable, partial, or invalid;
- `failed`: a required stage failed.

Parser, rule configuration, evidence generation, report generation, and
persistence failures are fatal. Parser and processing failures are persisted
when persistence remains available.

AWS and Bedrock are optional:

- Disabled stages perform no external calls.
- AWS collection failures become explicit unavailable context and normalized
  unknown facts. They are never interpreted as proof that a resource is
  absent.
- Invalid or unavailable Bedrock output is discarded, recorded as a warning,
  and the deterministic report is still generated.
- A persistence completion failure returns the in-memory result with an
  explicit persistence failure and no claim that the review was stored.

## Consequences

The local API now delegates review execution to one reusable and independently
testable service. Offline Terraform-only behavior remains the default. AWS and
Bedrock providers can be injected in deployments and tests without adding live
calls to unit tests.
