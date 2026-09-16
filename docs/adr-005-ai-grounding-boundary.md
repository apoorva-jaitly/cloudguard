# ADR 005: Finding-scoped AI grounding boundary

Status: Accepted

Date: 2026-09-16

## Context

CloudGuard previously sent the complete bounded evidence package to Amazon
Bedrock and accepted architecture summaries, facts, implications, tradeoffs,
remediations, uncertainties, and finding priorities. Identifier validation
prevented references to unknown evidence, resources, and findings, but most
free-form fields did not require a directly verified evidence excerpt. A model
could therefore attach unsupported prose to otherwise valid identifiers.

## Decision

The deterministic layer remains authoritative for finding existence, affected
resources, baseline severity, evidence sufficiency, evidence content, and
declared or observed confirmation and contradiction.

Bedrock receives a separate, deterministic `BedrockEvidenceContext`, not the
complete evidence package or raw IaC source. The context contains only:

- existing deterministic findings, their immutable severities, affected
  resource identities, and evidence associations; and
- evidence cited by those findings, represented by stable evidence ID,
  category, source, resource identity, concise bounded excerpt, and
  provenance.

The AI response is restricted to finding-scoped advisory records:

- an existing `finding_id`;
- an advisory `review_priority`;
- rationale;
- evidence IDs associated with that finding;
- a verbatim excerpt from cited evidence; and
- an optional concise recommendation.

The model cannot return architecture facts, findings, affected-resource lists,
severity, deterministic evidence, or evidence-sufficiency decisions.
`review_priority` is report metadata and never replaces deterministic
severity.

## Validation and rejection

CloudGuard rejects malformed output, a mismatched evidence-package ID,
unknown or duplicate finding IDs, unknown or cross-finding evidence IDs,
excerpts absent from cited evidence, unsupported response fields, and resource
identities in advisory prose that are outside the deterministic finding.

These checks provide a practical grounding boundary; they do not attempt
general-purpose natural-language fact checking. Prompt instructions reinforce
the boundary, but deterministic schema and reference validation are the
primary controls.

## Prompt-injection handling

IaC-derived excerpts are untrusted data. The system instruction requires the
model to ignore embedded prompts, use only supplied evidence, avoid tools and
actions, and avoid inferring absent controls from unavailable data. The
Bedrock request supplies no tool configuration. Excerpts remain subject to
the evidence package's redaction and size controls.

## Failure semantics

Bedrock remains explicitly optional. Disabled Bedrock makes no model call.
Invocation failure, malformed output, or grounding-validation failure leaves
the deterministic findings and report intact. The pipeline records the AI
stage as unavailable or invalid and returns a partial review rather than
claiming a successful AI interpretation.

A clean architecture has no finding-scoped model context. Any attempted
model-generated finding is rejected because its identifier is not present in
the deterministic findings.

## Consequences

AI output is less expansive but has a clear provenance chain and cannot alter
CloudGuard's deterministic conclusions. Architecture-wide model narration and
open-ended remediation analysis are intentionally removed. Future expansion
must add similarly bounded, typed advisory contracts rather than restoring
unrestricted prose fields.
