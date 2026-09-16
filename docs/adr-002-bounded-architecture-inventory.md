# ADR 002: Bounded architecture inventory

Status: Accepted

Date: 2026-09-16

## Context

CloudGuard's evidence package previously included only resources and parsed
evidence referenced by deterministic findings. A clean architecture could
therefore produce an effectively empty package, preventing an architectural
review from describing controls and topology explicitly present in the input.

## Decision

The evidence package has three separate concerns:

1. **Architecture inventory** is deterministic, source-grounded input. It
   contains normalized resource identity and type, redacted declared
   attributes, source location, declared and observed fact identifiers,
   evidence references, and relationships already established by a parser.
2. **Finding evidence** remains the deterministic findings plus their cited
   evidence. Finding evidence is prioritized when the package reaches its byte
   budget, but it does not determine inventory membership.
3. **AI interpretation** remains optional Bedrock output. It may summarize or
   interpret only identifiers and evidence in the validated package. It is
   never stored as architecture inventory or deterministic evidence.

Explicit positive controls, such as an enabled encryption attribute, are
included as declared attributes or observed facts. Missing controls are not
invented and unavailable observations are not converted into negative facts.

The inventory is bounded by the existing package byte, item, string, and
collection limits. Resources are ordered deterministically and omitted
resources and relationships are counted. Sensitive keys and values are
redacted before size measurement. Package identifiers are derived from stable
input content and exclude generation timestamps.

## Consequences

Clean architectures now produce useful evidence packages. Architectures with
findings contain both the bounded inventory and finding-specific evidence.
Very large architectures may have inventory entries omitted; omission metadata
makes that loss explicit. Bedrock still receives no live AWS access or tools,
and Terraform is never executed.
