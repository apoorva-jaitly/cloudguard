# ADR 001: Normalized declared and observed facts

Status: Accepted

Date: 2026-09-16

## Context

CloudGuard originally evaluated deterministic rules directly against parsed
Terraform resources. The read-only AWS context provider produced separately
typed observations, but those observations had no common representation with
declared configuration and could not be compared deterministically.

This separation made drift and contradictory evidence difficult to represent.
It also risked future code treating unavailable AWS data as a negative fact.

## Decision

CloudGuard uses an immutable normalized fact layer:

- `DeclaredFact` represents a literal or preserved value from submitted
  configuration.
- `ObservedFact` represents a value returned by an allowed read-only AWS API.
- `FactConflict` records different declared and observed values for the same
  resource and attribute.
- `UnknownFact` records that a value could not be established. It is not a
  negative value and is not evidence that a resource or control is absent.
- `FactReconciliation` records agreement, conflict, declared-only,
  observed-only, or unknown status.

Every fact retains resource identity, attribute, source type, source
identifier, evidence identifiers where available, and observation time where
applicable.

## Precedence and policy semantics

Declared state remains the policy input for existing deterministic rules.
Observed state may confirm a declaration, contradict it, or enrich the evidence
available to a review. It does not silently replace declared state.

When values conflict:

1. The conflict is retained explicitly.
2. Existing deterministic finding existence and baseline severity continue to
   be calculated from declared configuration.
3. A future rule may explicitly opt into observed-state or drift policy, but
   that behavior must be identified in the rule definition and tested.

Observed-only values are retained for evidence and future policies. They do not
implicitly create or suppress existing configuration findings.

## Deterministic and probabilistic boundary

Fact extraction and reconciliation are deterministic. Amazon Bedrock receives
only validated evidence and may explain implications, uncertainty, tradeoffs,
and remediation ordering. It does not decide whether a deterministic finding
exists, alter its baseline severity, execute AWS actions, or turn unavailable
context into a fact.

## Compatibility

When no AWS context is supplied, the rule engine normalizes declared facts and
preserves its existing Terraform-only behavior. The optional normalized-fact
input provides an incremental migration path for rules without requiring an
immediate rewrite of the complete catalog.

## Consequences

The architecture can now represent agreement, drift, and unavailable context
without conflating them. Existing rules remain declaration-authoritative.
Future work is required to expose reconciliation in reports and to define
explicit observed-state rules where operational drift should itself produce a
finding.
