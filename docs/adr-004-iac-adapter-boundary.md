# ADR 004: Format-neutral IaC adapter boundary

Status: Accepted

Date: 2026-09-16

## Context

CloudGuard's review pipeline previously depended directly on
`TerraformParser`, accepted one Terraform source document, and handled
Terraform diagnostics itself. Downstream fact normalization, deterministic
rules, evidence generation, AI review, reporting, and persistence already
operate on normalized architecture and evidence objects.

This direct dependency would require format-specific parsing logic in the
pipeline for every future input format.

## Decision

CloudGuard introduces a format-neutral adapter boundary:

1. `IaCDocument` contains one named, untrusted source document.
2. `IaCInput` contains one or more uniquely named documents, applies aggregate
   size and document-count limits, and orders documents deterministically.
3. `IaCAdapter` converts `IaCInput` into `IaCParseResult`.
4. `IaCParseResult` contains only normalized `Architecture`, declared
   `Evidence`, and generic `IaCDiagnostic` objects.
5. `ReviewPipeline` depends on `IaCAdapter`, not on a concrete parser.

`TerraformAdapter` wraps the existing safe `TerraformParser`; the parser itself
is not rewritten. The API explicitly selects this adapter and continues to
accept the existing single `filename` plus `content` request shape. It also
accepts a bounded list of Terraform documents.

## Multi-document Terraform behavior

Each Terraform document is parsed independently. Results are merged in
deterministic filename order:

- resources, relationships, declared evidence, and diagnostics are combined;
- source locations retain their document filenames;
- the combined architecture ID is derived from adapter identity and canonical
  document content;
- duplicate resource or relationship identities produce error diagnostics;
- ambiguous duplicate resources and their evidence are not silently merged;
- references are resolved only within each individual document.

This deliberately does not reproduce Terraform's full module-loading or
multi-file evaluation semantics.

Terraform module records remain internal to `TerraformParser` and are not part
of the generic pipeline result.

## Trust boundary

Adapters process untrusted data and must not execute infrastructure tooling.
The Terraform adapter does not invoke Terraform, evaluate expressions, load
providers, inspect state, fetch modules, access the network, or resolve
variables and locals.

CloudFormation, Terraform plan JSON, module expansion, provider aliases,
data-source normalization, and cross-file expression resolution remain
unsupported.

## Consequences

Future IaC formats can produce the same normalized architecture and evidence
contract without changing facts, rules, evidence bounding, Bedrock validation,
reporting, or persistence. Adapter selection remains explicit at application
composition boundaries; no dynamic imports or arbitrary parser loading are
introduced.
