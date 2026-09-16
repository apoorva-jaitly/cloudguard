# CloudGuard security review

Review date: 2026-09-16

Scope: Terraform ingestion, deterministic analysis, AWS context collection,
evidence aggregation, Amazon Bedrock reasoning, report generation, local API,
SQLite persistence, and documented IAM permissions.

## Summary

No confirmed Critical vulnerability was identified. Five High-risk findings
were fixed during this review. Remaining risks are Medium or Low and are
documented below.

## Findings and disposition

| Area | Severity | Finding | Disposition |
|---|---|---|---|
| Report exposure | High | Review, finding, report, and OpenAPI endpoints had no authentication. | Fixed: bearer authentication is mandatory except for `/health`; comparison is constant-time. |
| Report exposure | High | SQLite reports relied on process umask and responses could be cached. | Fixed: database/key directory uses `0700`, files use `0600` where supported, and responses include `Cache-Control: no-store`, `nosniff`, frame denial, and no-referrer headers. |
| Denial of service | High | Valid concurrent review requests could consume all parser worker capacity. | Fixed: configurable concurrent-review admission control returns HTTP 429 before parsing. Existing byte, token, nesting, and block limits remain enforced. |
| Model output injection | High | Model facts needed valid IDs but did not prove that cited evidence contained supporting content. Architecture summary citations were not required. | Fixed: summaries require evidence IDs; each fact requires a verbatim excerpt found in cited evidence; unknown IDs and extra fields remain rejected. |
| Model/report injection | High | Model-controlled Markdown characters could create links or alter rendered structure. | Fixed: Markdown metacharacters and HTML delimiters are escaped; model output remains schema validated and secret-redacted. |
| Arbitrary file access | Medium | `parse_file` accepted caller-selected paths and had a symlink-check/read race. The HTTP API itself never accepted paths. | Reduced: file opening uses `O_NOFOLLOW` where available, requires regular files, and supports a configured allowed root with traversal rejection. |
| Malicious Terraform | Medium | A hostile source can exercise parser edge cases and consume bounded CPU. | Reduced: Terraform is never executed; providers/modules/functions are not loaded; input bytes, tokens, nesting, blocks, and concurrent reviews are bounded. |
| Prompt injection | Medium | Descriptions and string attributes can contain instructions aimed at the model. Comments are discarded by the parser. | Reduced: only redacted evidence is sent, package delimiters are unpredictable, data is explicitly marked untrusted, tools are disabled, output is closed-schema validated, and factual excerpts are checked. Natural-language interpretation can still be influenced. |
| Secrets leakage | Medium | Pattern-based redaction cannot guarantee discovery of every proprietary credential format. | Reduced: raw source is not persisted or logged; sensitive keys, common AWS keys, bearer tokens, URL credentials, assignments, and private keys are redacted before model/report use. |
| Parser vulnerabilities | Medium | The custom HCL parser is not a complete Terraform language implementation and has not undergone independent fuzzing at scale. | Open residual risk; unsupported syntax becomes diagnostics or preserved expressions. |
| Oversized inputs | Medium | JSON request overhead and parser work can still consume memory up to configured limits. | Reduced: body, Terraform, evidence, model input/output, token, collection, nesting, and block limits are enforced. |
| Denial of service | Medium | Authentication and concurrency limits do not provide distributed rate limiting or per-client quotas. | Open residual risk for any deployment exposed beyond a trusted workstation. |
| Model cost abuse | Medium | Direct callers of `BedrockReviewService` can repeatedly invoke an approved model. | Reduced: bounded evidence, response bytes, and maximum tokens; API does not currently invoke Bedrock. Add account budgets, quotas, and per-tenant invocation limits before shared deployment. |
| Excessive IAM | Low | Context actions use `"Resource": "*"` where describe APIs require it. | Accepted with controls: only seven fixed `Describe*` calls are exposed; Bedrock role receives only `bedrock:InvokeModel` for an approved ARN. Keep context and Bedrock roles separate. |
| Model execution | Low | A model could recommend an action in prose. | Accepted: no tools are configured, no AWS credentials are exposed to the model, output cannot invoke code, and CloudGuard has no remediation executor. |

## Residual risks

### Prompt injection

Structured output and grounding reduce impact but cannot prove that every
interpretation is unbiased. Treat model implications, prioritization, and
tradeoffs as advisory. Deterministic findings remain authoritative.

### Secret detection

Redaction is key- and pattern-based. Organizations with custom credential
formats should add detectors and test fixtures. Do not submit real production
secret values where avoidable, even though raw source is not persisted.

### Parser assurance

The parser is intentionally non-executing and bounded, but it is custom code.
Add coverage-guided fuzzing, memory profiling, and a parser corpus before
processing untrusted internet-scale submissions.

### Local API boundary

The API is intended for `127.0.0.1`. Bearer authentication is not a substitute
for TLS, identity-aware authorization, distributed rate limiting, tenant
isolation, or audit controls. Do not bind it to a public interface.

### Persistence

SQLite is suitable for local use, not multi-tenant service isolation. Local
users or processes with the same operating-system identity can access review
state and the API key.

### Bedrock cost and governance

Before enabling Bedrock in a shared service, add persistent per-tenant quotas,
AWS Budgets alerts, invocation metrics, approved-model allowlists, and an
operator-controlled kill switch.

## Deployment requirements

- Bind the local API to `127.0.0.1`.
- Keep the API key out of shell history, logs, source control, and URLs.
- Use separate AWS roles for read-only context and Bedrock invocation.
- Do not attach infrastructure mutation permissions to either role.
- Use temporary AWS credentials.
- Monitor authentication failures, HTTP 429 responses, parser failures, and
  Bedrock token usage.
- Re-run this review before adding CloudFormation uploads, archives, multi-file
  projects, remote users, or automated remediation.

