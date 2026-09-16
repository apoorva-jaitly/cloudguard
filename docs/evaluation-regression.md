# CloudGuard Evaluation Regression Report

Generated from versioned local scenarios. No Terraform or AWS mutation is executed.

## Deterministic rule regression

- Scenarios: 30
- Passed: 30
- Failed: 0
- Pass rate: 100.0%

| Scenario | Expected | Actual | Result |
|---|---|---|---|
| public-rds | CG-SEC-001 | CG-SEC-001 | PASS |
| private-rds | none | none | PASS |
| single-az-rds | CG-REL-001 | CG-REL-001 | PASS |
| multi-az-placement | none | none | PASS |
| wildcard-iam | CG-SEC-003 | CG-SEC-003 | PASS |
| scoped-iam | none | none | PASS |
| missing-encryption | CG-SEC-004 | CG-SEC-004 | PASS |
| encryption-enabled | none | none | PASS |
| unrestricted-security-group | CG-SEC-002 | CG-SEC-002 | PASS |
| restricted-security-group | none | none | PASS |
| missing-backups | CG-REL-002 | CG-REL-002 | PASS |
| backups-enabled | none | none | PASS |
| missing-monitoring | CG-OPS-001 | CG-OPS-001 | PASS |
| monitoring-present | none | none | PASS |
| weak-scaling | CG-REL-005 | CG-REL-005 | PASS |
| scaling-present | none | none | PASS |
| risky-deployment | CG-OPS-002 | CG-OPS-002 | PASS |
| safe-deployment | none | none | PASS |
| expensive-network | CG-COST-001 | CG-COST-001 | PASS |
| no-nat-gateway | none | none | PASS |
| missing-log-retention | CG-OPS-003 | CG-OPS-003 | PASS |
| log-retention-present | none | none | PASS |
| missing-health-check | CG-REL-004 | CG-REL-004 | PASS |
| health-check-present | none | none | PASS |
| plaintext-secret | CG-SEC-005 | CG-SEC-005 | PASS |
| secret-reference | none | none | PASS |
| database-multi-az-disabled | CG-REL-003 | CG-REL-003 | PASS |
| database-multi-az-enabled | none | none | PASS |
| always-on-compute | CG-COST-002 | CG-COST-002 | PASS |
| scheduled-compute | none | none | PASS |

## Bedrock review-output regression

| Case | Schema | Grounding | Citations | Severity | Recommendations | Unsupported |
|---|---:|---:|---:|---:|---:|---:|
| grounded synthetic reference | PASS | 100.0% | 100.0% | 100.0% | 100.0% | 0 |
| adversarial unsupported claims | FAIL | 0.0% | 83.3% | 0.0% | 100.0% | 4 |

The grounded reference case is a synthetic contract fixture, not a claim about a particular foundation model. The adversarial case confirms unsupported IDs and uncited configuration claims are detected.

## Live Bedrock status

Not run. Model-specific quality and latency baselines require an explicitly approved model ID, AWS credentials, region, and cost authorization. The same grader can score captured JSON output without granting the model AWS access.

## Regression policy

- Deterministic scenarios must remain at 100%.
- Accepted model output must pass the strict Review schema.
- Accepted model output must have 100% evidence citation and zero unsupported claims.
- Severity and recommendation scores are tracked by model ID and prompt version.
