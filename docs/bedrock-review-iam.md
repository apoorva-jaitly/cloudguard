# Amazon Bedrock review-layer IAM permissions

The review layer calls only the non-streaming Amazon Bedrock Runtime `Converse`
API. It does not configure tools, agents, action groups, AWS SDK tools, or
infrastructure operations.

Grant the runtime role only model invocation permission for the approved model
or inference profile:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InvokeApprovedCloudGuardReviewModel",
      "Effect": "Allow",
      "Action": "bedrock:InvokeModel",
      "Resource": "APPROVED_MODEL_OR_INFERENCE_PROFILE_ARN"
    }
  ]
}
```

Do not attach infrastructure write permissions to this role. In particular, it
does not need IAM, CloudFormation, EC2, RDS, ECS, Lambda, S3, Systems Manager,
or Organizations mutation permissions.

The application sends only the bounded, redacted `EvidencePackage`. It uses
Bedrock structured output through `Converse.outputConfig.textFormat`, then
performs a second application-side validation pass. Model output cannot add or
modify deterministic findings; it can only prioritize finding IDs already
present in the evidence package.

Application controls also cap input bytes, output bytes, and generated tokens.
Factual claims require an evidence ID, a known resource ID, and an excerpt that
exists verbatim in the cited evidence. Use AWS Budgets, service quotas, and
account-level monitoring as additional cost controls for deployed environments.

