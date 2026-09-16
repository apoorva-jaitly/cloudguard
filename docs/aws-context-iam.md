# AWS context provider IAM permissions

CloudGuard's AWS context provider uses a fixed allowlist of read-only
`Describe*` API operations. It does not expose a generic boto3 operation
interface and contains no create, update, delete, start, stop, invoke, or
deployment calls.

## Required permissions

Grant only the permissions needed for the resource types included in a review:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudGuardReadOnlyContext",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVolumes",
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",
        "logs:DescribeLogGroups",
        "ecs:DescribeServices"
      ],
      "Resource": "*"
    }
  ]
}
```

These EC2, RDS, CloudWatch Logs, and ECS APIs are describe operations documented
by AWS. Some describe actions require `"Resource": "*"` because they do not
support resource-level IAM permissions.

## Credential model

Use temporary role credentials in deployed environments. The provider relies
on boto3's normal credential chain and does not store or log credentials.
Cross-account deployments should use a dedicated role with a constrained trust
policy and external ID.

## Failure semantics

- Missing credentials, denied permissions, endpoint failures, and SDK errors
  produce diagnostics.
- A successful API response with no matching resource produces a
  `resource_not_observed` diagnostic.
- Neither case produces a fact asserting that the resource or configuration is
  absent.
- Facts include the AWS API source, configured region, and UTC observation time.

## AWS API references

- EC2 `DescribeInstances`, `DescribeSecurityGroups`, and `DescribeVolumes`
- RDS `DescribeDBInstances` and `DescribeDBClusters`
- CloudWatch Logs `DescribeLogGroups`
- ECS `DescribeServices`

See the corresponding AWS API Reference documentation before changing the
allowlist or IAM policy.

