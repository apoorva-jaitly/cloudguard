terraform {
  required_version = ">= 1.5.0"
}

module "network" {
  source  = "./modules/network"
  version = "1.2.3"
}

resource "aws_iam_role" "writer" {
  name = "production-writer"
  tags = {
    Environment = "production"
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "example-production-logs"
  tags = {
    Environment = "production"
    Owner       = "platform"
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id

  policy = jsonencode({
    Statement = [{
      Principal = {
        AWS = aws_iam_role.writer.arn
      }
    }]
  })

  depends_on = [
    aws_s3_bucket.logs,
    aws_iam_role.writer,
  ]
}

