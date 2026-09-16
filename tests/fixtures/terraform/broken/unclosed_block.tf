resource "aws_s3_bucket" "broken" {
  bucket = "broken-bucket"
  tags = {
    Environment = "test"

