resource "aws_s3_bucket" "broken" {
  bucket = "this string never ends
}

