resource "aws_s3_bucket" "test_insecure" {
  bucket = "test-insecure-bucket-baru"
}

resource "aws_s3_bucket_acl" "test_insecure_acl" {
  bucket = aws_s3_bucket.test_insecure.id
  acl    = "public-read"
}