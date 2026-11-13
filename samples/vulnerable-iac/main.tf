# TEST ONLY: intentionally insecure; never deploy.
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

resource "aws_s3_bucket" "insecure" {
  bucket = "devsecops-test-only-insecure-example"
}

resource "aws_s3_bucket_acl" "insecure" {
  bucket = aws_s3_bucket.insecure.id
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "insecure" {
  bucket                  = aws_s3_bucket.insecure.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_security_group" "insecure" {
  name = "test-only-open-ingress"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
