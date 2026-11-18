# Secure Terraform S3 example (comparison only)
# Review naming, provider versions, IAM permissions and policies before deployment.
# No GitHub Actions workflow in this repository applies Terraform.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "secure_demo" {
  bucket_prefix = "devsecops-secure-demo-"
}

resource "aws_s3_bucket_public_access_block" "secure_demo" {
  bucket = aws_s3_bucket.secure_demo.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_demo" {
  bucket = aws_s3_bucket.secure_demo.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "secure_demo" {
  bucket = aws_s3_bucket.secure_demo.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_ownership_controls" "secure_demo" {
  bucket = aws_s3_bucket.secure_demo.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}
