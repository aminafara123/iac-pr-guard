# Hardened sample stack. iac-pr-guard reports zero findings against this.

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "data" {
  bucket = "amin-demo-private-data"
  acl    = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }

  versioning {
    enabled = true
  }
}

resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "https from the internal network only"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_iam_policy" "scoped" {
  name = "scoped-read"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::amin-demo-private-data/*"
    }
  ]
}
POLICY
}

resource "aws_ebs_volume" "vol" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = true
}

resource "aws_db_instance" "db" {
  allocated_storage   = 20
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  username            = "admin"
  storage_encrypted   = true
  publicly_accessible = false
}

resource "aws_cloudtrail" "main" {
  name           = "org-trail"
  s3_bucket_name = "amin-demo-private-data"
}
