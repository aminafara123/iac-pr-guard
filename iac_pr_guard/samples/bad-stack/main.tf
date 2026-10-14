# Intentionally INSECURE sample stack. Used to demonstrate iac-pr-guard findings.
# Do not deploy this.

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "data" {
  bucket = "amin-demo-public-data"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "allows the world in"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "admin" {
  name = "too-broad"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
POLICY
}

resource "aws_ebs_volume" "vol" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = false
}

resource "aws_db_instance" "db" {
  allocated_storage   = 20
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  username            = "admin"
  storage_encrypted   = false
  publicly_accessible = true
}
