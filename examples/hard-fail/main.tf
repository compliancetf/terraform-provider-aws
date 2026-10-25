# compliance.tf provider for AWS - hard_fail example
#
# A violated deny control is an error and `terraform plan` fails; a violated
# warn control stays a warning. See README.md for the expected output.

terraform {
  required_providers {
    aws = {
      source = "registry.compliance.tf/compliancetf/aws"
    }
  }
}

provider "aws" {
  region = "us-east-1"

  compliance {
    enforcement_mode = "hard_fail"
  }
}

resource "aws_db_instance" "non_compliant" {
  engine                  = "mysql"
  instance_class          = "db.t3.micro"
  storage_encrypted       = false # deny
  publicly_accessible     = true  # deny
  backup_retention_period = 3     # deny, minimum is 7
  deletion_protection     = false # warn
}

resource "aws_s3_bucket" "non_compliant" {
  bucket = "bobthecorp-public-bucket"
  acl    = "public-read" # deny
}
