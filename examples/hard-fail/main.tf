# compliance.tf Terraform Provider - hard_fail example
#
# With enforcement_mode = "hard_fail", a violated deny control is an error
# and `terraform plan` fails. A violated warn control stays a warning.
#
# Prerequisites and usage: see examples/basic/main.tf.
#
# Expected output: `terraform plan` fails (exit 1) with
#   Error:   rds_db_instance_encryption_at_rest_enabled
#   Error:   rds_db_instance_prohibit_public_access
#   Error:   rds_db_instance_backup_retention_period_less_than_7
#   Error:   s3_bucket_restrict_public_read_access
#   Warning: rds_db_instance_deletion_protection_enabled
# plus the hashicorp/aws deprecation warning for acl. Each compliance
# diagnostic looks like this:
#
#   Error: [rds_db_instance_encryption_at_rest_enabled] RDS instances must have storage encryption enabled.
#
#     with aws_db_instance.non_compliant,
#     on main.tf line 53, in resource "aws_db_instance" "non_compliant":
#     53:   storage_encrypted       = false # deny
#
#   Fix: Set storage_encrypted = true.
#   Severity: critical
#   Mode: hard_fail
#   Stage: plan
#   Frameworks: cis_aws:2.3.1
#   To waive: add an exception for rds_db_instance_encryption_at_rest_enabled in
#   the exceptions_file
#
# An exceptions_file counts only with a signed org profile that enables
# self-service exceptions for the control: see examples/exception.

terraform {
  required_providers {
    aws = {
      source = "compliancetf/aws"
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
