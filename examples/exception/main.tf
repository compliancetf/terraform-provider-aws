# compliance.tf Terraform Provider - self-service exception example
#
# The RDS instance violates rds_db_instance_encryption_at_rest_enabled. The
# signed org profile for org bobthecorp allows self-service exceptions for
# that control, and exceptions.hcl waives it for dev-* instances in the
# bobthecorp-dev workspace, so `terraform plan` succeeds in hard_fail.
# Without a signed profile that enables self-service exceptions, the
# exceptions file is ignored with a warning and the plan fails with the
# encryption error.
#
# Prerequisites: see examples/basic/main.tf. In practice compliance.tf
# issues the signed org profile. To try this with a development build
# (make build-dev, which trusts the test key), set issued_at in profile.json
# to today and expires_at at most 30 days later, then sign it from the repo
# root:
#   go run -tags ctftest ./cmd/ctfbundle sign -type profile \
#     -in examples/exception/profile.json -key test:profile \
#     -out examples/exception/profile.dsse.json
# The expires date in exceptions.hcl must be in the future and within
# max_lifetime_days (profile.json) of the run date: update it together with
# the profile dates.
#
# Usage (skip terraform init under dev_overrides):
#   terraform plan
#
# Expected output: `terraform plan` succeeds (exit 0) with no compliance
# error. The waiver is recorded in the evidence chain under evidence_dir.

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
    org_id           = "bobthecorp"
    environment      = "dev"
    profile_path     = "${path.module}/profile.dsse.json"
    exceptions_file  = "${path.module}/exceptions.hcl"
  }
}

resource "aws_db_instance" "dev_db" {
  identifier              = "dev-reporting"
  engine                  = "postgres"
  instance_class          = "db.t3.micro"
  storage_encrypted       = false # violation, waived by exceptions.hcl
  publicly_accessible     = false
  backup_retention_period = 14
  deletion_protection     = true
}
