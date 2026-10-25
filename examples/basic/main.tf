# compliance.tf Terraform Provider - basic example (happy path)
#
# A fully compliant RDS instance. `terraform plan` shows no compliance
# errors or warnings.
#
# Prerequisites (DEVELOPING.md, "Manual testing with Terraform"):
#   1. make build-dev
#   2. export TF_CLI_CONFIG_FILE=<CLI config with dev_overrides for
#      registry.terraform.io/compliancetf/aws pointing at the repo root>
#   3. export CTFTEST_UPSTREAM_PATH=<hashicorp/aws 6.x provider binary>
#   4. AWS credentials, as for hashicorp/aws. Plan creates nothing.
#
# Usage (skip terraform init under dev_overrides):
#   terraform plan

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

# Passes every embedded CIS control for aws_db_instance:
#   rds_db_instance_encryption_at_rest_enabled           storage_encrypted = true
#   rds_db_instance_prohibit_public_access               publicly_accessible = false
#   rds_db_instance_backup_retention_period_less_than_7  backup_retention_period >= 7
#   rds_db_instance_deletion_protection_enabled          deletion_protection = true
resource "aws_db_instance" "compliant" {
  engine                  = "postgres"
  instance_class          = "db.t3.micro"
  storage_encrypted       = true
  publicly_accessible     = false
  backup_retention_period = 14
  deletion_protection     = true
}
