# compliance.tf provider for AWS - basic example
#
# A fully compliant RDS instance: `terraform plan` shows no compliance
# error or warning. See README.md for how to run it.

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
