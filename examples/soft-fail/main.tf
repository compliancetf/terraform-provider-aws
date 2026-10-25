# compliance.tf Terraform Provider - soft_fail example
#
# soft_fail is the default mode: every violation, deny or warn, is a
# warning and `terraform plan` succeeds. Use it while onboarding existing
# configurations, then raise the mode to hard_fail.
#
# Prerequisites and usage: see examples/basic/main.tf.
#
# Expected output: `terraform plan` succeeds (exit 0) and warns for
#   rds_db_instance_encryption_at_rest_enabled
#   rds_db_instance_prohibit_public_access
#   rds_db_instance_backup_retention_period_less_than_7
#   rds_db_instance_deletion_protection_enabled
#   s3_bucket_restrict_public_read_access
# plus the hashicorp/aws deprecation warning for acl. Each warning carries
# "Mode: soft_fail".

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
    enforcement_mode = "soft_fail"
  }
}

# The same resources as the hard_fail example.

resource "aws_db_instance" "non_compliant" {
  engine                  = "mysql"
  instance_class          = "db.t3.micro"
  storage_encrypted       = false # deny: an error in hard_fail, a warning here
  publicly_accessible     = true  # deny: an error in hard_fail, a warning here
  backup_retention_period = 3     # deny: an error in hard_fail, a warning here
  deletion_protection     = false # warn: a warning in both modes
}

resource "aws_s3_bucket" "non_compliant" {
  bucket = "bobthecorp-public-bucket"
  acl    = "public-read" # deny: an error in hard_fail, a warning here
}
