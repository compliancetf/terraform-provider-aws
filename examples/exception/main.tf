# compliance.tf provider for AWS - self-service exception example
#
# Each resource below breaks a CIS deny control that exceptions.hcl waives,
# so `terraform plan` succeeds in hard_fail mode. See README.md for the
# signed profile this needs, how to run it and what to expect.

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
    org_id           = "bobthecorp"
    environment      = "dev"
    profile_path     = "${path.module}/profile.dsse.json" # signed profile.json
    exceptions_file  = "${path.module}/exceptions.hcl"
  }
}

# Waived by "dev-db-unencrypted": the identifier starts with dev-.
resource "aws_db_instance" "dev_db" {
  identifier              = "dev-reporting"
  engine                  = "postgres"
  instance_class          = "db.t4g.micro"
  storage_encrypted       = false # rds_db_instance_encryption_at_rest_enabled, waived
  publicly_accessible     = false
  backup_retention_period = 14
  deletion_protection     = true
}

# Two controls waived by one entry, "reporting-replica-restore". The
# identifier also starts with dev-, so "dev-db-unencrypted" matches its
# encryption control too; either entry is enough.
resource "aws_db_instance" "restore" {
  identifier              = "dev-reporting-restore"
  engine                  = "postgres"
  instance_class          = "db.t4g.micro"
  storage_encrypted       = false # rds_db_instance_encryption_at_rest_enabled, waived
  backup_retention_period = 1     # rds_db_instance_backup_retention_period_less_than_7, waived
  publicly_accessible     = false
  deletion_protection     = true
}

# Waived by "migration-target-backups" while it is created. Once it exists,
# an update that keeps backup_retention_period below 7 fails the plan.
resource "aws_db_instance" "migration_target" {
  identifier              = "dev-migration-target"
  engine                  = "postgres"
  instance_class          = "db.t4g.micro"
  storage_encrypted       = true
  backup_retention_period = 0 # rds_db_instance_backup_retention_period_less_than_7, waived on create
  publicly_accessible     = false
  deletion_protection     = true
}

# Waived by "scratch-volumes" through its purpose tag. "staging-only" and
# "old-load-test" also select it, but neither applies (wrong environment,
# expired).
resource "aws_ebs_volume" "scratch" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false # ebs_attached_volume_encryption_enabled, waived

  tags = { purpose = "scratch" }
}

# Waived by "public-docs-site": bucket name prefix and provider region.
resource "aws_s3_bucket" "docs" {
  bucket = "bobthecorp-docs-site"
  acl    = "public-read" # s3_bucket_restrict_public_read_access, waived
}
