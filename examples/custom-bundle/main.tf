# compliance.tf provider for AWS - custom bundle example
#
# A signed team bundle (bundle-src/) loaded next to the embedded CIS bundle
# with control_bundle_path. See README.md for how to build and run it.

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
    enforcement_mode    = "hard_fail"
    control_bundle_path = "${path.module}/team-controls.tar.gz"
  }
}

resource "aws_db_instance" "example" {
  engine                  = "postgres"
  instance_class          = "db.t3.micro"
  storage_encrypted       = true
  publicly_accessible     = false
  backup_retention_period = 14
  deletion_protection     = true
  multi_az                = false # deny: bobthecorp_rds_multi_az_enabled
}

resource "aws_s3_bucket" "example" {
  bucket        = "bobthecorp-team-data"
  force_destroy = true # warn: bobthecorp_s3_bucket_force_destroy_disabled
}
