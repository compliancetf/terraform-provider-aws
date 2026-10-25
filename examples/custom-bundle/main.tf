# compliance.tf Terraform Provider - custom bundle example
#
# control_bundle_path loads a signed bundle 2.0 archive (for example in an
# air-gapped run) next to the embedded CIS bundle. bundle-src/ holds the
# source of a two-control team bundle:
#   bobthecorp_rds_multi_az_enabled              deny  aws_db_instance.multi_az
#   bobthecorp_s3_bucket_force_destroy_disabled  warn  aws_s3_bucket.force_destroy
#
# Prerequisites: see examples/basic/main.tf. Then build the archive from
# the repo root; ctfbundle build signs it with -key. A development build
# (make build-dev) trusts the test key; a release build accepts only
# archives signed by compliance.tf.
#   go run -tags ctftest ./cmd/ctfbundle build -src examples/custom-bundle/bundle-src \
#     -key test:bundle -out examples/custom-bundle/team-controls.tar.gz
# In bundle-src/manifest.json, provider.address is the released provider
# address, and the zero schema_compat_digest and the catalog snapshot_id are
# placeholders for this example; compliance.tf fills them in for bundles it
# issues.
#
# Usage (skip terraform init under dev_overrides):
#   terraform plan
#
# Expected output: `terraform plan` fails (exit 1) with
#   Error:   bobthecorp_rds_multi_az_enabled
#   Warning: bobthecorp_s3_bucket_force_destroy_disabled
# The resources pass every embedded CIS control.

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
