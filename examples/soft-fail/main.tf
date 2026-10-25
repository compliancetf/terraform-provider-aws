# compliance.tf provider for AWS - soft_fail example
#
# The resources of the hard-fail example in soft_fail mode: every violation
# is a warning and `terraform plan` succeeds. See README.md.

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
