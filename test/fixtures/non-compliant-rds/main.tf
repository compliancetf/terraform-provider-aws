terraform {
  required_providers {
    aws = { source = "compliancetf/aws" }
  }
}

provider "aws" {
  region = "us-east-1"
  # Offline: dummy keys, no STS or IMDS calls.
  access_key                  = "dogfood"
  secret_key                  = "dogfood"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  compliance {
    enforcement_mode = "hard_fail"
  }
}

# dogfood-blocks: rds_db_instance_encryption_at_rest_enabled
# dogfood-blocks: rds_db_instance_prohibit_public_access
# dogfood-blocks: rds_db_instance_backup_retention_period_less_than_7
resource "aws_db_instance" "bad" {
  engine                  = "postgres"
  instance_class          = "db.t3.micro"
  storage_encrypted       = false # violation: encryption required
  publicly_accessible     = true  # violation: must not be public
  backup_retention_period = 3     # violation: minimum 7 days
}
