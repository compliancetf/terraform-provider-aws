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

resource "aws_db_instance" "compliant" {
  engine                  = "postgres"
  instance_class          = "db.t3.micro"
  storage_encrypted       = true
  publicly_accessible     = false
  backup_retention_period = 14
  deletion_protection     = true
}
