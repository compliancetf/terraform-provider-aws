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

# dogfood-blocks: s3_bucket_restrict_public_read_access
resource "aws_s3_bucket" "public" {
  bucket = "my-public-bucket"
  acl    = "public-read" # violation: public ACL
}
