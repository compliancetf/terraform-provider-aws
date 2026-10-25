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

# dogfood-blocks: vpc_security_group_remote_administration_ipv4
resource "aws_security_group" "open_ssh" {
  name = "open-ssh"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # violation: SSH open to the world
  }
}
