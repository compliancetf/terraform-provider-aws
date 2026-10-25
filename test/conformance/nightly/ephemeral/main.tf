terraform {
  required_providers {
    aws = {
      source = "registry.compliance.tf/compliancetf/aws"
    }
  }
}

provider "aws" {
  default_tags {
    tags = {
      "ctf-conformance" = "@PREFIX@"
    }
  }
}

# GetRandomPassword creates nothing; the value only reaches the write-only
# argument and is never stored in plan or state.
ephemeral "aws_secretsmanager_random_password" "p" {
  password_length     = 16
  exclude_punctuation = true
}

resource "aws_ssm_parameter" "a" {
  name             = "@PREFIX@-a"
  type             = "String"
  value_wo         = ephemeral.aws_secretsmanager_random_password.p.random_password
  value_wo_version = 1
}
