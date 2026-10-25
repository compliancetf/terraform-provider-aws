terraform {
  required_providers {
    aws = {
      source = "registry.compliance.tf/compliancetf/aws"
    }
  }
}

# Region and credentials come from the environment (OIDC in nightly.yml).
provider "aws" {
  default_tags {
    tags = {
      "ctf-conformance" = "@PREFIX@"
    }
  }
}

variable "value" {
  type    = string
  default = "v1"
}

resource "aws_ssm_parameter" "a" {
  name  = "@PREFIX@-a"
  type  = "String"
  value = var.value
}
