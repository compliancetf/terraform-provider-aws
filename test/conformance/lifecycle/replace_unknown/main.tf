terraform {
  required_providers {
    fake = { source = "registry.compliance.tf/compliancetf/aws" }
  }
}

variable "name" {
  type    = string
  default = "bobthecorp-old"
}

# A new name replaces r; its id is unknown until the create half runs.
resource "fake_replace" "r" {
  name = var.name
}
