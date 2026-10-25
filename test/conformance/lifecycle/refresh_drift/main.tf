terraform {
  required_providers {
    fake = { source = "registry.compliance.tf/compliancetf/aws" }
  }
}

# terraform.tfstate holds size 99, which violates fake_thing_size_max.
resource "fake_thing" "a" {
  name = "bobthecorp-a"
  size = 99
}
