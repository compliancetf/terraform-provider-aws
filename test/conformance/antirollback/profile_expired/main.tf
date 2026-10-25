terraform {
  required_providers {
    fake = { source = "registry.compliance.tf/compliancetf/aws" }
  }
}

resource "fake_thing" "a" {
  name = "bobthecorp-a"
}
