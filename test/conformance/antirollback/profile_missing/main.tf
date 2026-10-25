terraform {
  required_providers {
    fake = { source = "registry.compliance.tf/compliancetf/aws" }
  }
}

# Governed by env with no profile candidate: floor_mode is online (spec), and
# an offline run fails closed at the floor before any profile is selected.
resource "fake_thing" "a" {
  name = "bobthecorp-a"
}
