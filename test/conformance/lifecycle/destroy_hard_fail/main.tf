terraform {
  required_providers {
    fake = { source = "registry.compliance.tf/compliancetf/aws" }
  }
}

# The fake upstream applies size 11 for a drift- name, so a holds a size that
# violates fake_thing_size_max when destroy runs.
resource "fake_thing" "a" {
  name = "drift-a"
  size = 10
}
