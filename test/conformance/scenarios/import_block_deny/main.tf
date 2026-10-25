terraform {
  required_providers {
    fake = {
      source = "registry.compliance.tf/compliancetf/aws"
    }
  }
}

import {
  to = fake_thing.a
  id = "bobthecorp-imported"
}

# The fake upstream imports id X as {id = X, name = X, size = 1}; size 2
# makes the import plan an in-place update, so apply runs.
resource "fake_thing" "a" {
  name = "bobthecorp-imported"
  size = 2
}
