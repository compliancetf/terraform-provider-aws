terraform {
  required_providers {
    fake = {
      source = "registry.compliance.tf/compliancetf/aws"
    }
  }
}

# The fake upstream imports id X as {id = X, name = X, size = 1}.
resource "fake_thing" "a" {
  name = "bobthecorp-imported"
}
