terraform {
  required_providers {
    fake = {
      source = "registry.compliance.tf/compliancetf/aws"
    }
  }
}

# OpenEphemeralResource is intercepted; the result is never decoded or stored.
ephemeral "fake_secret" "s" {
  name = "bobthecorp"
}

resource "fake_thing" "a" {
  name = "bobthecorp-a"
}
