terraform {
  required_providers {
    fake = {
      source = "registry.compliance.tf/compliancetf/aws"
    }
  }
}

# The proxy passes the upstream's server_capabilities through (pinned in
# testdata/capabilities.json) and forwards the action RPCs raw.
action "fake_poke" "p" {
  config {
    target = "bobthecorp"
  }
}

resource "fake_thing" "a" {
  name = "bobthecorp-a"
}
