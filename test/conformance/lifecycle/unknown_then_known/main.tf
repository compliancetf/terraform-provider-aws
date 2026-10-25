terraform {
  required_providers {
    fake = { source = "registry.compliance.tf/compliancetf/aws" }
  }
}

resource "fake_thing" "a" {
  name = "src"
}

# b.name is unknown until a is created, then ends in -bad. Terraform re-plans
# b during apply with the known name, so the block comes from that plan call;
# envelope_mutation covers a block at apply_pre.
resource "fake_thing" "b" {
  name = "${fake_thing.a.id}-bad"
}
