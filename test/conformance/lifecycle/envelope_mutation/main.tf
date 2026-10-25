terraform {
  required_providers {
    fake = { source = "registry.compliance.tf/compliancetf/aws" }
  }
}

# terraform.tfstate seeds s; n is the planned create whose id stays unknown
# until upstream applies it, so apply_pre blocks it under hard_fail.
resource "fake_thing" "s" {
  name = "bobthecorp-s"
}

resource "fake_thing" "n" {
  name = "bobthecorp-n"
}
