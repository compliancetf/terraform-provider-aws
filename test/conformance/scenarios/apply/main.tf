terraform {
  required_providers {
    # fake_* resource types map to the local name "fake"; the proxy serves them.
    fake = {
      source = "registry.compliance.tf/compliancetf/aws"
    }
  }
}

variable "size" {
  type    = number
  default = 1
}

resource "fake_thing" "a" {
  name = "bobthecorp-a"
  size = var.size
}
