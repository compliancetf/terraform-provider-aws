terraform {
  required_providers {
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
