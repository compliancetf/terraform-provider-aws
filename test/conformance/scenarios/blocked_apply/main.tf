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

# terraform.tfstate seeds fake_thing.a with SDKv2-style private data: the
# scenario's deny:fake_thing evaluator would block the create that writes it.
resource "fake_thing" "a" {
  name = "bobthecorp-a"
  size = var.size
}
