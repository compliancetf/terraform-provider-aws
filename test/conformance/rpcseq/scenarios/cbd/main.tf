terraform {
  required_providers {
    fake = {
      source = "registry.compliance.tf/compliancetf/aws"
    }
  }
}

variable "name" {
  type    = string
  default = "bobthecorp-a"
}

# fake_replace requires replacement when name changes.
resource "fake_replace" "a" {
  name = var.name

  lifecycle {
    create_before_destroy = true
  }
}
