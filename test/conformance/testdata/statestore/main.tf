terraform {
  required_providers {
    fake = { source = "bobthecorp/fake" }
  }
  state_store "fake_store" {
    provider "fake" {}
  }
}
