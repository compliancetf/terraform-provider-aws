# ListResource is passthrough: the fake upstream yields <prefix>-1 and <prefix>-2.
list "fake_thing" "all" {
  provider = fake
  config {
    prefix = "bobthecorp"
  }
}
