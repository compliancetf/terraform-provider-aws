floor {
  epoch = "9"
}

exception "legacy-reporting-db" {
  match         = "type == 'aws_db_instance'"
  controls      = ["rds_db_instance_encryption_at_rest_enabled"]
  workspace     = "bobthecorp-reporting-prod"
  reason        = "Migration ticket OPS-4411"
  expires       = "2027-03-31"
}
