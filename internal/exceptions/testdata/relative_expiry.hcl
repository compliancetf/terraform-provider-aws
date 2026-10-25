exception "legacy-reporting-db" {
  controls      = ["rds_db_instance_encryption_at_rest_enabled"]
  match         = "type == 'aws_db_instance' && resource.identifier.matches('^legacy-')"
  workspace    = "bobthecorp-reporting-prod"
  environments = ["prod"]
  reason       = "Migration ticket OPS-4411"
  ticket       = "OPS-4411"
  expires      = "P90D"
}
