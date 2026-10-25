exception "wrong_workspace" {
  controls      = ["rds_db_instance_encryption_at_rest_enabled"]
  match         = "type == 'aws_db_instance' && resource.identifier != null"
  workspace    = "bobthecorp-other"
  environments = []
  reason       = "Test"
  expires      = "2027-01-01"
}
