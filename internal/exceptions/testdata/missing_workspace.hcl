exception "no-ws" {
  controls      = ["rds_db_instance_encryption_at_rest_enabled"]
  match         = "type == 'aws_db_instance' && resource.identifier != null"
  reason  = "Test"
  expires = "2027-01-01"
}
