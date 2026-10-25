exception "pg-encryption" {
  controls      = ["rds_db_instance_encryption_at_rest_enabled", "rds_instance_kms_key_configured"]
  match         = "type == 'aws_db_instance' && resource.deletion_protection == true"
  workspace = "bobthecorp-reporting-prod"
  reason    = "Encrypted copy in progress, OPS-4411"
  expires   = "2027-01-01"
}
