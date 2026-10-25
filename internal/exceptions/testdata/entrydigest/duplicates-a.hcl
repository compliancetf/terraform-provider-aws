exception "duplicates" {
  controls  = ["s3_bucket_logging_enabled", "CKV_AWS_18", "s3_bucket_logging_enabled"]
  match     = "type == 'aws_s3_bucket'"
  workspace = "bobthecorp-reporting-prod"
  reason    = "Duplicate control refs are kept and sorted"
  expires   = "2027-06-30"
}
