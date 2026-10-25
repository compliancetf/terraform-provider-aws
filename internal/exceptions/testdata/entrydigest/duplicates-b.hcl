exception "duplicates" {
  controls     = ["s3_bucket_logging_enabled", "s3_bucket_logging_enabled", "CKV_AWS_18"]
  match        = "type == 'aws_s3_bucket'"
  workspace    = "bobthecorp-reporting-prod"
  environments = []
  reason       = "An empty environments list equals an absent one"
  expires      = "2027-06-30"
}
