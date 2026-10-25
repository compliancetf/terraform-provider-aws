exception "unicode-selector" {
  controls  = ["s3_bucket_logging_enabled"]
  match     = "type == 'aws_s3_bucket' && resource.tags['owner'] == 'Böb \U0001F600' && resource.bucket != '\"<>&\t'"
  workspace = "bobthecorp-reporting-prod"
  reason    = "Non-ASCII and escapes in the selector"
  expires   = "2027-06-30"
}
