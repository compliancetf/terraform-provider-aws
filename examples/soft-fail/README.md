# soft-fail

The non-compliant resources of [hard-fail](../hard-fail) in `soft_fail` mode, the default. Every violation is a warning, and `terraform plan` succeeds. Use this mode while onboarding an existing configuration, then switch to `hard_fail`.

## Run it

You need Terraform 1.5 or later (or OpenTofu) and AWS credentials. The plan creates nothing.

```bash
cd examples/soft-fail
terraform init
terraform plan
```

## What to expect

`terraform plan` exits 0 with these warnings, each marked `Mode: soft_fail`:

| Resource | Control | Action |
|---|---|---|
| `aws_db_instance.non_compliant` | `rds_db_instance_encryption_at_rest_enabled` | deny |
| `aws_db_instance.non_compliant` | `rds_db_instance_prohibit_public_access` | deny |
| `aws_db_instance.non_compliant` | `rds_db_instance_backup_retention_period_less_than_7` | deny |
| `aws_db_instance.non_compliant` | `rds_db_instance_deletion_protection_enabled` | warn |
| `aws_s3_bucket.non_compliant` | `s3_bucket_restrict_public_read_access` | deny |

The plan also shows the `hashicorp/aws` deprecation warning for `acl`.

In `hard_fail` mode the four `deny` violations would be errors; the `warn` violation stays a warning in every mode.

`COMPLIANCETF_ENFORCEMENT_MODE=hard_fail` raises the mode without editing the file, because the stricter setting wins.
