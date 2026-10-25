# hard-fail

An RDS instance and an S3 bucket that break CIS controls, in `hard_fail` mode. A violated `deny` control is an error and stops the plan; a violated `warn` control stays a warning.

## Run it

You need Terraform 1.5 or later (or OpenTofu) and AWS credentials. The plan creates nothing.

```bash
cd examples/hard-fail
terraform init
terraform plan
```

## What to expect

`terraform plan` exits 1 with:

| Severity | Resource | Control |
|---|---|---|
| Error | `aws_db_instance.non_compliant` | `rds_db_instance_encryption_at_rest_enabled` |
| Error | `aws_db_instance.non_compliant` | `rds_db_instance_prohibit_public_access` |
| Error | `aws_db_instance.non_compliant` | `rds_db_instance_backup_retention_period_less_than_7` |
| Error | `aws_s3_bucket.non_compliant` | `s3_bucket_restrict_public_read_access` |
| Warning | `aws_db_instance.non_compliant` | `rds_db_instance_deletion_protection_enabled` |

The plan also shows the `hashicorp/aws` deprecation warning for `acl`. Each compliance diagnostic points at the line to change:

```
Error: [rds_db_instance_encryption_at_rest_enabled] RDS instances must have storage encryption enabled.

  with aws_db_instance.non_compliant,
  on main.tf line 25, in resource "aws_db_instance" "non_compliant":
  25:   storage_encrypted       = false # deny

Fix: Set storage_encrypted = true.
Docs: https://compliance.tf/docs/controls/aws/rds_db_instance_encryption_at_rest_enabled/
```

`COMPLIANCETF_DIAGNOSTICS=full` adds the severity, mode, stage and framework references. A `To waive:` line appears only when an `exceptions_file` entry can waive the control, which needs a signed org profile: see [exception](../exception) and [Diagnostics](../../docs/reference.md#diagnostics).

## Next steps

- Fix the settings, as in [basic](../basic) or [cis-complete](../cis-complete).
- Or waive a violation with an exception, which needs a signed org profile. See [exception](../exception).
