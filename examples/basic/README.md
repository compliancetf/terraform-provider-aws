# basic

A fully compliant RDS instance in `hard_fail` mode. Use it to check your setup: the plan shows no compliance errors or warnings.

## Run it

You need Terraform 1.5 or later (or OpenTofu) and AWS credentials, as for `hashicorp/aws`. The plan reads from AWS and creates nothing.

```bash
cd examples/basic
terraform init
terraform plan
```

## What to expect

`terraform plan` exits 0 and plans one `aws_db_instance`. No compliance diagnostics appear.

| Setting | Control |
|---|---|
| `storage_encrypted = true` | `rds_db_instance_encryption_at_rest_enabled` |
| `publicly_accessible = false` | `rds_db_instance_prohibit_public_access` |
| `backup_retention_period = 14` (7 or more) | `rds_db_instance_backup_retention_period_less_than_7` |
| `deletion_protection = true` | `rds_db_instance_deletion_protection_enabled` |

Change any of them to see the check. For example, `storage_encrypted = false` makes the plan fail with `rds_db_instance_encryption_at_rest_enabled`.

Each check is also written to `.terraform/compliancetf/evidence/`.
