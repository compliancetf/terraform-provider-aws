# cis-complete

Every resource type the embedded CIS bundle checks, configured to pass every control, in `hard_fail` mode. Each checked setting in `main.tf` has a comment with the control id and its CIS AWS reference. Use it as a reference for compliant settings, or as a template.

## Run it

You need Terraform 1.5 or later (or OpenTofu) and AWS credentials that can read the account (`sts:GetCallerIdentity`, `ec2:DescribeAvailabilityZones`).

```bash
cd examples/cis-complete
terraform init
terraform plan
```

Plan only. `terraform apply` would create a VPC, databases, a Redshift cluster, an ElastiCache group, a load balancer and more: billable resources, some of which take a long time to create. The RDS instance and cluster have `deletion_protection = true`, so `terraform destroy` fails until you set it to `false` and apply.

## What to expect

`terraform plan` exits 0, plans 23 resources, and shows no compliance errors or warnings. Every control of the embedded bundle runs and passes:

| Resource type | Controls |
|---|---|
| `aws_db_instance` | `rds_db_instance_encryption_at_rest_enabled`, `rds_db_instance_prohibit_public_access`, `rds_db_instance_backup_retention_period_less_than_7`, `rds_db_instance_deletion_protection_enabled` |
| `aws_rds_cluster` | `rds_db_cluster_encryption_at_rest_enabled`, `rds_db_instance_backup_retention_period_less_than_7`, `rds_db_cluster_deletion_protection_enabled` |
| `aws_redshift_cluster` | `redshift_cluster_kms_enabled`, `redshift_cluster_prohibit_public_access` |
| `aws_elasticache_replication_group` | `elasticache_replication_group_encryption_at_rest_enabled`, `elasticache_replication_group_encryption_in_transit_enabled` |
| `aws_ebs_volume` | `ebs_volume_encryption_at_rest_enabled` |
| `aws_efs_file_system` | `efs_file_system_encrypt_data_at_rest`, `efs_file_system_encrypted_with_cmk` |
| `aws_s3_bucket` | `s3_bucket_restrict_public_read_access`, `s3_bucket_restrict_public_write_access` |
| `aws_lb_listener` | `elb_application_network_listener_uses_secure_protocol` |
| `aws_security_group`, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule` | `vpc_security_group_remote_administration_ipv4`, `vpc_security_group_remote_administration_ipv6` |

To confirm they ran, look at the evidence records in `.terraform/compliancetf/evidence/`. Each `eval` line lists the controls checked for one resource, with `"state": "pass"`.

Break a setting to see a control fail. For example:
- `storage_encrypted = false` on the RDS instance;
- `cidr_ipv4 = "0.0.0.0/0"` on an SSH rule;
- `protocol = "HTTP"` on the listener.

## Notes

- **Values known at plan.** Controls read these values at plan, so the CIDR blocks are literals. The EFS key is given by its alias ARN, built from data sources. A value known only after apply, such as `aws_vpc.this.ipv6_cidr_block` or `aws_kms_key.efs.arn`, gives a `pending` warning at plan, and the control is checked again before apply.
- **Strings in hashicorp/aws 6.x.** `encrypted` on `aws_redshift_cluster` and `at_rest_encryption_enabled` on `aws_elasticache_replication_group` are strings, so they are written as `"true"`.
- **What is not covered.** HTTPS from `0.0.0.0/0` on port 443 passes: the security group controls cover SSH (22), RDP (3389) and all-protocol rules only. Settings outside the bundle, such as S3 public access blocks or VPC flow logs, are not checked by this provider. See [docs/reference.md](../../docs/reference.md#cis-controls).
