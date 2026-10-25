# Coverage

catalog snapshot `snap_20261004_000000_000000`.

| Bundle | Release | Controls | Generated | Pending review | Pending authoring | With IaC tool id |
|---|---|---|---|---|---|---|
| cis-aws | ga | 2 | 1 | 0 | 0 | 1 |
| soc2-aws | ga | 4 | 3 | 0 | 0 | 1 |
| pci-dss-aws | preview | 2 | 1 | 0 | 1 | 1 |
| hipaa-aws | preview | 1 | 0 | 0 | 1 | 1 |
| all | preview | 6 | 3 | 0 | 1 | 2 |

## cis-aws

Dispositions: provider-local 1, companion-local 0, graph 0, runtime 1, not-expressible 0.

Clauses covered in cis_v600: 1 of 3.

Not visible to the provider:

| Resource type | Disposition | Controls |
|---|---|---|
| (no resource type) | runtime | acct_bobthecorp_contact_set |

## soc2-aws

Dispositions: provider-local 2, companion-local 1, graph 1, runtime 0, not-expressible 0.

Clauses covered in soc_2: 3 of 4.

Not visible to the provider:

| Resource type | Disposition | Controls |
|---|---|---|
| aws_s3_bucket_versioning | graph | s3_bobthecorp_lifecycle_versioned |

## pci-dss-aws

Dispositions: provider-local 1, companion-local 1, graph 0, runtime 0, not-expressible 0.

Clauses covered in pci_dss_v40: 1 of 2.

Not generated yet (1):

- `rds_bobthecorp_deletion_guard`: pending authoring

## hipaa-aws

Dispositions: provider-local 1, companion-local 0, graph 0, runtime 0, not-expressible 0.

Clauses covered in hipaa_security_2003: 0 of 1.

Clauses covered in hipaa_final_omnibus_2013: 0 of 1.

Not generated yet (1):

- `rds_bobthecorp_deletion_guard`: pending authoring

## all

Dispositions: provider-local 3, companion-local 1, graph 1, runtime 1, not-expressible 0.

Not generated yet (1):

- `rds_bobthecorp_deletion_guard`: pending authoring

Not visible to the provider:

| Resource type | Disposition | Controls |
|---|---|---|
| aws_s3_bucket_versioning | graph | s3_bobthecorp_lifecycle_versioned |
| (no resource type) | runtime | acct_bobthecorp_contact_set |
