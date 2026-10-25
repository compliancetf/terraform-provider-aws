# custom-bundle

A team control bundle loaded next to the embedded CIS bundle with `control_bundle_path`, for example in an air-gapped run. `bundle-src/` holds the source of a two-control bundle:

| Control | Action | Checks |
|---|---|---|
| `bobthecorp_rds_multi_az_enabled` | deny | `aws_db_instance.multi_az` |
| `bobthecorp_s3_bucket_force_destroy_disabled` | warn | `aws_s3_bucket.force_destroy` |

## Run it

A release build accepts only bundles signed by compliance.tf, so this example runs with a development build, which also trusts the test signing key. From the repository root:

1. Build the provider with `make build-dev`.
2. Write a CLI config whose `dev_overrides` maps `registry.compliance.tf/compliancetf/aws` to the repository root (see [DEVELOPING.md](../../DEVELOPING.md#manual-testing-with-terraform)), and `export TF_CLI_CONFIG_FILE=<that file>`.
3. Point the provider at a `hashicorp/aws` 6.x binary: `export CTFTEST_UPSTREAM_PATH=<path to terraform-provider-aws_v6.x.y_x5>`.
4. Build and sign the bundle archive:

   ```bash
   go run -tags ctftest ./cmd/ctfbundle build -src examples/custom-bundle/bundle-src \
     -key test:bundle -out examples/custom-bundle/team-controls.tar.gz
   ```

5. Plan, without `terraform init` (Terraform skips it under `dev_overrides`):

   ```bash
   cd examples/custom-bundle
   terraform plan
   ```

## What to expect

`terraform plan` exits 1:

| Severity | Control |
|---|---|
| Error | `bobthecorp_rds_multi_az_enabled` (`multi_az = false`) |
| Warning | `bobthecorp_s3_bucket_force_destroy_disabled` (`force_destroy = true`) |

The resources pass every embedded CIS control. A development build also warns that `hashicorp/aws 0.0.0-ctftest` is outside the upstream version range of each bundle; this is expected with `CTFTEST_UPSTREAM_PATH`.

## Notes

- In `bundle-src/manifest.json`, `provider.address` is the released provider address. The zero `schema_compat_digest` and the catalog `snapshot_id` are placeholders; compliance.tf fills them in for the bundles it issues.
- `COMPLIANCETF_BUNDLE_PATH` overrides `control_bundle_path`. A bundle that fails verification is not loaded and the run stops.
