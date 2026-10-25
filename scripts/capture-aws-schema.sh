#!/usr/bin/env bash
#
# Captures testdata/schemas/aws-subset.json: `terraform providers schema -json`
# of hashicorp/aws pruned to the types below, plus aws-subset.provenance.json
# (version, the registry zh: hashes from the lock file, digests).
#
# Usage: scripts/capture-aws-schema.sh [version]   (make schema-subset; make pin)
# The version defaults to pins.json, then AWS_SCHEMA_VERSION. When pins.json
# pins a version, only that version is captured, and the provider Terraform
# installed must match the pin: every pinned zip sha256 is a lock zh: hash
# and the binary that runs is the pinned binary_sha256.
#
# Only `terraform init` (registry download, checked against HashiCorp's signed
# SHA256SUMS) and `providers schema` run: no credentials, no plan, no AWS calls.

set -euo pipefail

cd "$(dirname "$0")/.."

RESOURCES='aws_cloudtrail aws_db_instance aws_ebs_volume aws_efs_file_system
aws_ecs_task_definition aws_elasticache_replication_group aws_iam_group_policy
aws_iam_policy aws_iam_role_policy aws_iam_user_policy aws_instance aws_kms_key
aws_lambda_function_url aws_launch_template aws_lb_listener aws_rds_cluster aws_redshift_cluster aws_s3_bucket aws_s3_bucket_policy
aws_s3_bucket_public_access_block aws_s3_bucket_server_side_encryption_configuration
aws_s3_bucket_versioning aws_secretsmanager_secret_version aws_security_group
aws_security_group_rule aws_vpc_security_group_egress_rule
aws_vpc_security_group_ingress_rule'
DATA_SOURCES='aws_ami'

version="${1:-$(jq -r '.version // ""' pins.json)}"
version="${version:-${AWS_SCHEMA_VERSION:-}}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "capture-aws-schema.sh: need an exact x.y.z version (pins.json pins none)" >&2
  exit 1
}

pinned="$(jq -r '.version // ""' pins.json)"
[[ -z "$pinned" || "$version" == "$pinned" ]] || {
  echo "capture-aws-schema.sh: pins.json pins $pinned, not $version (run tools/pinupstream first)" >&2
  exit 1
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cat >"$work/main.tf" <<HCL
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= ${version}"
    }
  }
}
HCL

# Registry only: an explicit direct-only CLI config drops dev_overrides and the
# implied local mirrors (~/.terraform.d/plugins); no plugin cache, no extra args.
printf 'provider_installation {\n  direct {}\n}\n' >"$work/cli.tfrc"
unset TF_PLUGIN_CACHE_DIR TF_CLI_ARGS TF_CLI_ARGS_init TF_CLI_ARGS_providers \
  TF_DATA_DIR TF_REATTACH_PROVIDERS
export TF_CLI_CONFIG_FILE="$work/cli.tfrc" TF_IN_AUTOMATION=1
terraform -chdir="$work" init -input=false -backend=false >/dev/null
[[ -d "$work/.terraform/providers/registry.terraform.io/hashicorp/aws/$version" ]] || {
  echo "capture-aws-schema.sh: provider not installed from the registry" >&2
  exit 1
}

sha() {
  if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}
if [[ -n "$pinned" ]]; then
  lock_zh="$(grep -oE '"zh:[^"]+"' "$work/.terraform.lock.hcl" | tr -d '"' | sort)"
  pin_zh="$(jq -r '.platforms[].zip_sha256 | "zh:" + .' pins.json | sort)"
  # The registry may list platforms pins.json does not pin; every pinned zip must be in the lock.
  [[ -n "$pin_zh" && -z "$(comm -23 <(echo "$pin_zh") <(echo "$lock_zh"))" ]] || {
    echo "capture-aws-schema.sh: a pins.json zip_sha256 is not among the lock file zh: hashes" >&2
    exit 1
  }
  dirs=("$work/.terraform/providers/registry.terraform.io/hashicorp/aws/$version"/*/)
  [[ ${#dirs[@]} -eq 1 ]] || { echo "capture-aws-schema.sh: want one installed platform, got ${#dirs[@]}" >&2; exit 1; }
  platform="$(basename "${dirs[0]}")"
  bin="${dirs[0]}$(jq -r --arg p "$platform" '.platforms[$p].binary // ""' pins.json)"
  pin_sha="$(jq -r --arg p "$platform" '.platforms[$p].binary_sha256 // ""' pins.json)"
  [[ -f "$bin" && -n "$pin_sha" && "$(sha "$bin")" == "$pin_sha" ]] || {
    echo "capture-aws-schema.sh: installed $platform binary does not match the pins.json binary_sha256" >&2
    exit 1
  }
fi
terraform -chdir="$work" providers schema -json >"$work/full.json"

# Write both files under $work and move them only once every check passed.
out="$work/aws-subset.json"
jq -S --arg r "$RESOURCES" --arg d "$DATA_SOURCES" '
  def pick($names): with_entries(select(.key | IN($names | split("\\s+"; "")[])));
  .provider_schemas |= with_entries(select(.key == "registry.terraform.io/hashicorp/aws")
    | .value |= {
        provider,
        resource_schemas: (.resource_schemas | pick($r)),
        data_source_schemas: (.data_source_schemas | pick($d)),
        ephemeral_resource_schemas: {}
      })
' "$work/full.json" >"$out"

want=$(($(wc -w <<<"$RESOURCES") + $(wc -w <<<"$DATA_SOURCES")))
got=$(jq '.provider_schemas[] | (.resource_schemas | length) + (.data_source_schemas | length)' "$out")
[[ "$got" == "$want" ]] || { echo "capture-aws-schema.sh: want $want types, got $got" >&2; exit 1; }

# zh: hashes are the registry's per-platform package hashes; h1: covers only
# the platform that ran the capture, so it is left out.
hashes="$(grep -oE '"zh:[^"]+"' "$work/.terraform.lock.hcl" | jq -s 'sort')"
jq -e 'length > 0' <<<"$hashes" >/dev/null || { echo "capture-aws-schema.sh: no zh: hashes in the lock file" >&2; exit 1; }
jq -n -S \
  --arg version "$version" \
  --arg terraform "$(terraform version -json | jq -r .terraform_version)" \
  --arg jq "$(jq --version)" \
  --arg full "sha256:$(sha "$work/full.json")" \
  --arg subset "sha256:$(sha "$out")" \
  --argjson hashes "$hashes" '
  {
    source: "registry.terraform.io/hashicorp/aws",
    version: $version,
    captured_with: ("terraform " + $terraform + " providers schema -json, " + $jq + " -S"),
    lock_hashes: $hashes,
    full_schema_sha256: $full,
    subset_sha256: $subset,
    regenerate: ("scripts/capture-aws-schema.sh " + $version)
  }' >"$work/aws-subset.provenance.json"

mv "$out" "$work/aws-subset.provenance.json" testdata/schemas/
echo "captured hashicorp/aws ${version}: ${got} types -> testdata/schemas/aws-subset.json"
