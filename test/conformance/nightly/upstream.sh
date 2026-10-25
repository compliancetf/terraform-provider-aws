#!/usr/bin/env bash
#
# Prints the path of hashicorp/aws at the version pins.json
# pins, installed by terraform init. The proxy then verifies it against the
# pin through COMPLIANCETF_UPSTREAM_PATH, as a release build would.

set -euo pipefail

cd "$(dirname "$0")/../../.."
v=$(sed -n 's/^  "version": "\([0-9.]*\)",$/\1/p' pins.json)
[[ -n "$v" ]] || { echo "upstream.sh: pins.json pins no version" >&2; exit 1; }

d=$(mktemp -d)
cat >"$d/main.tf" <<EOF
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= $v"
    }
  }
}
EOF
terraform -chdir="$d" init -backend=false -input=false -no-color >&2
bin=("$d"/.terraform/providers/registry.terraform.io/hashicorp/aws/"$v"/*/terraform-provider-aws_v"$v"_x5)
[[ -x "${bin[0]}" ]] || { echo "upstream.sh: no provider binary under $d" >&2; exit 1; }
echo "${bin[0]}"
