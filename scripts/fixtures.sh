#!/usr/bin/env bash
#
# Runs Terraform on every fixture in test/fixtures/ (a directory with a
# main.tf) against the ctftest provider build and a real hashicorp/aws.
#
#   scripts/fixtures.sh validate   terraform validate each fixture (make test-terraform)
#   scripts/fixtures.sh plan       terraform plan each fixture and check that the
#                                  embedded CIS bundle blocks exactly what it lists (make dogfood)
#
# A fixture lists each control that must block its plan on its own line:
#   # dogfood-blocks: <control id>
# Without such lines the plan must succeed. With them the plan must fail and
# its errors must be exactly the listed controls ("Error: [<id>] ..."), so a
# plan that fails for another reason fails the fixture. The fixtures set dummy
# credentials and skip AWS API calls.
#
# Needs CTFTEST_UPSTREAM_PATH: an executable hashicorp/aws 6.x binary, e.g.
#   ~/.terraform.d/plugin-cache/registry.terraform.io/hashicorp/aws/6.69.0/darwin_arm64/terraform-provider-aws_v6.69.0_x5
# Exits 0 (skip) without terraform on PATH, otherwise with the number of
# failing fixtures.

set -euo pipefail

mode="${1:-}"
case "${mode}" in
  validate | plan) ;;
  *) echo "usage: scripts/fixtures.sh validate|plan" >&2; exit 2 ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v terraform >/dev/null; then
  echo "terraform not found, skipping"
  exit 0
fi
if [[ ! -x "${CTFTEST_UPSTREAM_PATH:-}" ]]; then
  echo "fixtures.sh: set CTFTEST_UPSTREAM_PATH to an executable hashicorp/aws 6.x provider binary" >&2
  exit 2
fi

echo "==> Building the ctftest provider"
make -C "${root}" build-dev

# A throwaway CLI config: the checkout needs no .terraformrc and the user's
# own CLI config is not read.
TF_CLI_CONFIG_FILE="$(mktemp)"
export TF_CLI_CONFIG_FILE
trap 'rm -f "${TF_CLI_CONFIG_FILE}"' EXIT
cat >"${TF_CLI_CONFIG_FILE}" <<RC
provider_installation {
  dev_overrides {
    "registry.terraform.io/compliancetf/aws" = "${root}"
    "registry.opentofu.org/compliancetf/aws" = "${root}"
  }
  direct {}
}
RC
export CHECKPOINT_DISABLE=1 TF_IN_AUTOMATION=1 TF_INPUT=0

# check_plan prints why a fixture's plan output does not match its
# dogfood-blocks lines, or nothing when it does.
check_plan() {
  local dir="$1" rc="$2" out="$3" want got
  want="$(sed -n 's/^# dogfood-blocks: *\([^[:space:]]*\).*/\1/p' "${dir}/main.tf" | sort -u)"
  # Every error summary, reduced to its control id ("other" when it names none).
  got="$(awk '/^Error: /{ if (match($0, /^Error: \[[^]]+\]/)) print substr($0, 9, RLENGTH - 9); else print "other" }' <<<"${out}" | sort -u)"
  if [[ -z "${want}" && ${rc} -eq 0 ]] || [[ -n "${want}" && ${rc} -ne 0 && "${got}" == "${want}" ]]; then
    return
  fi
  echo "exit ${rc}; blocked by: ${got//$'\n'/ }; want: ${want//$'\n'/ }"
}

failed=0
total=0
results=()
for dir in "${root}"/test/fixtures/*/; do
  dir="${dir%/}"
  [[ -f "${dir}/main.tf" ]] || continue
  name="$(basename "${dir}")"
  total=$((total + 1))
  echo "--- ${name} ---"
  rc=0
  if [[ "${mode}" == validate ]]; then
    terraform -chdir="${dir}" validate -no-color || rc=$?
    why=""
    [[ ${rc} -eq 0 ]] || why="exit ${rc}"
  else
    out="$(terraform -chdir="${dir}" plan -no-color -lock=false 2>&1)" || rc=$?
    why="$(check_plan "${dir}" "${rc}" "${out}")"
    [[ -z "${why}" ]] || tail -40 <<<"${out}"
  fi
  if [[ -z "${why}" ]]; then
    results+=("  PASS  ${name}")
  else
    results+=("  FAIL  ${name}  (${why})")
    failed=$((failed + 1))
  fi
done

echo "========================================"
printf '%s\n' "${results[@]}"
echo "  Total: ${total}  Failed: ${failed}"
exit "${failed}"
