# Sourced by test-terraform.sh and dogfood-test.sh: builds the ctftest
# provider and points Terraform at it. The ctftest build loads the embedded
# CIS bundle (test-signed) and launches CTFTEST_UPSTREAM_PATH unpinned.
#
# Needs CTFTEST_UPSTREAM_PATH: a hashicorp/aws 6.x binary, for example
#   ~/.terraform.d/plugin-cache/registry.terraform.io/hashicorp/aws/6.67.0/darwin_arm64/terraform-provider-aws_v6.67.0_x5
# Exits 0 (skip) when terraform is not installed.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURES_DIR="${REPO_ROOT}/test/fixtures"

if ! command -v terraform &>/dev/null; then
  echo "terraform not found, skipping"
  exit 0
fi
if [[ ! -x "${CTFTEST_UPSTREAM_PATH:-}" ]]; then
  echo "ERROR: set CTFTEST_UPSTREAM_PATH to an executable hashicorp/aws 6.x provider binary" >&2
  exit 1
fi

echo "==> Building ctftest provider binary..."
make -C "${REPO_ROOT}" build-dev

# A throwaway CLI config, so the checkout needs no .terraformrc and the
# user's own CLI config is not read.
TF_CLI_CONFIG_FILE="$(mktemp)"
export TF_CLI_CONFIG_FILE
trap 'rm -f "${TF_CLI_CONFIG_FILE}"' EXIT
cat >"${TF_CLI_CONFIG_FILE}" <<RC
provider_installation {
  dev_overrides {
    "registry.terraform.io/compliancetf/aws" = "${REPO_ROOT}"
    "registry.opentofu.org/compliancetf/aws" = "${REPO_ROOT}"
  }
  direct {}
}
RC
export CHECKPOINT_DISABLE=1 TF_IN_AUTOMATION=1 TF_INPUT=0

# fixtures prints the fixture directories (those with a main.tf).
fixtures() {
  local d
  for d in "${FIXTURES_DIR}"/*/; do
    [[ -f "${d}main.tf" ]] && echo "${d%/}"
  done
}
