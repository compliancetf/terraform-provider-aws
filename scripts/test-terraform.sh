#!/usr/bin/env bash
#
# CLI smoke test: `terraform validate` on every fixture in test/fixtures/
# with the ctftest provider build (see fixture-env.sh for the setup).
# Exits with the number of failing fixtures.

set -euo pipefail
source "$(dirname "$0")/fixture-env.sh"

failed=0
total=0
results=()
while IFS= read -r dir; do
  name="$(basename "${dir}")"
  total=$((total + 1))
  echo "--- ${name} ---"
  if terraform -chdir="${dir}" validate -no-color; then
    results+=("  PASS  ${name}")
  else
    results+=("  FAIL  ${name}")
    failed=$((failed + 1))
  fi
done < <(fixtures)

echo "========================================"
printf '%s\n' "${results[@]}"
echo "  Total: ${total}  Failed: ${failed}"
exit "${failed}"
