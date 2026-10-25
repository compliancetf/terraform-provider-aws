#!/usr/bin/env bash
#
# Dog-food test: `terraform plan` on every fixture in test/fixtures/ with the
# ctftest provider build and a real hashicorp/aws (see fixture-env.sh), and
# checks that the embedded CIS bundle blocks exactly what the fixture says.
#
# A fixture lists each control that must block its plan on its own line:
#   # dogfood-blocks: <control id>
# Without such lines the plan must succeed. With them the plan must fail, and
# its errors must be exactly the listed controls ("Error: [<id>] ..."), so a
# plan that fails for another reason, an evaluator error for example, fails
# the fixture. The fixtures set dummy credentials and skip AWS API calls.
#
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
  rc=0
  out="$(terraform -chdir="${dir}" plan -no-color -lock=false 2>&1)" || rc=$?
  want="$(sed -n 's/^# dogfood-blocks: *\([^[:space:]]*\).*/\1/p' "${dir}/main.tf" | sort -u)"
  # Every error summary, reduced to its control id ("other" when it names none).
  got="$(awk '/^Error: /{ if (match($0, /^Error: \[[^]]+\]/)) print substr($0, 9, RLENGTH - 9); else print "other" }' <<<"${out}" | sort -u)"
  if [[ -z "${want}" && ${rc} -eq 0 ]] || [[ -n "${want}" && ${rc} -ne 0 && "${got}" == "${want}" ]]; then
    results+=("  PASS  ${name}")
  else
    results+=("  FAIL  ${name}  (exit ${rc}; blocked by: ${got//$'\n'/ }; want: ${want//$'\n'/ })")
    echo "${out}" | tail -40
    failed=$((failed + 1))
  fi
done < <(fixtures)

echo "========================================"
printf '%s\n' "${results[@]}"
echo "  Total: ${total}  Failed: ${failed}"
exit "${failed}"
