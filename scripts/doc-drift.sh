#!/usr/bin/env bash
#
# Fails when a tracked file still names something the provider v2 protocol
# layer removed: the legacy upstream variables, the mock switch, the protofix
# package, the conflictPolicy ldflag, the old BSL license, or the v0.1
# control engine packages and baseline file (opv1) that the CEL engine
# replaced.
#
# Usage: scripts/doc-drift.sh   (make doc-drift; also run by TestDocDrift)

set -euo pipefail

cd "$(dirname "$0")/.."

LEGACY='UPSTREAM_PROVIDER_(PATH|VERSION)'
OTHER='COMPLIANCETF_USE_MOCK|protofix|conflictPolicy|Business Source License'
V01='internal/(controls|audit|values|testutil|engine/opv1)([^a-z_]|$)|cis_baseline\.json'
NAMES="${LEGACY}|${OTHER}|${V01}"
WORDS='BSL'

HISTORY=(
	':!scripts/doc-drift.sh'
)

# grep_ok runs git grep; exit 1 (no match) is success, anything else fails.
grep_ok() {
	local rc=0
	git grep "$@" || rc=$?
	if [[ $rc -gt 1 ]]; then
		echo "doc-drift: git grep $* failed (exit $rc)" >&2
		exit 2
	fi
}

# Every removed name everywhere except history.
found="$(
	{
		grep_ok -nIE -e "$NAMES" -- . "${HISTORY[@]}"
		grep_ok -nIw -e "$WORDS" -- . "${HISTORY[@]}"
	} | sort -u
)"

fail=0
if [[ -n "$found" ]]; then
	echo "doc-drift: removed names outside history:" >&2
	echo "$found" >&2
	fail=1
fi

if [[ $fail -eq 0 ]]; then
	echo "doc-drift: ok"
fi
exit "$fail"
