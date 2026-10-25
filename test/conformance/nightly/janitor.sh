#!/usr/bin/env bash
#
# Deletes every SSM parameter named bobthecorp-ctf-conf-* last modified more
# than 24 h ago, the only type the nightly scenarios create (nightlyTypes).
# Needs aws (credentials and region from the environment) and jq.
# Usage: janitor.sh [PREFIX MAX_AGE_SECONDS]   (nightly.yml passes this run's
# prefix and 0 after the tests, since a go test timeout skips t.Cleanup)

set -euo pipefail

PREFIX=${1:-bobthecorp-ctf-conf-}
MAX_AGE=${2:-$((24 * 3600))}
[[ "$PREFIX" == bobthecorp-ctf-conf-* && "$MAX_AGE" =~ ^[0-9]+$ ]] || { echo "janitor: bad arguments" >&2; exit 2; }
cutoff=$(($(date +%s) - MAX_AGE))

# LastModifiedDate is ISO 8601 from aws CLI v2 ("...T01:02:03.456000+00:00")
# or epoch seconds with cli_timestamp_format = wire. Any other shape makes jq
# fail and the janitor exit non-zero without deleting anything.
names=$(
	aws ssm describe-parameters --output json \
		--parameter-filters "Key=Name,Option=BeginsWith,Values=${PREFIX}" |
		jq -r --arg p "$PREFIX" --argjson cutoff "$cutoff" '
			def epoch: if type == "number" then floor
				else sub("\\.[0-9]+"; "") | sub("(\\+00:00|Z)$"; "Z") | fromdateiso8601 end;
			.Parameters[] | select(.Name | startswith($p))
			| select((.LastModifiedDate | epoch) < $cutoff) | .Name'
)

n=0
while IFS= read -r name; do
	[[ -n "$name" ]] || continue
	echo "janitor: deleting SSM parameter $name"
	aws ssm delete-parameter --name "$name"
	n=$((n + 1))
done <<<"$names"
echo "janitor: deleted $n SSM parameter(s) under $PREFIX older than $MAX_AGE s"
