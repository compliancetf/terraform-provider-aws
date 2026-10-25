#!/usr/bin/env bash
#
# Makes the release commit for a hashicorp/aws release older than the pin
# (a backfill), so compliancetf/aws X.Y.Z exists for it too.
#
# Usage: scripts/backfill.sh X.Y.Z   (make backfill VERSION=X.Y.Z), from a
# clean checkout of a master commit.
#
#   1. pins.json: tools/pinupstream for X.Y.Z (signed SHA256SUMS).
#   2. The CIS controls must hold on that release: scripts/capture-aws-schema.sh
#      and tools/cispin run as for a pin, and the backfill stops when cispin
#      stops for an owner decision or when the CIS type table or manifest
#      would change (the embedded bundle was signed for the current types).
#   3. Everything but pins.json is restored, and pins.json is committed alone
#      on branch backfill/X.Y.Z. release.yml releases a tag on that commit only
#      while its parent is on master and pins.json is the only change.
#
# The commit never merges: master keeps the newest pin, and releases.json
# (premium bundle support) is not touched.

set -euo pipefail

cd "$(dirname "$0")/.."

version="${1:-}"
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
  echo "usage: scripts/backfill.sh X.Y.Z (got \"$version\")" >&2
  exit 2
}

[[ -z "$(git status --porcelain)" ]] || { echo "backfill: working tree is dirty; commit or remove changes first" >&2; exit 1; }
git fetch -q origin master
git merge-base --is-ancestor HEAD origin/master || { echo "backfill: HEAD is not a master commit" >&2; exit 1; }

current="$(jq -r .version pins.json)"
[[ "${version%%.*}" == "${current%%.*}" ]] || { echo "backfill: $version is not in the major of the pinned $current" >&2; exit 1; }
[[ "$version" != "$current" && "$(printf '%s\n%s\n' "$current" "$version" | sort -t. -k1,1n -k2,2n -k3,3n | head -n1)" == "$version" ]] || {
  echo "backfill: $version is not older than the pinned $current; use make pin" >&2
  exit 1
}

restore() { git checkout -q -- . && git clean -qfd -- testdata internal/embedded; }
trap 'restore' ERR

go run ./tools/pinupstream -version "$version"
./scripts/capture-aws-schema.sh "$version"
go run ./tools/cispin
if ! git diff --quiet -- internal/embedded/; then
  git diff --stat -- internal/embedded/ >&2
  echo "backfill: the CIS type table changes for hashicorp/aws $version; the embedded bundle does not hold as signed (owner decision)" >&2
  restore
  exit 1
fi
trap - ERR
cp pins.json "${TMPDIR:-/tmp}/backfill-pins-$version.json"
restore
cp "${TMPDIR:-/tmp}/backfill-pins-$version.json" pins.json

git switch -q -c "backfill/$version"
git commit -q -m "chore(backfill): hashicorp/aws $version" -- pins.json
echo "backfill: committed backfill/$version on $(git rev-parse --short HEAD^). Push the branch, then tag:"
echo "  git push origin backfill/$version && git tag -a v$version -m v$version HEAD && git push origin v$version"
