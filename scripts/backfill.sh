#!/usr/bin/env bash
#
# Makes the release commit for a hashicorp/aws release older than the pin
# (a backfill), so compliancetf/aws X.Y.Z exists for it too.
#
# Usage: scripts/backfill.sh X.Y.Z   (make backfill VERSION=X.Y.Z), from a
# clean checkout of a master commit. REPUBLISH=1 allows a version whose tag
# already exists: its new archives replace the old ones in the registry, so
# lock files that recorded the old hashes fail until their entry is removed.
#
#   1. pins.json: tools/pinupstream for X.Y.Z (signed SHA256SUMS).
#   2. The CIS controls must hold on that release: scripts/capture-aws-schema.sh
#      and tools/cispin run as for a pin, and the backfill stops when cispin
#      stops for an owner decision or when the CIS type table or manifest
#      would change (the embedded bundle was signed for the current types).
#   3. Everything but pins.json is restored, and pins.json is committed alone
#      on branch backfill/X.Y.Z. release.yml releases a tag on that commit only
#      while its parent is on master, pins.json is the only change and
#      tools/pinupstream gives the same pins.json again.
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
branch="backfill/$version"

[[ -z "$(git status --porcelain)" ]] || { echo "backfill: working tree is dirty; commit or remove changes first" >&2; exit 1; }
git fetch -q origin master
git merge-base --is-ancestor HEAD origin/master || { echo "backfill: HEAD is not a master commit" >&2; exit 1; }
! git rev-parse -q --verify "refs/heads/$branch" >/dev/null || { echo "backfill: branch $branch exists; delete it first" >&2; exit 1; }
if [[ -n "$(git ls-remote --tags origin "refs/tags/v$version")" && "${REPUBLISH:-}" != 1 ]]; then
  echo "backfill: v$version is already released; REPUBLISH=1 replaces its archives (lock files with the old hashes break)" >&2
  exit 1
fi

current="$(jq -r .version pins.json)"
[[ "${version%%.*}" == "${current%%.*}" ]] || { echo "backfill: $version is not in the major of the pinned $current" >&2; exit 1; }
[[ "$version" != "$current" && "$(printf '%s\n%s\n' "$current" "$version" | sort -t. -k1,1n -k2,2n -k3,3n | head -n1)" == "$version" ]] || {
  echo "backfill: $version is not older than the pinned $current; use make pin" >&2
  exit 1
}

start="$(git rev-parse HEAD)"
saved="$(mktemp)"
committed=false
# On any exit before the commit lands: back to the start commit, generated files removed.
cleanup() {
  rm -f "$saved"
  $committed && return
  git checkout -q --detach "$start" 2>/dev/null || true
  git checkout -q -- . && git clean -qfd -- testdata internal/embedded
  git branch -q -d "$branch" 2>/dev/null || true
}
trap cleanup EXIT

go run ./tools/pinupstream -version "$version"
./scripts/capture-aws-schema.sh "$version"
go run ./tools/cispin
if ! git diff --quiet -- internal/embedded/; then
  git diff --stat -- internal/embedded/ >&2
  echo "backfill: the CIS type table changes for hashicorp/aws $version; the embedded bundle does not hold as signed (owner decision)" >&2
  exit 1
fi
cp pins.json "$saved"
git checkout -q -- . && git clean -qfd -- testdata internal/embedded
cp "$saved" pins.json

git switch -q -c "$branch"
git commit -q -m "chore(backfill): hashicorp/aws $version" -- pins.json
committed=true
echo "backfill: committed $branch on $(git rev-parse --short HEAD^). Push the branch, then tag:"
echo "  git push origin $branch && git tag -a v$version -m v$version HEAD && git push origin v$version"
