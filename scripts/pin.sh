#!/usr/bin/env bash
#
# Regenerates every artifact that depends on the pinned hashicorp/aws version.
#
# Usage: scripts/pin.sh X.Y.Z   (make pin VERSION=X.Y.Z), from a clean tree.
#
#   1. pins.json: tools/pinupstream (signed SHA256SUMS, every platform zip).
#   2. testdata/schemas/aws-subset.json and its provenance:
#      scripts/capture-aws-schema.sh, checked against the new pins.json.
#   3. internal/embedded/testdata/schema_compat.tsv and the CIS manifest
#      schema_compat_digest: tools/cispin. It fails, writing nothing, when the
#      pin needs an owner decision (version_range, a read gone or Computed).
#   4. internal/embedded/cis_ctftest.tar.gz: go generate (derived test key).
#   5. releases.json and testdata/schemas/aws: a new pin is appended to the
#      supported releases, and the schema subset of the previous pin is kept
#      as testdata/schemas/aws/<previous>.json, so a premium bundle is checked
#      against every release from the floor (ctf-bundlegen generate). The
#      owner raises the floor in releases.json, dropping the releases below
#      it and their schema files. A new major needs a new floor first.
#
# internal/embedded/cis.tar.gz is left to the owner: when step 3 changed the
# manifest, commit, then re-sign with scripts/owner-sign-cis.sh; until then
# TestReleaseKeyGuard fails. Re-running for the current pin changes nothing.

set -euo pipefail

cd "$(dirname "$0")/.."

version="${1:-}"
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
  echo "usage: scripts/pin.sh X.Y.Z (got \"$version\")" >&2
  exit 2
}

[[ -z "$(git status --porcelain)" ]] || { echo "pin: working tree is dirty; commit or remove changes first" >&2; exit 1; }

previous="$(jq -r .version pins.json)"
same_major=false
[[ "${version%%.*}" == "${previous%%.*}" ]] && same_major=true
if [[ "$version" != "$previous" ]]; then
  [[ "$(printf '%s\n%s\n' "$previous" "$version" | sort -t. -k1,1n -k2,2n -k3,3n | tail -n1)" == "$version" ]] || {
    echo "pin: $version is older than the pinned $previous; releases only move forward" >&2
    exit 1
  }
  $same_major || [[ "$(jq -r .floor releases.json)" == "$version" ]] || {
    echo "pin: $version is a new major after $previous: commit releases.json with floor \"$version\" and releases [\"$version\"] first" >&2
    exit 1
  }
fi

go run ./tools/pinupstream -version "$version"
if [[ "$version" != "$previous" ]] && $same_major && [[ "$(jq -r .version testdata/schemas/aws-subset.provenance.json)" == "$previous" ]]; then
  mkdir -p testdata/schemas/aws
  cp testdata/schemas/aws-subset.json "testdata/schemas/aws/$previous.json"
fi
./scripts/capture-aws-schema.sh "$version"
# Before cispin, so a pin that stops for an owner decision already lists it.
jq --arg v "$version" '.releases |= (if index([$v]) then . else . + [$v] end)' releases.json >releases.json.tmp
mv releases.json.tmp releases.json
go run ./tools/cispin
go generate ./internal/embedded/
# releases.json fits the new pin and testdata/schemas/aws holds each older release.
go test -count=1 -run '^TestRepoReleases$' ./internal/bundlegen

if ! git diff --quiet -- internal/embedded/cis/; then
  echo "pin: internal/embedded/cis changed: commit, then KEY=<production bundle key PEM> scripts/owner-sign-cis.sh"
fi
git status --short -- pins.json releases.json testdata/schemas internal/embedded
