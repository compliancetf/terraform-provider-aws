#!/usr/bin/env bash
#
# Bumps or checks the goreleaser pin in .github/workflows/release.yml
# (GORELEASER_VERSION and GORELEASER_SHA256 of the "Install goreleaser" step).
#
# Usage:
#   scripts/bump-goreleaser.sh vX.Y.Z   verify vX.Y.Z, then rewrite both pins
#   scripts/bump-goreleaser.sh --check  verify the pinned pair, change nothing
#
# Both modes run the same checks as the release step: download the
# Linux_x86_64 tarball, checksums.txt and its sigstore bundle, `cosign
# verify-blob` checksums.txt with goreleaser's release identity and issuer,
# take the tarball's sha256 from the verified checksums.txt and check the
# downloaded tarball against it. Unlike release.yml, which checks the pinned
# sha256 first, this verifies the signature before trusting any sha256 from
# checksums.txt. --check also requires that sha256 to equal the pinned one.
# Any failure exits non-zero before a file changes: the rewrite goes to a
# temp file, is checked there, and replaces release.yml as the last step.
#
# Needs curl and cosign (COSIGN=/path/to/cosign to override). Downloads only:
# it never builds, tags or releases anything.

set -euo pipefail

cd "$(dirname "$0")/.."

WORKFLOW=.github/workflows/release.yml
TARBALL=goreleaser_Linux_x86_64.tar.gz
COSIGN="${COSIGN:-cosign}"

die() { echo "bump-goreleaser.sh: $*" >&2; exit 1; }

# pinned NAME [FILE] prints each value of "NAME: value" in FILE (the workflow).
pinned() { sed -n "s/^[[:space:]]*$1: \([^[:space:]]*\)[[:space:]]*\$/\1/p" "${2:-$WORKFLOW}"; }

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

case "${1:-}" in
  --check) mode=check; version="$(pinned GORELEASER_VERSION)" ;;
  v*) mode=bump; version="$1" ;;
  *) die "usage: $0 vX.Y.Z | --check" ;;
esac
[[ $# -eq 1 ]] || die "usage: $0 vX.Y.Z | --check"
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "bad version '$version' (want vX.Y.Z)"
[[ "$(pinned GORELEASER_VERSION | wc -l)" -eq 1 && "$(pinned GORELEASER_SHA256 | wc -l)" -eq 1 ]] ||
  die "$WORKFLOW must pin GORELEASER_VERSION and GORELEASER_SHA256 exactly once"
command -v "$COSIGN" >/dev/null || die "cosign not found (set COSIGN)"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
base="https://github.com/goreleaser/goreleaser/releases/download/$version"
for f in "$TARBALL" checksums.txt checksums.txt.sigstore.json; do
  curl -fsSL --proto '=https' -o "$tmp/$f" "$base/$f" || die "download $base/$f failed"
done

"$COSIGN" verify-blob \
  --certificate-identity "https://github.com/goreleaser/goreleaser/.github/workflows/release.yml@refs/tags/$version" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle "$tmp/checksums.txt.sigstore.json" "$tmp/checksums.txt" ||
  die "cosign verify-blob of $version checksums.txt failed"

sum="$(awk -v f="$TARBALL" '$2 == f { print $1 }' "$tmp/checksums.txt")"
[[ "$sum" =~ ^[0-9a-f]{64}$ ]] || die "no single sha256 for $TARBALL in checksums.txt"
[[ "$(sha256 "$tmp/$TARBALL")" == "$sum" ]] || die "$TARBALL does not match checksums.txt"

if [[ "$mode" == check ]]; then
  [[ "$(pinned GORELEASER_SHA256)" == "$sum" ]] ||
    die "pinned GORELEASER_SHA256 differs from $version checksums.txt ($sum)"
  echo "OK: $version $sum verified"
  exit 0
fi

out="$(mktemp "$WORKFLOW.XXXXXX")"
trap 'rm -rf "$tmp" "$out"' EXIT
cp -p "$WORKFLOW" "$out" # keeps release.yml's mode; the contents are replaced below
sed \
  -e "s/^\([[:space:]]*GORELEASER_VERSION: \)[^[:space:]]*/\1$version/" \
  -e "s/^\([[:space:]]*GORELEASER_SHA256: \)[^[:space:]]*/\1$sum/" \
  "$WORKFLOW" >"$out"
# Equality also means each pin occurs exactly once in the result.
[[ "$(pinned GORELEASER_VERSION "$out")" == "$version" &&
   "$(pinned GORELEASER_SHA256 "$out")" == "$sum" ]] ||
  die "rewrite of $WORKFLOW failed; $WORKFLOW is unchanged"
mv "$out" "$WORKFLOW"
echo "Pinned goreleaser $version $sum in $WORKFLOW"
