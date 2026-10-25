#!/usr/bin/env bash
# Public-repo hygiene guard: this repo is MPL 2.0 and may go public,
# so it holds generator code and a small synthetic test catalog only. Paid
# framework bundles and the real content inputs they are built from stay in
# the private content pipeline.
#
# Usage:
#   scripts/check-no-private-content.sh [--root DIR]
#   scripts/check-no-private-content.sh --self-test
#
# Scans tracked and untracked, non-ignored files under DIR (default: the repo
# root), so a planted file fails before it is committed. Prints each hit.
# Exit 0 = clean, 1 = private content found, 2 = error.
#
# Rules:
#   1. Path: generated bundle output (dist/bundles/, <bundle-id>/{controls,build}.json,
#      <bundle-id>/cases/ where <bundle-id> is `all` or a framework bundle such as
#      soc2-aws), authored control bodies (provider/controls/**.yaml) and the
#      content export (provider_dispositions.json) may only appear under the
#      synthetic test catalog, internal/bundlegen/testdata/.
#   2. Content, everywhere: a build record must come from the test generator
#      (generator.version 0.0.0-test); a content export manifest must carry
#      all-zero sha256 digests; a controls.json catalog must stay under
#      MAX_CATALOG_BYTES. Real exports and real bundles fail these.
#   3. Path: local agent and issue-tracker state (.beads/, .claude/, .codex/,
#      .cursor/, .agents/, issues.jsonl) is never part of the tree.
#   4. Text, everywhere but this script: no absolute home-directory paths
#      (placeholder users such as user, dev and bobthecorp are fine) and no
#      planning task ids (P<n>-T<n>).
#   5. Text: no match of a private pattern list. The list names terms that
#      must not be published, so it is never committed: one extended regex
#      per line (# comments and blank lines skipped) in the file named by
#      COMPLIANCETF_PRIVATE_PATTERNS_FILE, default <git common dir>/info/private-patterns.
#      A missing default file skips this rule; a missing named file is an error.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SYNTHETIC='internal/bundlegen/testdata/'
MAX_CATALOG_BYTES=65536
# Matched case-insensitively: macOS checkouts fold case.
BUNDLE_PATH_RE='(^|/)dist/bundles/|(^|/)([^/]+-(aws|azurerm|google)|all)/(controls\.json$|build\.json$|cases/)|(^|/)provider/controls/.+\.ya?ml$|(^|/)provider_dispositions\.json$'
TEST_GENERATOR_RE='"generator":\{[^}]*"version":"0\.0\.0-test"'
REAL_DIGEST_RE='"sha256":"[0-9a-f]*[1-9a-f][0-9a-f]*"'
AGENT_PATH_RE='(^|/)\.(beads|claude|codex|cursor|agents)/|(^|/)issues\.jsonl$'
HOME_PATH_RE='/(Users|home)/[A-Za-z0-9._-]+'
PLACEHOLDER_HOME_RE='/(Users|home)/(user|dev|runner|bobthecorp|example)'
TASK_ID_RE='(^|[^A-Za-z0-9])P[0-9]+[A-Z]?-T[0-9]+[a-z]?([^A-Za-z0-9]|$)'
SELF='scripts/check-no-private-content.sh'

die() { echo "check-no-private-content: $*" >&2; exit 2; }

check() {
  local root=$ROOT
  while [[ $# -gt 0 ]]; do
    case $1 in
      --root) root=$2; shift 2 ;;
      *) die "unknown argument: $1" ;;
    esac
  done
  list=$(mktemp)
  trap 'rm -f "$list"' EXIT
  git -C "$root" ls-files -z --cached --others --exclude-standard >"$list" 2>/dev/null ||
    die "cannot list files under $root (not a git checkout?)"

  local patterns=${COMPLIANCETF_PRIVATE_PATTERNS_FILE:-}
  if [[ -n $patterns ]]; then
    [[ -f $patterns && -r $patterns ]] || die "cannot read COMPLIANCETF_PRIVATE_PATTERNS_FILE $patterns"
  else
    patterns="$(git -C "$root" rev-parse --path-format=absolute --git-common-dir)/info/private-patterns"
  fi

  shopt -s nocasematch
  local path f flat size hit=0 out
  while IFS= read -r -d '' path; do
    if [[ $path =~ $BUNDLE_PATH_RE && $path != "$SYNTHETIC"* ]]; then
      echo "$path: bundle content outside $SYNTHETIC"; hit=1
    fi
    if [[ $path =~ $AGENT_PATH_RE ]]; then
      echo "$path: local agent or issue-tracker state"; hit=1
    fi
    f="$root/$path"
    [[ -f $f ]] || continue
    case ${path##*/} in
      build.json)
        flat=$(tr -d '[:space:]' <"$f")
        if [[ ! $flat =~ $TEST_GENERATOR_RE ]]; then
          echo "$path: build record not from the test generator"; hit=1
        fi
        ;;
      manifest.json)
        flat=$(tr -d '[:space:]' <"$f")
        if [[ $flat == *'"snapshot_id"'* && $flat =~ $REAL_DIGEST_RE ]]; then
          echo "$path: content export manifest with real digests"; hit=1
        fi
        ;;
      controls.json)
        size=$(wc -c <"$f")
        if [[ $size -gt $MAX_CATALOG_BYTES ]]; then
          echo "$path: catalog of $((size)) bytes exceeds the synthetic limit $MAX_CATALOG_BYTES"; hit=1
        fi
        ;;
    esac
  done <"$list"
  shopt -u nocasematch

  # Text rules: git grep over the same file set, binary files skipped.
  # -o: each match is filtered alone, so a placeholder cannot hide a real path on its line.
  out=$(textgrep "$root" -o -e "$HOME_PATH_RE" -- . ":!$SELF")
  out=$(printf '%s\n' "$out" | grep -vE ":${PLACEHOLDER_HOME_RE}\$" || true)
  [[ -z $out ]] || { echo "$out" | sed 's/$/  <- home directory path/'; hit=1; }
  out=$(textgrep "$root" -e "$TASK_ID_RE" -- . ":!$SELF")
  [[ -z $out ]] || { echo "$out" | sed 's/$/  <- planning task id/'; hit=1; }
  if [[ -f $patterns && -r $patterns ]]; then
    local list2 rc=0
    list2=$(mktemp)
    grep -vE '^[[:space:]]*(#|$)' "$patterns" >"$list2" || rc=$?
    [[ $rc -le 1 ]] || { rm -f "$list2"; die "cannot read pattern file $patterns"; }
    if [[ -s $list2 ]]; then
      out=$(textgrep "$root" -f "$list2")
      [[ -z $out ]] || { echo "$out" | sed 's/$/  <- private pattern/'; hit=1; }
    fi
    rm -f "$list2"
  fi
  return $hit
}

# textgrep ROOT ARGS...: matching lines as path:line:text; exit 2 on a git error.
# The home-path and task-id rules exclude this script (its self-test plants
# both); the private-pattern rule covers it too.
textgrep() {
  local root=$1 rc=0
  shift
  git -C "$root" grep --untracked -I -n -E "$@" || rc=$?
  [[ $rc -le 1 ]] || die "git grep failed (exit $rc)"
}

# --- self-test --------------------------------------------------------------

SYNTH_BUILD='{"bundle_id":"soc2-aws","generator":{"version":"0.0.0-test","commit":"0000000"}}'
REAL_BUILD='{"bundle_id":"soc2-aws","generator":{"version":"1.4.0","commit":"9c1d2e3"}}'
SYNTH_MANIFEST='{"files":{"controls.json":{"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}},"snapshot_id":"snap_1"}'
REAL_MANIFEST='{"files":{"controls.json":{"sha256":"5d41402abc4b2a76b9719d911017c592ae2fbd4c5f1e3ddc4a3e1c9d0b7a8f6e"}},"snapshot_id":"snap_1"}'
G=internal/bundlegen/testdata

st_fail=0
# expect <want-exit> <name> [path=content]...: plant the files in a fresh git
# repo (untracked, as a developer would before `git add`) and run the check.
expect() {
  local want=$1 name=$2 got=0 dir spec
  shift 2
  dir=$(mktemp -d "$tmp/case.XXXXXX")
  git -C "$dir" init -q
  for spec in "$@"; do
    mkdir -p "$dir/$(dirname "${spec%%=*}")"
    printf '%s\n' "${spec#*=}" >"$dir/${spec%%=*}"
  done
  "$0" --root "$dir" >/dev/null 2>&1 || got=$?
  if [[ $got != "$want" ]]; then
    echo "FAIL $name: exit $got, want $want"
    st_fail=1
  else
    echo "ok   $name"
  fi
}

self_test() {
  # The cases set their own pattern file; an ambient one must not leak in.
  unset COMPLIANCETF_PRIVATE_PATTERNS_FILE
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  local big got=0
  big=$(head -c $((MAX_CATALOG_BYTES + 1)) /dev/zero | tr '\0' 'x')

  echo "private content (exit 1):"
  expect 1 planted-bundle 'soc2-aws/controls.json=[]'
  expect 1 planted-build "bundles/soc2-aws/build.json=$SYNTH_BUILD"
  expect 1 planted-cases 'out/cis-aws/cases/c1/pass.json={}'
  expect 1 planted-case-variant 'SOC2-AWS/Controls.json=[]'
  expect 1 dist-bundles 'dist/bundles/all/controls.json=[]'
  expect 1 authored-controls 'provider/controls/s3_bucket_versioning_enabled.yaml=id: x'
  expect 1 all-bundle 'out/all/controls.json=[]'
  expect 1 all-bundle-cases 'all/cases/c1/fail.json={}'
  expect 1 authored-controls-nested 'provider/controls/storage/s3.yml=id: x'
  expect 1 dispositions-export 'exports/provider_dispositions.json={}'
  expect 1 other-testdata-bundle 'internal/bundle/testdata/soc2-aws/controls.json=[]'
  expect 1 real-build-in-testdata "$G/golden/fixture/soc2-aws/build.json=$REAL_BUILD"
  expect 1 real-manifest-in-testdata "$G/inputs/export/manifest.json=$REAL_MANIFEST"
  expect 1 big-catalog-in-testdata "$G/golden/fixture/soc2-aws/controls.json=$big"
  expect 1 mixed 'README.md=x' 'soc2-aws/controls.json=[]'
  expect 1 tracker-dir '.beads/issues.jsonl={}'
  expect 1 agent-settings '.claude/settings.json={}'
  expect 1 tracker-export 'export/issues.jsonl={}'
  expect 1 home-path 'docs/a.md=see /Users/alice/src/x'
  expect 1 linux-home-path 'main.go=// built in /home/alice/go'
  expect 1 task-id 'main.go=// fixed in P1-T2'
  expect 1 task-id-letter 'main.go=// see P9X-T7'
  expect 1 task-id-two-digit 'main.go=// see P10-T3'
  expect 1 bare-home-dir 'docs/a.md=HOME=/home/alice'
  expect 1 home-path-beside-placeholder 'docs/a.md=/home/user/x and /Users/alice/y'
  printf '# private terms\n\nsecretcodename\n' >"$tmp/patterns"
  COMPLIANCETF_PRIVATE_PATTERNS_FILE="$tmp/patterns" expect 1 private-pattern 'README.md=the secretcodename plan'
  COMPLIANCETF_PRIVATE_PATTERNS_FILE="$tmp/patterns" expect 1 private-pattern-in-guard "$SELF=# secretcodename"
  expect 1 default-patterns-file '.git/info/private-patterns=secretcodename' 'README.md=the secretcodename plan'
  echo "clean (exit 0):"
  expect 0 synthetic-goldens "$G/golden/fixture/soc2-aws/controls.json=[]" \
    "$G/golden/fixture/soc2-aws/build.json=$SYNTH_BUILD" \
    "$G/golden/fixture/cis-aws/cases/c1/pass.json={}" \
    "$G/inputs/export/manifest.json=$SYNTH_MANIFEST" \
    "$G/inputs/export/provider_dispositions.json={}"
  expect 0 bundle-schema-testdata 'internal/bundle/testdata/controls/invalid/empty.json=[]'
  expect 0 example-bundle 'examples/custom-bundle/my-controls.json=[]'
  expect 0 embedded-baseline 'internal/embedded/cis/controls.json=[]'
  expect 0 near-miss 'soc2-aws-notes/controls.md=x' 'docs/soc2-aws.md=x'
  expect 0 empty
  expect 0 guard-own-fixtures "$SELF=# /Users/alice/x P1-T2"
  expect 0 placeholder-home 'main_test.go=dir := "/home/user/x" + "/Users/dev/y"'
  expect 0 not-a-task-id 'main.go=// P99 latency and EP-T1000X are fine'
  COMPLIANCETF_PRIVATE_PATTERNS_FILE="$tmp/patterns" expect 0 private-pattern-clean 'README.md=nothing here'
  echo "error (exit 2):"
  "$0" --root "$tmp/missing" >/dev/null 2>&1 || got=$?
  if [[ $got != 2 ]]; then echo "FAIL not-a-repo: exit $got, want 2"; st_fail=1; else echo "ok   not-a-repo"; fi
  COMPLIANCETF_PRIVATE_PATTERNS_FILE="$tmp/none" expect 2 missing-patterns-file 'README.md=x'
  COMPLIANCETF_PRIVATE_PATTERNS_FILE="$tmp" expect 2 patterns-file-is-dir 'README.md=x'

  if [[ $st_fail != 0 ]]; then echo "self-test FAILED"; return 1; fi
  echo "self-test passed"
}

if [[ ${1:-} == --self-test ]]; then
  self_test
  exit $?
fi
check "$@"
