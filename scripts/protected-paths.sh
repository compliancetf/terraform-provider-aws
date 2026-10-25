#!/usr/bin/env bash
# Decide whether a pull request touches a protected path.
#
# Usage:
#   scripts/protected-paths.sh [--rules FILE] [--patch-dir DIR] < changed-paths
#   scripts/protected-paths.sh --compare OWNER/REPO BASE_SHA HEAD_SHA
#   scripts/protected-paths.sh --self-test
#
# --compare: classify the files changed from the merge base of BASE_SHA to
#   HEAD_SHA, from the GitHub compare API (needs gh and GH_TOKEN). Pinned to
#   HEAD_SHA, so the result is for that commit even if the PR head moves; no PR
#   code is fetched or run, only the changed file list, go.sum patches and the
#   go.mod files at the merge base and HEAD_SHA (read as data).
# stdin: changed paths, one per line (renames: old and new path).
# --patch-dir: holds <path>.patch for each changed go.sum and <path>.old /
#   <path>.new for each changed go.mod, at the root or in a nested module
#   (test/fakeupstream/go.mod.new). A missing file means the change is unknown
#   and counts as protected.
# go.mod is parsed by tools/gomodcheck (built with go from this checkout),
# so an edit anywhere inside a replace/exclude/retract block is seen.
# Prints each protected hit. Exit 0 = clean, 1 = protected, 2 = error.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

OWNER='@antonbabenko'
# Crypto modules: a go.mod / go.sum line adding, removing or bumping one is protected.
# Covers every golang.org/x/crypto, filippo.io, sigstore, secure-systems-lab and
# theupdateframework module, and any module whose path contains "crypto" (any case).
CRYPTO_RE='[Cc][Rr][Yy][Pp][Tt][Oo]|filippo\.io/|github\.com/sigstore/|github\.com/cloudflare/circl|github\.com/theupdateframework/|github\.com/secure-systems-lab/|minisign'

die() { echo "protected-paths: $*" >&2; exit 2; }

# matches <regex> <file>: grep -Eq, but a grep error (exit 2) aborts instead of
# reading as "no match", so a broken check never fails open.
matches() {
  local rc=0
  grep -Eq "$1" "$2" || rc=$?
  [[ $rc -le 1 ]] || die "grep failed ($rc) on $2"
  return "$rc"
}

# build_gomodcheck: build tools/gomodcheck into $gmc once per run.
build_gomodcheck() {
  [[ -z ${gmc:-} ]] || return 0
  gmc=$(mktemp -d)
  trap 'rm -rf "$gmc"' EXIT
  (cd "$ROOT" && go build -o "$gmc/gomodcheck" ./tools/gomodcheck) >&2 || die "cannot build tools/gomodcheck"
}

check() {
  local rules="$ROOT/.github/protected-paths" pdir=""
  while [[ $# -gt 0 ]]; do
    case $1 in
      --rules) rules=$2; shift 2 ;;
      --patch-dir) pdir=$2; shift 2 ;;
      *) die "unknown argument: $1" ;;
    esac
  done
  [[ -r $rules ]] || die "cannot read $rules"

  local -a pats=()
  local line pat owner extra
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -z $line || $line == \#* ]] && continue
    [[ $line =~ ^/[A-Za-z0-9._/-]+\ @[A-Za-z0-9-]+$ ]] || die "invalid protected-paths rule: $line"
    read -r pat owner extra <<<"$line"
    [[ $owner == "$OWNER" && -z ${extra:-} ]] || die "unexpected owner: $line"
    pat=${pat#/}
    pats+=("${pat%/}")
  done <"$rules"
  [[ ${#pats[@]} -gt 0 ]] || die "no rules in $rules"

  # A rule covers the path itself (file, symlink or submodule) and everything
  # below it. Compare case-insensitively: macOS checkouts fold case, so
  # INTERNAL/Hook/x.go lands in internal/hook there.
  shopt -s nocasematch
  local path hit=0 f rc why
  while IFS= read -r path || [[ -n $path ]]; do
    [[ -z $path ]] && continue
    path=${path#/}
    for pat in "${pats[@]}"; do
      if [[ $path == "$pat" || $path == "$pat"/* ]]; then
        echo "$path"; hit=1; break
      fi
    done
    f="${pdir:-/nonexistent}/$path"
    case $path in
      go.sum | */go.sum)
        if [[ ! -r $f.patch ]]; then
          echo "$path (patch unavailable)"; hit=1
        elif matches "^[-+].*($CRYPTO_RE)" "$f.patch"; then
          echo "$path (crypto dependency)"; hit=1
        fi
        ;;
      go.mod | */go.mod)
        if [[ ! -r $f.old || ! -r $f.new ]]; then
          echo "$path (go.mod unavailable)"; hit=1
        else
          build_gomodcheck
          rc=0
          why=$("$gmc/gomodcheck" -crypto "$CRYPTO_RE" "$f.old" "$f.new") || rc=$?
          [[ $rc -le 1 ]] || die "gomodcheck failed ($rc) on $path"
          if [[ $rc -eq 1 ]]; then echo "$path ($why)"; hit=1; fi
        fi
        ;;
    esac
  done
  return $hit
}

# --- self-test --------------------------------------------------------------

st_fail=0
expect() { # expect <want-exit> <name> <paths> [patch-dir]
  local want=$1 name=$2 paths=$3 pdir=${4:-} got=0
  local args=(--rules "$ROOT/.github/protected-paths")
  [[ -n $pdir ]] && args+=(--patch-dir "$pdir")
  printf '%s\n' "$paths" | "$0" "${args[@]}" >/dev/null 2>&1 || got=$?
  if [[ $got != "$want" ]]; then
    echo "FAIL $name: exit $got, want $want"
    st_fail=1
  else
    echo "ok   $name"
  fi
}

self_test() {
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/plain" "$tmp/sum" "$tmp/big" "$tmp/none" "$tmp/xcryptosub" "$tmp/anycrypto-sum" "$tmp/added"
  # go.mod fixtures: go.mod.old is B, go.mod.new is B with one edit. The
  # exclude and retract edits sit inside a block, away from its opener.
  local B=$'module github.com/bobthecorp/app\n\ngo 1.26.2\n\nrequire (\n\tgithub.com/bobthecorp/lib v1.0.0\n\tgolang.org/x/crypto v0.30.0\n)\n\nexclude (\n\tgithub.com/bobthecorp/a v1.0.0\n\tgithub.com/bobthecorp/b v1.0.0\n)\n\nretract (\n\tv0.1.0\n\tv0.2.0\n)\n'
  local R=$'require (\n'
  gomodpair() { # gomodpair <dir> <from> <to>
    [[ $B == *"$2"* ]] || { echo "FAIL fixture $1: no $2"; st_fail=1; }
    mkdir -p "$tmp/$1"
    printf '%s' "$B" >"$tmp/$1/go.mod.old"
    printf '%s' "${B/"$2"/"$3"}" >"$tmp/$1/go.mod.new"
  }
  gomodpair crypto 'crypto v0.30.0' 'crypto v0.31.0'
  gomodpair replace 'retract (' $'replace github.com/bobthecorp/x => ../x\n\nretract ('
  gomodpair block '/b v1.0.0' '/b v1.1.0'
  gomodpair retract 'v0.2.0' 'v0.2.1'
  gomodpair goversion 'go 1.26.2' 'go 1.27'
  gomodpair malformed "$R" $'require (\n\tgithub.com/bobthecorp/x\n'
  gomodpair plain 'lib v1.0.0' 'lib v1.1.0'
  printf '%s\n' '@@ -1,2 +1,2 @@' '-github.com/bobthecorp/lib v1.0.0 h1:aaa=' '+github.com/bobthecorp/lib v1.1.0 h1:bbb=' >"$tmp/plain/go.sum.patch"
  printf '%s\n' '@@ -1,2 +1,2 @@' '-golang.org/x/crypto v0.30.0 h1:aaa=' '+golang.org/x/crypto v0.31.0 h1:bbb=' >"$tmp/sum/go.sum.patch"
  # Every module family named in the crypto rule, plus any path containing "crypto".
  gomodpair filippo "$R" $'require (\n\tfilippo.io/edwards25519 v1.1.0\n'
  gomodpair sigstore "$R" $'require (\n\tgithub.com/sigstore/sigstore-go v1.0.0\n'
  gomodpair sslab "$R" $'require (\n\tgithub.com/secure-systems-lab/go-securesystemslib v0.9.0\n'
  gomodpair tuf "$R" $'require (\n\tgithub.com/theupdateframework/go-tuf/v2 v2.0.0\n'
  printf '%s\n' '@@ -1,1 +1,1 @@' '+golang.org/x/crypto/x509roots/fallback v0.0.1 h1:ccc=' >"$tmp/xcryptosub/go.sum.patch"
  gomodpair anycrypto "$R" $'require (\n\tgithub.com/bobthecorp/cryptolib v1.0.0 // indirect\n'
  printf '%s\n' '@@ -1,1 +1,1 @@' '-github.com/bobthecorp/hashcrypto v1.0.0/go.mod h1:aaa=' >"$tmp/anycrypto-sum/go.sum.patch"
  gomodpair upper "$R" $'require (\n\tgithub.com/bobthecorp/GoCrypto v1.0.0\n'
  # go.mod accepts quoted module paths with escapes, which hide the word crypto.
  gomodpair quoted "$R" $'require (\n\t"golang.org/x/cr\\x79pto" v0.31.0\n'
  # A new go.mod has no old side.
  printf '%s' "$B" >"$tmp/added/go.mod.new"
  # Nested modules get the same go.mod / go.sum checks as the root module.
  mkdir -p "$tmp/nested/test/fakeupstream" "$tmp/nestedcrypto/test/fakeupstream"
  cp "$tmp/plain/go.mod.old" "$tmp/plain/go.mod.new" "$tmp/nested/test/fakeupstream/"
  cp "$tmp/crypto/go.mod.old" "$tmp/crypto/go.mod.new" "$tmp/nestedcrypto/test/fakeupstream/"
  # Large patch with the crypto line first: a quiet matcher must not fail open.
  { printf '%s\n' '@@ -1,5000 +1,5000 @@' '+golang.org/x/crypto v0.31.0 h1:bbb='
    for i in $(seq 1 5000); do echo "+github.com/bobthecorp/m$i v1.0.0 h1:x="; done; } >"$tmp/big/go.sum.patch"

  echo "protected (exit 1):"
  expect 1 trust 'internal/trust/keyring.go'
  expect 1 hook 'internal/hook/route.go'
  expect 1 classes 'internal/tfplugin/classes.json'
  expect 1 workflow '.github/workflows/test.yml'
  expect 1 rules '.github/protected-paths'
  expect 1 codeowners '.github/CODEOWNERS'
  expect 1 self 'scripts/protected-paths.sh'
  expect 1 main 'main.go'
  expect 1 gomodcheck 'tools/gomodcheck/main.go'
  expect 1 proxy-file 'internal/proxy/classify.go'
  expect 1 proxy-any 'internal/proxy/server.go'
  expect 1 proxy-new 'internal/proxy/route5_new.go'
  expect 1 upstream-keys 'keys/release.asc'
  expect 1 upstream-any 'internal/upstream/client.go'
  # pins.json and keys/ moved to the repo root.
  expect 1 upstream-pins 'pins.json'
  expect 1 upstream-keys-readme 'keys/README'
  expect 1 upstream-keys-dir 'keys'
  expect 1 upstream-pins-move $'internal/upstream/pins.json\npins.json'
  expect 1 golangci '.golangci.yml'
  expect 1 golangci-alt-name '.golangci.yaml'
  expect 1 rename-out-of-protected $'internal/trust/keyring.go\ndocs/keyring.go'
  expect 1 mixed $'README.md\ninternal/embedded/cis.tar.gz'
  expect 1 gomod-crypto 'go.mod' "$tmp/crypto"
  expect 1 gomod-replace 'go.mod' "$tmp/replace"
  expect 1 gomod-exclude-block 'go.mod' "$tmp/block"
  expect 1 gomod-no-patch 'go.mod' "$tmp/none"
  expect 1 gosum-crypto 'go.sum' "$tmp/sum"
  expect 1 gosum-crypto-large 'go.sum' "$tmp/big"
  expect 1 gomod-filippo 'go.mod' "$tmp/filippo"
  expect 1 gomod-sigstore 'go.mod' "$tmp/sigstore"
  expect 1 gomod-secure-systems-lab 'go.mod' "$tmp/sslab"
  expect 1 gomod-tuf 'go.mod' "$tmp/tuf"
  expect 1 gosum-x-crypto-submodule 'go.sum' "$tmp/xcryptosub"
  expect 1 gomod-any-crypto 'go.mod' "$tmp/anycrypto"
  expect 1 gosum-any-crypto 'go.sum' "$tmp/anycrypto-sum"
  expect 1 gomod-crypto-uppercase 'go.mod' "$tmp/upper"
  expect 1 gomod-quoted-escape 'go.mod' "$tmp/quoted"
  expect 1 gomod-retract-block 'go.mod' "$tmp/retract"
  expect 1 gomod-go-version 'go.mod' "$tmp/goversion"
  expect 1 gomod-malformed 'go.mod' "$tmp/malformed"
  expect 1 gomod-added 'go.mod' "$tmp/added"
  expect 1 nested-gomod-crypto 'test/fakeupstream/go.mod' "$tmp/nestedcrypto"
  expect 1 nested-gosum-no-patch 'test/fakeupstream/go.sum' "$tmp/nested"
  # A symlink or submodule at the directory path itself (before the package exists).
  expect 1 dir-node 'internal/trust'
  expect 1 dir-node-github '.github'
  # Case variants fold onto the protected package on macOS checkouts.
  expect 1 case-variant 'INTERNAL/Hook/x.go'
  # Golden fixtures of protected paths that live outside protected directories.
  expect 1 golden-envelope 'internal/proxy/testdata/envelope/v1-full.bin'
  expect 1 golden-testdata-keys 'testdata/keys/test-bundle.txt'
  expect 1 golden-testdata-bundles 'testdata/bundles/good.tar.gz'
  expect 1 golden-rpcseq 'test/conformance/rpcseq/goldens/1.9/create.json'
  expect 1 golden-capabilities 'test/conformance/testdata/capabilities.json'
  # Wrapper loader and the wrapper.json it loads.
  expect 1 wrapper $'internal/wrapper/wrapper.go\nwrapper.json'
  expect 1 wrapper-json 'wrapper.json'
  echo "clean (exit 0):"
  expect 0 near-miss-dir 'internal/trustx/a.go'
  expect 0 near-miss-keys 'keysx/a.go'
  expect 0 nested-keys 'docs/keys/a.md'
  expect 0 conformance-other 'test/conformance/scenario_test.go'
  expect 0 docs 'docs/design.md'
  expect 0 readme 'README.md'
  expect 0 near-miss-prefix 'internal/hooks/x.go'
  expect 0 near-miss-proxy 'internal/proxyx/a.go'
  expect 0 near-miss-upstream 'internal/upstreamx/a.go'
  expect 0 near-miss-golangci '.golangci.yml.bak'
  expect 0 bundles 'bundles/soc2.json'
  expect 0 gomod-plain-bump $'go.mod\ngo.sum' "$tmp/plain"
  expect 0 nested-gomod-plain-bump 'test/fakeupstream/go.mod' "$tmp/nested"
  expect 0 empty ''
  echo "invalid rules file (exit 2):"
  local got=0
  printf '/internal/*.go @antonbabenko\n' >"$tmp/rules"
  echo README.md | "$0" --rules "$tmp/rules" >/dev/null 2>&1 || got=$?
  if [[ $got != 2 ]]; then echo "FAIL wildcard-rejected: exit $got, want 2"; st_fail=1; else echo "ok   wildcard-rejected"; fi
  got=0
  "$0" --compare 'bad repo' 1 2 >/dev/null 2>&1 || got=$?
  if [[ $got != 2 ]]; then echo "FAIL pr-bad-args: exit $got, want 2"; st_fail=1; else echo "ok   pr-bad-args"; fi

  aba_race
  if [[ $st_fail != 0 ]]; then echo "self-test FAILED"; return 1; fi
  echo "self-test passed"
}

# A->B->A force-push: the run for protected head A starts, the PR's live head
# is B (README only), then A again. A fake gh serves B's files for the live PR
# and A's files only for a compare pinned to A; the gate must classify A.
aba_race() {
  local base=1111111111111111111111111111111111111111 a=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa got=0
  local c=cccccccccccccccccccccccccccccccccccccccc e=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
  local z=0000000000000000000000000000000000000000
  # go.mod in compare mode: whole files at the merge base (m) and head (p plain bump, x exclude edit).
  local m=2222222222222222222222222222222222222222 p=3333333333333333333333333333333333333333
  local x=4444444444444444444444444444444444444444
  local nl=5555555555555555555555555555555555555555
  mkdir -p "$tmp/bin" "$tmp/gh"
  echo '[{"filename":"README.md","status":"modified","additions":1,"deletions":0}]' >"$tmp/gh/live-files.json"
  echo '{"total_commits":1,"commits":[],"files":[{"filename":"internal/trust/keyring.go","status":"modified","additions":1,"deletions":0}]}' >"$tmp/gh/compare-a.json"
  # Fake gh: answers only the two calls above, by URL; anything else fails.
  cat >"$tmp/bin/gh" <<STUB
#!/usr/bin/env bash
url="" jqx=""
while [[ \$# -gt 0 ]]; do
  case \$1 in
    --jq) jqx=\$2; shift 2 ;;
    repos/*) url=\$1; shift ;;
    *) shift ;;
  esac
done
case \$url in
  "repos/octo/repo/pulls/7/files?per_page=100") f=$tmp/gh/live-files.json ;;
  "repos/octo/repo/compare/$base...$a") f=$tmp/gh/compare-a.json ;;
  "repos/octo/repo/compare/$base...$c") f=$tmp/gh/compare-cap.json ;;
  "repos/octo/repo/compare/$base...$e") f=$tmp/gh/compare-nofiles.json ;;
  "repos/octo/repo/compare/$base...$z") f=$tmp/gh/compare-empty.json ;;
  "repos/octo/repo/compare/$base...$nl") f=$tmp/gh/compare-newline.json ;;
  "repos/octo/repo/compare/$base...$p" | "repos/octo/repo/compare/$base...$x") f=$tmp/gh/compare-gomod.json ;;
  "repos/octo/repo/contents/go.mod?ref=$m") f=$tmp/plain/go.mod.old ;;
  "repos/octo/repo/contents/go.mod?ref=$p") f=$tmp/plain/go.mod.new ;;
  "repos/octo/repo/contents/go.mod?ref=$x") f=$tmp/block/go.mod.new ;;
  *) echo "fake gh: unexpected \$url" >&2; exit 1 ;;
esac
if [[ -n \$jqx ]]; then jq -c "\$jqx" "\$f"; else cat "\$f"; fi
STUB
  chmod +x "$tmp/bin/gh"
  # 300 clean files: the compare API may have cut the list, so protected.
  jq -nc '{total_commits: 1, commits: [], files: [range(300) | {filename: "docs/f\(.).md", additions: 1, deletions: 0}]}' >"$tmp/gh/compare-cap.json"
  echo '{"total_commits":1,"commits":[]}' >"$tmp/gh/compare-nofiles.json"
  echo '{"total_commits":1,"commits":[],"files":[]}' >"$tmp/gh/compare-empty.json"
  # One renamed file whose old name holds a newline: it must not split into two clean paths.
  echo '{"total_commits":1,"commits":[],"files":[{"filename":"docs/b.md","previous_filename":"README.md\ndocs/a.md","status":"renamed","additions":0,"deletions":0}]}' >"$tmp/gh/compare-newline.json"
  echo '{"total_commits":1,"merge_base_commit":{"sha":"'"$m"'"},"commits":[],"files":[{"filename":"go.mod","status":"modified","additions":1,"deletions":1}]}' >"$tmp/gh/compare-gomod.json"
  PATH="$tmp/bin:$PATH" "$0" --compare octo/repo "$base" "$a" >/dev/null 2>&1 || got=$?
  if [[ $got != 1 ]]; then echo "FAIL aba-race: exit $got, want 1"; st_fail=1; else echo "ok   aba-race"; fi
  got=0; PATH="$tmp/bin:$PATH" "$0" --compare octo/repo "$base" "$c" >/dev/null 2>&1 || got=$?
  if [[ $got != 1 ]]; then echo "FAIL compare-cap: exit $got, want 1"; st_fail=1; else echo "ok   compare-cap"; fi
  got=0; PATH="$tmp/bin:$PATH" "$0" --compare octo/repo "$base" "$e" >/dev/null 2>&1 || got=$?
  if [[ $got != 2 ]]; then echo "FAIL compare-no-files: exit $got, want 2"; st_fail=1; else echo "ok   compare-no-files"; fi
  got=0; PATH="$tmp/bin:$PATH" "$0" --compare octo/repo "$base" "$z" >/dev/null 2>&1 || got=$?
  if [[ $got != 1 ]]; then echo "FAIL compare-empty-files: exit $got, want 1"; st_fail=1; else echo "ok   compare-empty-files"; fi
  got=0; PATH="$tmp/bin:$PATH" "$0" --compare octo/repo "$base" "$nl" >/dev/null 2>&1 || got=$?
  if [[ $got != 2 ]]; then echo "FAIL compare-newline-name: exit $got, want 2"; st_fail=1; else echo "ok   compare-newline-name"; fi
  got=0; PATH="$tmp/bin:$PATH" "$0" --compare octo/repo "$base" "$p" >/dev/null 2>&1 || got=$?
  if [[ $got != 0 ]]; then echo "FAIL compare-gomod-plain: exit $got, want 0"; st_fail=1; else echo "ok   compare-gomod-plain"; fi
  got=0; PATH="$tmp/bin:$PATH" "$0" --compare octo/repo "$base" "$x" >/dev/null 2>&1 || got=$?
  if [[ $got != 1 ]]; then echo "FAIL compare-gomod-exclude: exit $got, want 1"; st_fail=1; else echo "ok   compare-gomod-exclude"; fi
}

# compare_check <owner/repo> <base-sha> <head-sha>: run check on the compare
# API file list of base...head.
compare_check() {
  local repo=$1 base=$2 head=$3 rc=0 count f mb enc side ref
  [[ $repo =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ && $base =~ ^[0-9a-f]{40}$ && $head =~ ^[0-9a-f]{40}$ ]] \
    || die "bad --compare arguments"
  work=$(mktemp -d) # global: the EXIT trap reads it after return
  trap 'rm -rf "$work"' EXIT
  mkdir -p "$work/patches"
  gh api "repos/$repo/compare/$base...$head" >"$work/compare.json" || die "cannot compare $base...$head in $repo"
  jq -e '.files | type == "array"' "$work/compare.json" >/dev/null || die "compare response has no file list"
  jq -c '.files[]' "$work/compare.json" >"$work/files.jsonl" || die "jq failed"
  # paths.txt is one path per line: a name with a newline would split into
  # several paths, so refuse it.
  jq -se 'map(.filename, (.previous_filename // empty)) | any(contains("\n")) | not' "$work/files.jsonl" >/dev/null \
    || die "changed file name contains a newline"
  jq -r '.filename, (.previous_filename // empty)' "$work/files.jsonl" >"$work/paths.txt" || die "jq failed"
  # Keep a go.sum patch only when it is complete: its +/- line count must
  # equal the API's additions + deletions. Otherwise the patch counts as
  # unavailable, which check treats as protected.
  while IFS= read -r f; do
    [[ $f != *..* ]] || die "unexpected path: $f"
    mkdir -p "$work/patches/$(dirname "$f")"
    jq -r --arg f "$f" 'select(.filename == $f and .patch != null)
      | select(([.patch | split("\n")[] | select(test("^[-+]"))] | length) == (.additions + .deletions))
      | .patch' "$work/files.jsonl" >"$work/patches/$f.patch" || die "jq failed"
    [[ -s $work/patches/$f.patch ]] || rm -f "$work/patches/$f.patch"
  done < <(jq -r 'select(.filename | test("(^|/)go\\.sum$"; "i")) | .filename' "$work/files.jsonl")
  # Each go.mod path (renames: old and new) as a whole file at the merge base
  # and at head. A fetch that fails (added, removed or renamed file, API
  # error) leaves that side missing, which check treats as protected.
  mb=$(jq -r '.merge_base_commit.sha // ""' "$work/compare.json")
  while IFS= read -r f; do
    [[ $f != *..* ]] || die "unexpected path: $f"
    mkdir -p "$work/patches/$(dirname "$f")"
    enc=$(jq -rn --arg p "$f" '$p | split("/") | map(@uri) | join("/")')
    for side in old new; do
      ref=$mb; [[ $side == old ]] || ref=$head
      [[ $ref =~ ^[0-9a-f]{40}$ ]] || continue
      gh api -H 'Accept: application/vnd.github.raw+json' "repos/$repo/contents/$enc?ref=$ref" \
        >"$work/patches/$f.$side" 2>/dev/null || rm -f "$work/patches/$f.$side"
    done
  done < <(jq -Rr 'select(test("(^|/)go\\.mod$"; "i"))' "$work/paths.txt" | sort -u)
  "$0" --patch-dir "$work/patches" <"$work/paths.txt" || rc=$?
  [[ $rc -le 1 ]] || die "check failed ($rc)"
  # The compare API returns at most 300 files and does not page them.
  count=$(wc -l <"$work/files.jsonl")
  if [[ $count -ge 300 ]]; then
    echo "changed-file list hit the compare API cap ($count files)"; rc=1
  fi
  # Commits but no files: either they cancel out or the API dropped the list.
  if [[ $count -eq 0 ]] && ! jq -e '.total_commits == 0' "$work/compare.json" >/dev/null; then
    echo "compare lists commits but no changed files"; rc=1
  fi
  return "$rc"
}

if [[ ${1:-} == --compare ]]; then
  [[ $# -eq 4 ]] || die "usage: --compare OWNER/REPO BASE_SHA HEAD_SHA"
  rc=0; compare_check "$2" "$3" "$4" || rc=$?
  exit "$rc"
fi
if [[ ${1:-} == --self-test ]]; then
  self_test
  exit $?
fi
check "$@"
