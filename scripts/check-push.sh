#!/usr/bin/env bash
#
# Pre-push guard (prek, .pre-commit-config.yaml): refuses a push that could
# publish history from outside this repository.
#
# Every root commit reachable from any local ref (branches, tags, remote-tracking
# and other refs), FETCH_HEAD and the pushed commit must be this repository's
# root commit. Checking the roots, not only that the tip descends from the
# root, also catches a merge that pulls in unrelated history through another
# parent. Checking every local ref covers multi-ref pushes, which prek reports
# as one ref, and local refs/dolt/* data, whose commits have their own root.
# Not covered: a commit no ref points at, pushed by explicit SHA as a second
# ref of the same push. refs/dolt/* is never pushed.
#
# prek sets PRE_COMMIT_TO_REF (a pushed commit, all zeros for a deletion) and
# PRE_COMMIT_REMOTE_BRANCH (its remote ref). By hand:
#   scripts/check-push.sh [<commit>] [<remote ref>]

set -euo pipefail

root=a0291ae59f294f8f49a9cab95feabe65fe222106
to="${PRE_COMMIT_TO_REF:-${1:-HEAD}}"
remote="${PRE_COMMIT_REMOTE_BRANCH:-${2:-}}"

case "${remote}" in
  refs/dolt/*)
    echo "check-push: refusing to push ${remote}: issue-tracker data does not belong in this repository" >&2
    exit 1
    ;;
esac

revs=(--all)
fetch_head="$(git rev-parse -q --verify FETCH_HEAD || true)"
[[ -z "${fetch_head}" ]] || revs+=("${fetch_head}")
[[ -z "${to//0/}" ]] || revs+=("${to}")

roots="$(git rev-list --max-parents=0 "${revs[@]}")" || {
  echo "check-push: cannot list the root commits of the local refs" >&2
  exit 1
}
others="$(sort -u <<<"${roots}" | grep -vx "${root}" || true)"
if [[ -n "${others}" ]]; then
  echo "check-push: unrelated history reachable from local refs or the pushed commit (root commits other than ${root:0:7}):" >&2
  echo "${others}" >&2
  echo "check-push: delete or rebase those refs; pushing them would publish that history" >&2
  exit 1
fi
