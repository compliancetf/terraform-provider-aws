#!/usr/bin/env bash
#
# Pre-push guard (prek, .pre-commit-config.yaml): refuses a push that would
# publish history from outside this repository. Every pushed commit must
# descend from the repository's root commit, and refs/dolt/* (data of a
# Dolt-backed issue tracker) is never pushed.
#
# prek sets PRE_COMMIT_TO_REF (the pushed commit) and PRE_COMMIT_REMOTE_BRANCH
# (the remote ref). By hand: scripts/check-push.sh [<commit>] [<remote ref>].

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

if ! git merge-base --is-ancestor "${root}" "${to}" 2>/dev/null; then
  echo "check-push: ${to} does not descend from this repository's root commit ${root:0:7}; it would publish unrelated history" >&2
  exit 1
fi
