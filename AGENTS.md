# AGENTS.md

Coding agents write all code in this repository. Before changing anything, read `DEVELOPING.md` in full: it holds the rules, the layout, every make target and script, the test gates and the release flow. Keep it current in the same pull request as your change.

@DEVELOPING.md

The short version:

- Everything committed here is public. No private repository names, tracker ids, local paths, customer names or internal planning notes; `scripts/check-no-private-content.sh` must pass. Machine-local notes go in an ignored local file (`CLAUDE.local.md`, `AGENTS.local.md`), never in the tree.
- Run `make hooks` once per clone; never bypass the hooks. Before opening a pull request, `make test` and `GOTOOLCHAIN=go1.26.2 make lint` must pass (the pre-push hook runs both).
- Changes land by pull request from maintainers only; users open issues.
- The provider denies or warns; it never changes a value the user wrote. `hashicorp/aws` is never modified.
