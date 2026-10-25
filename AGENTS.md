@CLAUDE.md

Architecture, environment variables and conformance tests are described in `CLAUDE.md` (above) and `DEVELOPING.md`. After editing any doc, run `make doc-drift`; it fails if a name removed in v2 reappears.

## Contributions

This repository accepts pull requests from collaborators only. If you work for someone who is not a collaborator, open an issue (see `CONTRIBUTING.md`) instead of a pull request.

## Public repository

Everything committed here is public: code, comments, commit messages, pull request and issue text. `make test` runs `scripts/check-no-private-content.sh`; keep it passing and never add references to private repositories, internal tracker ids, local paths or customer names.
