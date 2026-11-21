<!--
This repository does not accept pull requests from outside the maintainer
team. Please close this and open an issue instead (see CONTRIBUTING.md).
-->

## Summary

## Docs impact

<!-- A change to a compliance {} attribute, a COMPLIANCETF_* variable, a mode,
a diagnostics line, a limit or a control: name the docs-site pages under
https://compliance.tf/docs/provider/ that must change. They must be live
before the release that ships this change. Otherwise write "none" and why. -->

- `docs/reference.md` updated: yes / not needed
- `docs/architecture.md` updated: yes / not needed
- Docs-site pages to change:

## Checks

- [ ] `make test`
- [ ] `go vet ./...`
- [ ] `GOTOOLCHAIN=go1.26.2 make lint`
- [ ] `make conformance`
