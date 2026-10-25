# Contributing

This repository accepts pull requests from collaborators only. If you are not
a collaborator, please open an issue instead: bug reports, feature requests
and questions are all welcome there. Pull requests from other accounts are
closed without review.

## Opening a useful issue

- Search the existing issues first.
- Say what you expected and what happened instead.
- Include the provider version, the Terraform or OpenTofu version, and the
  `hashicorp/aws` version the provider runs.
- Include the smallest configuration that shows the problem, and the plan or
  apply output with the error. Remove account ids, credentials and any other
  secrets before you post.
- For a feature request, describe the problem you want solved, not only the
  change you have in mind.

Do not report a security vulnerability in a public issue. Use GitHub's
private vulnerability reporting for this repository instead.

## For collaborators

Build, test and architecture notes are in [DEVELOPING.md](DEVELOPING.md).
Before you open a pull request, run:

```bash
make test                          # hygiene, doc-drift and all Go tests
go vet ./...
GOTOOLCHAIN=go1.26.2 make lint
make conformance                   # Terraform on PATH; TF=/path/to/tofu for OpenTofu
```

Use conventional commit messages (`feat:`, `fix:`, `test:`, `docs:`,
`chore:`). Pull requests that touch a path in `.github/protected-paths` need
the code owner's approval.
