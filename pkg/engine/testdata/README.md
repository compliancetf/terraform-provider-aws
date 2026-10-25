# Selector cross-check vectors

`selector_vectors.json` holds exception selectors, the values they bind and
the outcome the provider's selector engine gives them. A tool that decides
exceptions outside the provider imports `pkg/engine` and runs these vectors
to show it binds selectors the same way (for example from plan JSON).

The vectors are generated from the exception selector tests of
`internal/exceptions` (`TestExceptionSelector`,
`TestExceptionSelectorCompile`, `TestExceptionSetMapShapes` and the v0.1
truth table rows of `TestExceptionV01Verdicts`). For each case the generator
checks that the engine outcome gives the exception verdict the provider's
lookup gives (pass applies, unknown is pending, not_evaluable is rejected,
fail does not apply) and that every value round-trips through the encoding.

## Regenerate

```sh
go test ./internal/exceptions -run TestSelectorVectors -update
go test ./pkg/engine/...
```

Without `-update` the generator fails when the committed file is stale.

## Format

- `schemas`: resource type to its schema object as printed by
  `terraform providers schema -json`; read it with `engine.SchemaFromJSON`.
- `vectors[]`: `name`, `selector`, and either `compile_error` (the message
  `engine.CompileSelector` returns) or `type`, `op`, `env`, `env_known`,
  `provider` (a missing field is unknown), `resource`, `config`, `prior` (a
  missing value binds null) and `want` (`state`, `err`, `unknown_paths`).
- Values: JSON null is null, `{"$unknown": true}` is unknown,
  `{"$repeat": n, "of": x}` is a list or set of n copies of x or a string of x
  repeated n times; numbers parse at 512-bit precision. Keys starting with `$`
  are reserved. `pkg/engine/enginetest` reads and writes this encoding.

Vectors evaluate under a one-minute deadline; the per-resource time budget is
not part of them.
