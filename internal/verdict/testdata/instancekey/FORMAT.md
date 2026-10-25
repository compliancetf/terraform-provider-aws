# instance_key format, version 1 (frozen)

This directory freezes the `instance_key` format. `ctfkit gate`
computes the key from plan JSON (tfjson adapter). The provider recomputes it at apply from
`PlannedState` (tftypes adapter). Both must produce the same bytes. The goldens here are the
oracle. A Go canonicalizer that does not reproduce every `expected.json` and `canonical.json`
byte for byte is wrong. A change to any rule below is a new format version, not an edit.

The key words MUST, MUST NOT and SHOULD carry their RFC 2119 meaning.

## Files

| Path | Content |
|---|---|
| `<type>/plan.json` | `terraform show -json` output from Terraform 1.16.3 and hashicorp/aws 6.65.0, trimmed to `format_version`, `terraform_version` and that type's `resource_changes`. Plans were made with fake credentials over a fabricated state for the fake org `bobthecorp` (account ids `111111111111`, `222222222222`). Input only, never regenerated. |
| `<type>/schema.json` | That type's resource schema and identity schema, verbatim from `terraform providers schema -json` of hashicorp/aws 6.65.0, in the same tree shape. Input only. |
| `<type>/expected.json` | Keys per instance (normative output). |
| `<type>/canonical.json` | Intermediate trees per key, for diffing an implementation step by step. Normative output. |
| `_edge/` | Synthetic type `edge_thing` (provider `registry.terraform.io/bobthecorp/edge`): number, set, list, dynamic, nested-type, Unicode and error cases. |

The outputs are frozen. They were written by a standard-library reference producer
(`ref.py`, not part of this repo), which also self-tests the provider-side path rules a golden
cannot pin: index syntax, set steps, tuple arity, schema validation before value lookup, no-op
cases, and zero spellings. The provider's Go code must reproduce every output.

## Test secret

Every golden is computed with this fixed secret:

```
test secret (32 ASCII bytes): INSECURE-TEST-SECRET-instancekey
test_secret_hex:              494e5345435552452d544553542d5345435245542d696e7374616e63656b6579
```

The secret is public, so every key derived from it is forgeable. Every way a secret enters
ctfkit (`ctfkit gate`, `ctfkit apply`) or the provider (the key-file loader) MUST
go through one constructor. That constructor:

- decodes the key file, which holds exactly 64 lowercase hex characters, into a fixed 32-byte
  buffer, and refuses any other encoding or length as its own error, never truncating;
- compares the buffer with this secret in constant time;
- refuses a match unless a `//go:build ctftest` file sets the allowing constant.

Release builds (goreleaser) never set `ctftest`, and release CI fails if they do. Tests prove
that an untagged build refuses the secret and a tagged build accepts it. A run secret MUST come from `crypto/rand`
(spec B3).

`k_leaf_hex` in `expected.json` is the HKDF `k_leaf` derived from this secret, and `key_check`
is `instance_key_check`.

## Keys and leaves

```
k_leaf  = HKDF-SHA256(ikm = secret, salt = "", info = "compliancetf.verdict/v1 leaf")
k_check = HKDF-SHA256(ikm = secret, salt = "", info = "compliancetf.verdict/v1 key-check")
leaf(v) = hex(HMAC-SHA256(k_leaf, tag || 0x00 || text(v)))
instance_key_check = hex(HMAC-SHA256(k_check, "compliancetf.verdict/v1 key-check"))
key = "sha256:" || hex(sha256("compliancetf.instance_key/v1" || 0x00 || type || 0x00 || form
      || 0x00 || JCS(H(after_masked)) || 0x00 || JCS(H(prior_identity))))
```

- HKDF: RFC 5869. The empty salt is 32 zero bytes, the same as Go `hkdf.New` with a nil salt.
  The output length is 32 bytes.
- All hex is lowercase.
- Leaf tags and text:

  | Kind | Tag | Text |
  |---|---|---|
  | string | `s` | the UTF-8 bytes as given; no NFC or other normalization |
  | number | `n` | the canonical number text (see [Numbers](#numbers)) |
  | bool | `b` | `true` or `false` |

- `H(x)` is `x` with every leaf replaced by `leaf(v)`. Sensitive and non-sensitive leaves are
  hashed alike, so sensitivity never has to agree between the two sides.
- JSON `null` is not a leaf and is never hashed.
- `type` is the resource type as written in plan JSON `type`, for example `aws_s3_bucket`.
- JCS is RFC 8785. A hashed tree holds only strings, `null`, arrays and objects:
  - Object keys (attribute names, map keys) stay plaintext and sort by UTF-16 code units.
  - Strings escape `"`, `\`, `\b`, `\f`, `\n`, `\r`, `\t` and the other code points below
    U+0020 (as `\u00xx`). Everything else is emitted as raw UTF-8.

## Forms, fields and prior identity

| Plan `actions` | Keys produced, in this order | Field |
|---|---|---|
| `["create"]` | create | `instance_key` |
| `["update"]` | update | `instance_key` |
| `["delete"]` (plain, deposed) | delete | `delete_key` |
| `["delete","create"]` (destroy-before-create and tainted replace) | delete, create | `delete_key`, `instance_key` |
| `["create","delete"]` (create-before-destroy) | create, delete | `instance_key`, `delete_key` |
| `["no-op"]`, `["read"]` | none | - |

Only changes with `mode: "managed"` produce keys; data sources are skipped. Any other action
list is an error. A deposed object takes only a delete entry; anything else for a deposed object
is an error, including `no-op`.

| Form | after | prior identity |
|---|---|---|
| create (also the create half of a replace) | planned after, masked | `null`, kind `none`; `change.before` and `before_identity` are ignored |
| update | planned after, masked | prior identity |
| delete (also the destroy half of a replace) | `null` | prior identity |

The prior identity kind is chosen the same way on both sides:

For the update and delete forms, a non-null prior identity that is not an object is an error,
and so is a non-null `change.before` that is not an object. When the type has no identity
schema, a prior identity is ignored and the kind is `id`.
`after_identity` is never read.

1. Kind `identity`: the prior identity object is non-null and keeps at least one leaf after the
   value-tree rules below. The prior identity object is plan JSON `change.before_identity` for
   ctfkit and `PriorIdentity` for the provider. The tree is that object, typed by the
   `resource_identity_schemas` entry. The prior state `id` is then not used, whatever it holds.
   Exception: the destroy half of a tainted replace (`action_reason: replace_because_tainted`)
   never uses kind `identity`; it takes kind `id` whatever the prior identity holds.
2. Kind `id`: otherwise. The tree is the object `{"id": "<prior state id>"}`, built from plan
   JSON `change.before.id` for ctfkit and the `PriorState` `id` for the provider. `H` hashes
   its one string leaf like any other leaf; the object is not hashed as a unit. The id MUST be
   a string of at least one byte, used untrimmed.
3. Kind `none`: the create form only.

For the update and delete forms, these are errors and the instance gets no key: no usable
identity together with an id that is null, absent, empty or not a string; an unknown inside
the prior identity; or a type mismatch. `ctfkit gate sign` refuses (exit 2); the
provider finds no match and blocks.

Every key records its `prior_identity_kind`. An entry whose kind differs from the kind the
provider derives never matches.

Terraform 1.16.3 emits `before_identity: null` for a tainted object even when its state holds an
identity (`aws_instance.tainted`). OpenTofu emits a usable `before_identity` there, and the
provider keys that destroy by id, so rule 1 excludes it (`_edge` `edge_thing.tainted`). An
SDKv2 create plans an identity object whose values are all null; that object never counts as
usable.

## Value tree

The tree is built from the schema, and both adapters follow the same rules:

- Each attribute's `type` gives its kind. `nested_type` and `block_types` follow
  `nesting_mode`:

  | `nesting_mode` | Kind |
  |---|---|
  | `single`, `group` | object |
  | `list` | list |
  | `set` | set |
  | `map` | map |

- `object` types are objects, and `tuple` types are lists. A tuple value whose length differs
  from its schema arity is an error.
- For the create and update forms, the planned value MUST be a JSON object (`after: false` is
  an error). The whole planned value is checked against these rules before masking, so masking
  never hides a value of the wrong kind or out of bounds.
- A null object attribute and a null map value are omitted. A null element inside a list or set
  is kept as JSON `null`.
- Empty lists, sets, maps and objects are kept.
- Dynamic types (DynamicPseudoType). A type is dynamic-bearing when it is `dynamic`, a list, set
  or map whose element type is dynamic-bearing, or a tuple with at least one dynamic-bearing
  position. An object type is never
  dynamic-bearing, but each of its dynamic-bearing members is omitted on its own. A
  dynamic-bearing value is omitted together with every unknown path into it (`_edge`
  `edge_thing.dynmix`: `mix.d` and `dynlist` go, `mix.s` stays).
- These are errors (the instance gets no key):
  - no schema entry for the change's `provider_name` and `type`
  - an attribute that the schema does not declare
  - a value whose JSON kind does not match its schema type
  - a duplicate JSON object key anywhere in plan JSON
  - a string or key that is not valid UTF-8, including a lone surrogate escape
  - a number outside the [Numbers](#numbers) bound
- Sets: each element is canonicalized and hashed, then the elements are sorted bytewise by
  `JCS(H(element))`. Duplicates are kept, because neither adapter deduplicates. "Sorted by JCS
  bytes" in the spec means this order.

## Unknown values

- ctfkit reads `after_unknown` against the schema: `true` at any node marks that node unknown.
- ctfkit records the result as the verdict entry's `unknown_paths`. The provider applies that
  list verbatim and never derives it again.
- Each path is a JSON array of strings: attribute names, block type names, map keys, and list
  or tuple indices.
- The schema node at each step decides how the step is read, on both sides:
  - An index MUST match the ASCII pattern `0|[1-9][0-9]{0,8}` (at most 9 digits, so it never
    wraps). A tuple index MUST be below the tuple arity.
  - A map key is any string.
  - A step into a set is an error. Normalization ends every path at the set, so an unknown
    under a set always masks the whole set, sensitive or dynamic contents included.
- The whole list is validated against the schema alone before any value is read. A path the
  schema cannot read is an error even when the value it names is absent.
- `after_unknown: true` for the whole planned value is an error. So is an `after_unknown` node
  that is not `true`, `false`, `null`, an array or an object, or whose shape does not match the
  schema node, inside a set included.

Normalization, applied by ctfkit before recording the list:

1. An unknown anywhere inside a set masks the whole set. The recorded path is the full path up
   to and including the set-valued step, for example `["ingress"]` or `["item","0","vals"]`.
2. A path into a dynamic attribute is dropped.
3. A path is dropped when a shorter listed path is its prefix, comparing whole segments (not
   string prefixes).
4. The list is deduplicated and sorted bytewise by the JCS of each path.

Masking applies each path to the planned value:

- The last step of a path removes an object attribute or a map key, whatever kind of value it
  holds.
- When the last step addresses a list element, that element becomes JSON `null`. List positions
  never shift.
- A path that does not resolve in the value is a no-op. That covers a missing attribute or
  key, a null container, and an index at or beyond the list length. Masking never extends a
  list.
- A present value whose JSON kind does not match the schema is refused by the value-tree rules,
  so masking can never leave it in the key.
- Every path MUST be non-empty and start with an attribute or block type the schema declares.
  Otherwise the verdict entry is invalid and fails closed. Validation runs on the normalized
  list.
- Delete-form keys have no planned value, so their `unknown_paths` is `[]`.

## Numbers

Plan JSON numbers are read as raw decimal text (Go: `json.Decoder.UseNumber`), never as float.

1. Number text longer than 1200 bytes is an error, checked before parsing. 1200 bytes holds
   every in-bound value as cty writes it (`Text('f', -1)`).
2. If the value is zero, the text is `0`. That covers `-0` and any zero spelling, such as `0e`
   followed by 100 nines, and the check runs before the exponent bound.
3. Let `e = floor(log10(|x|))` of the exact input value, taken before rounding and independent
   of spelling. Compute `e` from the literal's coefficient digits and exponent, without
   expanding the value. If `|e| > 1000`, it is an error.
   - `1e1000` and `0.1e1001` pass (the same value).
   - `10e1000` fails.
   - `1e-1000` passes.
   - `1e-1001` fails.
4. Otherwise, round the value to a 512-bit binary mantissa, ties to even (Go:
   `big.ParseFloat(s, 10, 512, big.ToNearestEven)`).
5. An integral result (`IsInt` of the rounded value, whatever the spelling) uses
   `Text('f', 0)`, the exact decimal integer, for any exponent.
6. Any other result uses `Text('g', -1)`: the shortest decimal that rounds back to the same
   512-bit value. It uses e-notation when the decimal exponent is below -4 or at least 6,
   always with a sign and at least two exponent digits.

Examples from `_edge` and the AWS goldens:

| Input | Text |
|---|---|
| `0.1` | `0.1` |
| `1e21` | `1000000000000000000000` |
| `9223372036854775808` (2^63) | `9223372036854775808` |
| `9007199254740993` (2^53+1) | `9007199254740993` |
| `18446744073709551617` (2^64+1) | `18446744073709551617` |
| `18446744073709552000` (aws float64 attribute) | `18446744073709552000` |
| `1234567.5` | `1.2345675e+06` |
| `0.00001` | `1e-05` |
| `0.0001` | `0.0001` |
| `-0` | `0` |
| `1e1000`, `0.1e1001` | the exact integer of the 512-bit rounding of 10^1000: 1000 digits beginning `99999` (see `_edge/canonical.json`) |
| `1e-1000` | `1e-1000` |
| `10e1000` | error (exponent) |
| `1e-1001` | error (exponent) |
| 1201 digits | error (length) |

The `ref.py` number code was cross-checked against Go `math/big` on 8000 random inputs, with up
to 300 significant digits and exponents of +-330, and had no differences.

A value that travels to the provider by msgpack keeps the same 512-bit value. go-cty v1.19.0
`msgpack/marshal.go` writes an integer that fits int64 as an int, a non-integral exact float64
as a float64, and anything else as `Text('f', -1)`. Only `-0` loses its sign on the way, hence
rule 2. Infinity has no plan JSON form; either side seeing it is an error.

## Golden file layout

`expected.json`:

```json
{
  "entries": [
    {
      "action_reason": "replace_because_cannot_update",
      "actions": ["create", "delete"],
      "address": "aws_iam_role_policy_attachment.this",
      "keys": [
        {"field": "instance_key", "form": "create", "key": "sha256:0bb85db8d1bddc46c30f645e88f1f7f85d2b78db3a5d0ff337813f2244732544", "prior_identity_kind": "none", "unknown_paths": [["id"]]},
        {"field": "delete_key", "form": "delete", "key": "sha256:72b94bcce87fddcaee512454f1ad3be4936f310477657cf7fab5fec133a54ba0", "prior_identity_kind": "identity", "unknown_paths": []}
      ]
    }
  ],
  "format": "compliancetf.instancekey.golden/v1",
  "k_leaf_hex": "...",
  "key_check": "...",
  "provider_version": "hashicorp/aws 6.65.0",
  "terraform_version": "1.16.3",
  "test_secret_hex": "494e5345435552452d544553542d5345435245542d696e7374616e63656b6579"
}
```

- `deposed` appears for a deposed object.
- An instance the format refuses has `error` instead of `keys` (only in the `_edge*`
  directories). A file the format refuses as a whole (`_edge_dupkey`, `_edge_surrogate`) has an
  `expected.json` and `canonical.json` of just `{"error", "format"}`.
- Entries follow the order of `resource_changes` in `plan.json`; keys follow the order in the
  actions table.
- In an entry or file that has `error`, only the presence of `error` is normative. Its text
  explains the case to a reader and is not part of the format. Every other field and byte of
  the goldens is normative. An implementation reports a refused instance as a runtime error (exit 2),
  never as a finding.

`canonical.json` has the same entries. Each key has `field`, `form` and `prior_identity_kind`
as in `expected.json`, plus:

- `after`: the masked tree before hashing, with leaves shown as `<tag>:<text>`. This is for
  display only; the hash input separates tag and text with 0x00.
- `prior_identity`: the prior identity tree, shown the same way.
- `after_hashed_jcs` and `prior_identity_hashed_jcs`: the exact JCS bytes that enter the key.

Display trees order sets like the hashed tree, but their object keys are sorted by code point
by the JSON writer. Only the `*_hashed_jcs` strings are in JCS order.

Both files are written by Python `json.dumps(indent=2, sort_keys=True, ensure_ascii=False)`
plus a trailing LF. That encoder escapes only `"`, `\` and code points below U+0020. The
byte layout is for `ref.py --check` only. Go tests MUST compare the goldens as parsed JSON
values. The `*_hashed_jcs` strings and the keys are compared exactly as strings.

## Coverage

| Case | Where |
|---|---|
| create, update, delete | most types |
| replace `["delete","create"]` | `aws_s3_bucket_public_access_block.this`, `aws_secretsmanager_secret_version.this` |
| replace `["create","delete"]` (create-before-destroy) | `aws_iam_role_policy_attachment.this` |
| tainted replace | `aws_instance.tainted`, `_edge` `edge_thing.tainted` (usable `before_identity`) |
| deposed delete | `aws_sns_topic.this` (deposed `b0b7ec01`), `_edge` `edge_thing.gone` |
| no-op (no key) | `aws_s3_bucket_public_access_block.noop`, `aws_sns_topic.this` |
| list block with unknown inner attributes; whole-list unknown | `aws_instance.new` |
| unknown inside a set | `aws_security_group.new` (`ingress`), `aws_s3_bucket_server_side_encryption_configuration.new`, `_edge` `edge_thing.unknowns` |
| unknown map value | `aws_vpc_security_group_ingress_rule.new` (`tags.Group`), `_edge` `edge_thing.unknowns` |
| unknown whole list element (null at index) | `_edge` `edge_thing.unknowns` (`lst`) |
| numbers above 2^53, non-integral numbers | `aws_cloudwatch_metric_alarm`, `_edge` `edge_thing.numbers` |
| sensitive leaves | `aws_db_instance` (`password`), `aws_rds_cluster` (`master_password`), `aws_lambda_function` (`environment` variables), `aws_secretsmanager_secret_version` (`secret_string`) |
| prior kind `identity` / `id` | most updates and deletes / `aws_kms_key.this`, `aws_ebs_volume.this`, `aws_instance.tainted`, `_edge` `edge_thing.allnull`, `edge_thing.tainted` |
| map keys whose UTF-16 and code point orders differ (U+1F600 before U+FF61) | `aws_s3_bucket.new` (`tags`), `_edge` `edge_thing.unicode` |
| JCS strings that keep `<`, `>`, `&`, U+2028, U+2029 and DEL raw (Go `encoding/json` would escape the first five, so its default escaping MUST be off) | `_edge` `edge_thing.unicode` |
| empty list, set, map and nested-type list kept | `aws_security_group.new`, `_edge` `edge_thing.empties` |
| dynamic attribute omitted, nested-type attribute, duplicate set elements | `_edge` |
| dynamic member of an object kept apart from its siblings; list of dynamic omitted | `_edge` `edge_thing.dynmix` |
| zero with a 100-digit exponent | `_edge` `edge_thing.zeroexp` |
| data source change skipped | `_edge` `data.edge_thing.datasrc` |
| errors: wrong-kind value under an unknown path; malformed `after_unknown` under a set (scalar, mixed `[true, "yes"]`, wrong shape); `before` not an object, also next to a usable identity; deposed `no-op`; planned after not an object; no usable identity with an absent, empty or non-string id; non-object identity; exponent bound in both directions; number length; root unknown; undeclared attribute; no schema for the provider; non-delete deposed entry | `_edge` |
| whole-file errors: duplicate JSON object key, lone surrogate (invalid UTF-8 bytes take the same path) | `_edge_dupkey`, `_edge_surrogate` |

## Fixture contract and re-recording

Plans and schemas carry only the fake org `bobthecorp`, the fake account ids `111111111111` and
`222222222222`, and fake resource ids. `ref.py --check` fails on any other 12-digit account id
in an ARN, or in a field whose name contains `account` or `owner` (string or number). It also
fails on an AWS access key id or a missing input file. Numbers are read exactly, so
`123456789012.0` counts as an account id.

The plans were recorded once, as follows:

1. Run `terraform plan` with Terraform 1.16.3 and hashicorp/aws 6.65.0 from a local plugin
   cache, using static fake credentials, every `skip_*` provider flag and an HTTPS proxy that
   reaches nothing, so no AWS call leaves the host.
2. Plan the creates. Turn their planned values into a version 4 state, with identities and
   with one tainted and one deposed object.
3. Run `terraform plan -refresh=false` against an edited configuration to get the updates,
   deletes and replaces.
4. Trim the output per type with `jq -S`.

Inputs are never re-recorded in place. A new Terraform or provider version gets new golden
directories next to these.

Plan inputs: two SDKv2 behaviours shape what the goldens can show. A map with one unknown value
is planned as a fully unknown map (`aws_iam_role.new`), so only the plugin-framework resource
`aws_vpc_security_group_ingress_rule` has a partially unknown map. An empty `tags = {}` is
planned as null (`aws_kms_key.new`).
