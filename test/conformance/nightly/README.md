# Nightly real-upstream conformance

`.github/workflows/nightly.yml` runs the scenarios in this directory, on manual `workflow_dispatch` only for now, against the real `hashicorp/aws` provider in a dedicated AWS sandbox account. The pull-request conformance run (`test/conformance/scenarios/`) uses the fake upstream; this run checks the same protocol paths (plan, apply, update, destroy, import, refresh, ephemeral, blocked apply, the NewState tap) against real AWS.

Each scenario directory has a `steps.json` in the shape of the PR scenarios and uses the shared `main.tf` unless it has its own. `@PREFIX@` renders to `bobthecorp-ctf-conf-<run id>-<attempt>-<scenario>`.

```bash
# Dry run, contacts no AWS API: renders each scenario, checks its step plan and
# resource types, tests the janitor against a fake aws CLI, and runs terraform
# validate when -tf is given and hashicorp/aws is on disk (-upstream, or the
# pinned version in the plugin cache); otherwise validate is skipped with a message.
go test -count=1 -tags conformance,nightly ./test/conformance/... -run Nightly -plan-only \
  [-tf "$(command -v terraform)" -upstream "$(test/conformance/nightly/upstream.sh)"]
```

validate never configures the provider, and its environment has no `AWS_*` variables and `/dev/null` AWS config and credentials files. The live run adds `-prefix bobthecorp-ctf-conf-<run>` and drops `-plan-only`. The workflow jobs:

| Job | Runs when | Does |
|---|---|---|
| `dry-run` | always | the dry run above with the pinned upstream, no AWS credentials |
| `nightly` | `NIGHTLY_ROLE_ARN` and `NIGHTLY_ACCOUNT_ID` set, ref `master` | OIDC into the sandbox role, refuses any other account, runs `janitor.sh`, then the live run on the newest Terraform (the `terraform-latest` cell) |
| `nuke` | `NIGHTLY_NUKE_ROLE_ARN`, `NIGHTLY_ACCOUNT_ID` and `NIGHTLY_NUKE_BLOCKLIST` set, ref `master`; after `nightly` whatever its result | OIDC into the nuke role, refuses any other account, runs aws-nuke with `nuke-config.yml`; a dry run (list only) unless `NIGHTLY_NUKE_LIVE` is `true` |

Until the variables exist the gated jobs show as skipped and the dry run prints a notice.

## Upstream binary

`upstream.sh` installs `hashicorp/aws` at the version `pins.json` pins, with `terraform init` (which checks the package against the registry's HashiCorp-signed SHA256SUMS). The runner hands that binary to the proxy as `COMPLIANCETF_UPSTREAM_PATH`, and pinned discovery verifies it against `pins.json` as in a release build. The conformance suite hands the fake upstream over the same `COMPLIANCETF_UPSTREAM_PATH`, verified against a generated `COMPLIANCETF_CONFORMANCE_PINS` file, which only `conformance` builds read. While `pins.json` pins no version, `upstream.sh` fails and the live jobs cannot run.

## Resources and cleanup

The scenarios create only SSM `String` parameters (standard tier, free) and call Secrets Manager `GetRandomPassword` (creates nothing), so the expected cost is near zero. Leaks are removed three ways: every step plan undoes its applies and imports (`TestNightly` checks this) and a failed scenario runs `terraform destroy` in cleanup; `janitor.sh` deletes `bobthecorp-ctf-conf-*` SSM parameters older than 24 h before each live run and, after it, this run's parameters at any age (a `go test` timeout skips `t.Cleanup`); the `nuke` job deletes everything except the owner setup below.

A new resource type needs an entry in `nightlyTypes` (`nightly_test.go`), a case in `janitor.sh` and actions in the role policy below.

## Owner setup (AWS and GitHub)

Nothing here exists yet. Replace `<SANDBOX>` with the sandbox account id, `<MGMT>` with the organization management account id and `<REGION>` with the region (default `us-east-1`).

### 1. Account

- A new member account in the organization used for nothing else. Do not enroll it in Control Tower (the nuke would remove its baseline) or extend `nuke-config.yml` filters to cover the baseline.
- An account alias without `prod` in it (aws-nuke refuses accounts without an alias or with `prod`), for example `compliancetf-conformance-sandbox`.
- Required SCP on the account: deny all actions outside `<REGION>` except global services (the nuke covers only `global` and `<REGION>`), and deny `organizations:LeaveOrganization`.

### 2. GitHub OIDC

In the sandbox account create the IAM OIDC provider `https://token.actions.githubusercontent.com` with audience `sts.amazonaws.com`.

In the repository:

- Environments `nightly-sandbox` and `nightly-nuke`, each with deployment branches limited to `master`.
- An OIDC subject template that carries the environment and the calling workflow, so a role trusts only `nightly.yml` on `master`:

```bash
gh api -X PUT repos/compliancetf/terraform-provider-aws/actions/oidc/customization/sub \
  -F use_default=false -f 'include_claim_keys[]=repo' -f 'include_claim_keys[]=context' -f 'include_claim_keys[]=job_workflow_ref'
```

This changes the `sub` claim of every workflow in the repository; no other workflow here uses OIDC today. A future OIDC role must match the same template.

### 3. Conformance role `bobthecorp-ctf-conf-nightly`

Maximum session duration 1 h. Trust policy:

```json
{"Version": "2012-10-17", "Statement": [{
  "Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
  "Principal": {"Federated": "arn:aws:iam::<SANDBOX>:oidc-provider/token.actions.githubusercontent.com"},
  "Condition": {"StringEquals": {
    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
    "token.actions.githubusercontent.com:sub": "repo:compliancetf/terraform-provider-aws:environment:nightly-sandbox:job_workflow_ref:compliancetf/terraform-provider-aws/.github/workflows/nightly.yml@refs/heads/master"}}}]}
```

Permissions (inline policy; covers the scenarios, the provider's reads and the janitor):

```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "ConformanceParameters", "Effect": "Allow",
   "Action": ["ssm:PutParameter", "ssm:GetParameter", "ssm:GetParameters", "ssm:DeleteParameter",
              "ssm:AddTagsToResource", "ssm:RemoveTagsFromResource", "ssm:ListTagsForResource"],
   "Resource": "arn:aws:ssm:<REGION>:<SANDBOX>:parameter/bobthecorp-ctf-conf-*"},
  {"Sid": "UnscopedReads", "Effect": "Allow", "Resource": "*",
   "Action": ["ssm:DescribeParameters", "secretsmanager:GetRandomPassword"],
   "Condition": {"StringEquals": {"aws:RequestedRegion": "<REGION>"}}}]}
```

`sts:GetCallerIdentity` needs no permission. `DescribeParameters` and `GetRandomPassword` do not support resource-level scoping.

### 4. Nuke role `bobthecorp-ctf-conf-nuke`

aws-nuke lists and deletes every resource type, so this role is broad by necessity; the account holds nothing of value, and the trust policy limits it to the `nuke` job. Maximum session duration 1 h.

- Trust policy: as above with `environment:nightly-nuke` in place of `environment:nightly-sandbox`.
- Permissions: the AWS managed `AdministratorAccess` policy plus this deny, which keeps the setup out of reach even if `nuke-config.yml` filters break:

```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "ProtectSetup", "Effect": "Deny", "Action": ["iam:*", "budgets:*"],
   "Resource": ["arn:aws:iam::<SANDBOX>:role/bobthecorp-ctf-conf-*", "arn:aws:iam::<SANDBOX>:policy/bobthecorp-ctf-conf-*",
                "arn:aws:iam::<SANDBOX>:oidc-provider/token.actions.githubusercontent.com",
                "arn:aws:budgets::<SANDBOX>:budget/bobthecorp-ctf-conf-*"]},
  {"Sid": "NoAccountChanges", "Effect": "Deny", "Action": ["organizations:*", "account:*"], "Resource": "*"},
  {"Sid": "NoNewPrincipals", "Effect": "Deny", "Resource": "*",
   "Action": ["iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:CreateRole", "iam:UpdateAssumeRolePolicy", "iam:PassRole"]}]}
```

### 5. Budget

In the sandbox account, AWS Budgets cost budget `bobthecorp-ctf-conf-monthly`: USD 50 per month (Phases 0-3), with

- email alerts to the owner at 80 % and 100 % actual and 100 % forecasted;
- a budget action at 100 % actual, run automatically, that attaches the customer managed policy `bobthecorp-ctf-conf-deny-all` (`{"Effect": "Deny", "Action": "*", "Resource": "*"}`) to `bobthecorp-ctf-conf-nightly`. Its execution role `bobthecorp-ctf-conf-budget-action` is trusted by `budgets.amazonaws.com` and may only `iam:AttachRolePolicy` and `iam:DetachRolePolicy` on that role.

Billing data lags by hours, so the budget stops a runaway night after the fact; the cheap resource set, the janitor and the nuke are the first line.

### 6. Repository variables

Repository variables (not environment variables: job conditions are evaluated before an environment is selected). None of these are secrets.

| Variable | Value |
|---|---|
| `NIGHTLY_ACCOUNT_ID` | `<SANDBOX>`; both jobs refuse credentials for any other account |
| `NIGHTLY_ROLE_ARN` | `arn:aws:iam::<SANDBOX>:role/bobthecorp-ctf-conf-nightly` |
| `NIGHTLY_AWS_REGION` | optional, default `us-east-1` |
| `NIGHTLY_NUKE_ROLE_ARN` | `arn:aws:iam::<SANDBOX>:role/bobthecorp-ctf-conf-nuke` |
| `NIGHTLY_NUKE_BLOCKLIST` | `<MGMT>`; aws-nuke requires at least one account it must never touch |
| `NIGHTLY_NUKE_LIVE` | `true` to delete; anything else lists only |

First run: set every variable but `NIGHTLY_NUKE_LIVE`, dispatch the workflow on `master`, check that `nightly` passes and the `nuke` dry run lists only leftovers (never the setup above), then set `NIGHTLY_NUKE_LIVE=true`.
