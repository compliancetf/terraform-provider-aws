package lifecycle

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

// TestOwnAccount: provider.account_id is the one declared
// allowed_account_ids id, a twelve-digit account id; anything else, or
// skip_requesting_account_id set, is unknown.
func TestOwnAccount(t *testing.T) {
	for _, c := range []struct {
		name  string
		req   hook.ConfigureRequest
		want  string
		known bool
	}{
		{"declared one", hook.ConfigureRequest{AccountID: "111111111111", AccountKnown: true}, "111111111111", true},
		{"absent, many or unknown at plan", hook.ConfigureRequest{}, "", false},
		{"skip requesting account id", hook.ConfigureRequest{AccountID: "111111111111", AccountKnown: true, SkipAccountID: true}, "", false},
		{"eleven digits", hook.ConfigureRequest{AccountID: "11111111111", AccountKnown: true}, "", false},
		{"thirteen digits", hook.ConfigureRequest{AccountID: "1111111111111", AccountKnown: true}, "", false},
		{"not digits", hook.ConfigureRequest{AccountID: "11111111111a", AccountKnown: true}, "", false},
		{"trailing newline", hook.ConfigureRequest{AccountID: "111111111111\n", AccountKnown: true}, "", false},
		{"empty", hook.ConfigureRequest{AccountKnown: true}, "", false},
	} {
		if got, known := ownAccount(&c.req); got != c.want || known != c.known {
			t.Errorf("%s: ownAccount = %q, %v; want %q, %v", c.name, got, known, c.want, c.known)
		}
	}
}

// TestEvalOwnAccount: an IAM control over the own account reads
// provider.account_id as ownAccount binds it, through the real celeng
// compiler. Only a declared account passes or fails; an undeclared one (absent,
// several ids or unknown at plan) is not_evaluable / unresolved, never pass.
func TestEvalOwnAccount(t *testing.T) {
	ctls, err := bundle.ParseControls([]byte(`[{"id": "s3_policy_own_account", "version": "1.0.0", "kind": "resource",
  "resource_type": "aws_s3_bucket_policy", "reads": ["policy"], "presence_mode": "effective", "on": ["create", "update"],
  "expr": "iam.parse(resource.policy).statements.all(s, iam.principals_in_account(s, provider.account_id, provider.partition))",
  "action": "deny", "severity": "high", "message": "Only principals of the own account.", "exemption_coverable": []}]`))
	if err != nil {
		t.Fatal(err)
	}
	cs := iamControlSet(t, ctls)
	typ := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"policy": tftypes.String}}
	v := tftypes.NewValue(typ, map[string]tftypes.Value{"policy": tftypes.NewValue(tftypes.String,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"s3:GetObject","Resource":"*"}]}`)})
	bind := func(req hook.ConfigureRequest) engine.ProviderInfo {
		p := providerInfo("us-east-1", true)
		p.AccountID, p.AccountKnown = ownAccount(&req)
		return p
	}
	for _, c := range []struct {
		name string
		req  hook.ConfigureRequest
		want engine.State
	}{
		{"declared own", hook.ConfigureRequest{AccountID: "111111111111", AccountKnown: true}, engine.Pass},
		{"declared other", hook.ConfigureRequest{AccountID: "222222222222", AccountKnown: true}, engine.Fail},
		{"not declared", hook.ConfigureRequest{}, engine.NotEvaluable},
		{"skip requesting account id", hook.ConfigureRequest{AccountID: "111111111111", AccountKnown: true, SkipAccountID: true}, engine.NotEvaluable},
	} {
		cfg := &Configured{Controls: cs, Schemas: policySchemas{}, Provider: bind(c.req)}
		cfg.compiler = celeng.NewCompilerFor(cfg.Schemas, cs, "sha256:nhj")
		l := New(Options{})
		l.testPerResource = 10 * time.Second // verdicts, not the 50 ms budget under load
		out := l.eval(context.Background(), cfg, profile.Dim{}, &cs.All()[0],
			&engine.Activation{Resource: v, Config: v, Op: engine.OpCreate,
				Provider: engine.ProviderInfo{AccountID: "111111111111", AccountKnown: true}}) // a caller-set account never counts
		if out.State != c.want {
			t.Errorf("%s: state %v (err %v), want %v", c.name, out.State, out.Err, c.want)
		}
		if c.want == engine.NotEvaluable && out.Err != engine.ErrUnresolved {
			t.Errorf("%s: err %v, want %v", c.name, out.Err, engine.ErrUnresolved)
		}
	}
}
