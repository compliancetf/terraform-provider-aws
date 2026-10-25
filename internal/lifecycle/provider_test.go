package lifecycle

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// TestPartitionOf: the region of the upstream provider config
// names the partition aws, aws-cn or aws-us-gov; anything else, an absent
// region included, is not known (fail closed, never aws).
func TestPartitionOf(t *testing.T) {
	for _, c := range []struct {
		region, want string
		known        bool
	}{
		{"us-east-1", "aws", true},
		{"eu-west-1", "aws", true},
		{"ap-southeast-7", "aws", true},
		{"il-central-1", "aws", true},
		{"mx-central-1", "aws", true},
		{"cn-north-1", "aws-cn", true},
		{"cn-northwest-1", "aws-cn", true},
		{"us-gov-west-1", "aws-us-gov", true},
		{"us-gov-east-1", "aws-us-gov", true},
		{"", "", false},
		{"us-iso-east-1", "", false},  // ISO partitions: not mapped
		{"us-isob-east-1", "", false}, // ISO partitions: not mapped
		{"eu-isoe-west-1", "", false},
		{"eusc-de-east-1", "", false},
		{"US-EAST-1", "", false},
		{"us-east-1 ", "", false},
		{"cn-north", "", false},
		{"us-gov-west-", "", false},
		{"xx-east-1", "", false},
		{"cn-north-1\n", "", false},
		{"aws", "", false},
		{"us-gov-1", "", false},      // gov label without a name: not aws (SDK says aws)
		{"us-iso-1", "", false},      // iso label: not aws
		{"us-isofoo-1", "", false},   // iso* label: not aws
		{"us-east-999", "aws", true}, // the SDK pattern: aws
		{"cn-invalid-1", "aws-cn", true},
	} {
		p, known := partitionOf(c.region)
		if p != c.want || known != c.known {
			t.Errorf("partitionOf(%q) = %q, %v; want %q, %v", c.region, p, known, c.want, c.known)
		}
	}
}

// TestEvalBindsProvider: the program sees the provider binding of
// the Configure snapshot, never a caller-set one; before Configure every
// field is unknown.
func TestEvalBindsProvider(t *testing.T) {
	ctl := stageControlSet(t).For("aws_db_instance", bundle.OnCreate)[0]
	v := tftypes.NewValue(dbType, map[string]tftypes.Value{
		"storage_encrypted": tftypes.NewValue(tftypes.Bool, false), "kms_key_id": tftypes.NewValue(tftypes.String, nil),
		"engine": tftypes.NewValue(tftypes.String, nil), "deletion_protection": tftypes.NewValue(tftypes.Bool, nil),
		"id": tftypes.NewValue(tftypes.String, nil)})
	forged := engine.ProviderInfo{Partition: "aws", PartitionKnown: true, Region: "us-east-1", RegionKnown: true}
	cn := engine.ProviderInfo{Partition: "aws-cn", PartitionKnown: true}
	for _, c := range []struct {
		name string
		cfg  *Configured
		want engine.ProviderInfo
	}{
		{"before configure", nil, engine.ProviderInfo{}},
		{"configured unknown", &Configured{}, engine.ProviderInfo{}},
		{"configured aws-cn", &Configured{Provider: cn}, cn},
	} {
		var seen []engine.Activation
		l := New(Options{})
		l.testPerResource = 10 * time.Second // verdicts, not the 50 ms budget under load
		l.compiler = envCompiler{seen: &seen}
		a := &engine.Activation{Resource: v, Config: v, Op: engine.OpCreate, Provider: forged}
		l.eval(context.Background(), c.cfg, profile.Dim{}, &ctl, a)
		if len(seen) != 1 || seen[0].Provider != c.want {
			t.Errorf("%s: program saw %+v, want provider %+v", c.name, seen, c.want)
		}
		if a.Provider != forged {
			t.Errorf("%s: eval mutated the caller's activation", c.name)
		}
	}
}

// policySchemas is a one-attribute upstream schema for the
// principals_in_account eval test.
type policySchemas struct{}

func (policySchemas) Resource(typ string) (*tfprotov5.Schema, bool) {
	if typ != "aws_s3_bucket_policy" {
		return nil, false
	}
	return &tfprotov5.Schema{Block: &tfprotov5.SchemaBlock{Attributes: []*tfprotov5.SchemaAttribute{
		{Name: "policy", Type: tftypes.String, Optional: true}}}}, true
}

func (policySchemas) DataSource(string) (*tfprotov5.Schema, bool)        { return nil, false }
func (policySchemas) EphemeralResource(string) (*tfprotov5.Schema, bool) { return nil, false }

// TestEvalPrincipalsInAccount: iam.principals_in_account reads
// provider.partition as the Configure snapshot binds it, through the real
// celeng compiler. A principal of the account in aws-cn passes only when the
// bound partition is aws-cn; an unknown partition is unresolved; a caller-set
// provider never counts. No row without a known aws-cn binding passes.
func TestEvalPrincipalsInAccount(t *testing.T) {
	ctls, err := bundle.ParseControls([]byte(`[{"id": "s3_policy_principals_in_account", "version": "1.0.0", "kind": "resource",
  "resource_type": "aws_s3_bucket_policy", "reads": ["policy"], "presence_mode": "effective", "on": ["create", "update"],
  "expr": "iam.parse(resource.policy).statements.all(s, iam.principals_in_account(s, \"111111111111\", provider.partition))",
  "action": "deny", "severity": "high", "message": "Only principals of the account.", "exemption_coverable": []}]`))
	if err != nil {
		t.Fatal(err)
	}
	cs := iamControlSet(t, ctls)
	typ := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"policy": tftypes.String}}
	v := tftypes.NewValue(typ, map[string]tftypes.Value{"policy": tftypes.NewValue(tftypes.String,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws-cn:iam::111111111111:root"},"Action":"s3:GetObject","Resource":"*"}]}`)})
	cn := engine.ProviderInfo{Partition: "aws-cn", PartitionKnown: true}
	for _, c := range []struct {
		name   string
		cfg    *Configured
		caller engine.ProviderInfo
		want   engine.State
	}{
		{"aws-cn bound", &Configured{Controls: cs, Schemas: policySchemas{}, Provider: cn}, engine.ProviderInfo{}, engine.Pass},
		{"aws bound", &Configured{Controls: cs, Schemas: policySchemas{}, Provider: engine.ProviderInfo{Partition: "aws", PartitionKnown: true}}, cn, engine.Fail},
		{"partition unknown", &Configured{Controls: cs, Schemas: policySchemas{}}, cn, engine.NotEvaluable},
		{"partition not in the list", &Configured{Controls: cs, Schemas: policySchemas{}, Provider: engine.ProviderInfo{Partition: "aws-mars", PartitionKnown: true}}, cn, engine.NotEvaluable},
	} {
		c.cfg.compiler = celeng.NewCompilerFor(c.cfg.Schemas, cs, "sha256:m0l")
		l := New(Options{})
		l.testPerResource = 10 * time.Second // verdicts, not the 50 ms budget under load
		out := l.eval(context.Background(), c.cfg, profile.Dim{}, &cs.All()[0],
			&engine.Activation{Resource: v, Config: v, Op: engine.OpCreate, Provider: c.caller})
		if out.State != c.want {
			t.Errorf("%s: state %v (err %v), want %v", c.name, out.State, out.Err, c.want)
		}
		if c.want == engine.NotEvaluable && out.Err != engine.ErrUnresolved {
			t.Errorf("%s: err %v, want %v", c.name, out.Err, engine.ErrUnresolved)
		}
		if c.cfg.Provider != cn && out.State == engine.Pass {
			t.Errorf("%s: passes without a known aws-cn binding", c.name)
		}
	}
}

// iamControlSet is controls in one bundle that ships the action catalog
// fixture as its iam-actions.json.
func iamControlSet(t *testing.T, controls []bundle.Control) *bundle.ControlSet {
	t.Helper()
	mraw, err := os.ReadFile("testdata/stages/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	m, err := bundle.DecodeManifest(mraw)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../testdata/iam/actions-fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	cat, err := iampolicy.LoadCatalog(raw)
	if err != nil {
		t.Fatal(err)
	}
	b := &bundle.Bundle{Manifest: m, Digest: "sha256:" + strings.Repeat("cd", 32), Controls: controls,
		Revocations: trust.NoRevocations(), IAMCatalog: cat}
	cs, _, err := bundle.NewControlSet("bobthecorp", time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC), trust.NoRevocations(), b)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// TestResourceProvider: a resource's own region argument binds
// provider.region and its partition; an unknown one leaves both unknown,
// never the provider value; a null one, or a schema with no region
// attribute, keeps the provider-level binding. With no config (deletion
// guard, apply post-state) the resource value is read.
func TestResourceProvider(t *testing.T) {
	aws := engine.ProviderInfo{Region: "us-east-1", RegionKnown: true, Partition: "aws", PartitionKnown: true,
		AccountID: "111111111111", AccountKnown: true}
	acct := engine.ProviderInfo{AccountID: "111111111111", AccountKnown: true}
	rt := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"region": tftypes.String, "name": tftypes.String}}
	obj := func(r tftypes.Value) tftypes.Value {
		return tftypes.NewValue(rt, map[string]tftypes.Value{"region": r, "name": tftypes.NewValue(tftypes.String, "x")})
	}
	str := func(s string) tftypes.Value { return tftypes.NewValue(tftypes.String, s) }
	null := tftypes.NewValue(tftypes.String, nil)
	unknown := tftypes.NewValue(tftypes.String, tftypes.UnknownValue)
	noRegion := tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{"name": tftypes.String}},
		map[string]tftypes.Value{"name": str("x")})
	numRegion := tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{"region": tftypes.Number}},
		map[string]tftypes.Value{"region": tftypes.NewValue(tftypes.Number, 1)})
	dynNull := tftypes.NewValue(tftypes.DynamicPseudoType, nil)
	for _, c := range []struct {
		name             string
		config, resource tftypes.Value
		want             engine.ProviderInfo
	}{
		{"known aws-cn", obj(str("cn-north-1")), obj(str("cn-north-1")),
			engine.ProviderInfo{Region: "cn-north-1", RegionKnown: true, Partition: "aws-cn", PartitionKnown: true, AccountID: "111111111111", AccountKnown: true}},
		{"known gov", obj(str("us-gov-west-1")), obj(unknown),
			engine.ProviderInfo{Region: "us-gov-west-1", RegionKnown: true, Partition: "aws-us-gov", PartitionKnown: true, AccountID: "111111111111", AccountKnown: true}},
		{"known, no partition", obj(str("us-iso-east-1")), obj(str("us-iso-east-1")),
			engine.ProviderInfo{Region: "us-iso-east-1", RegionKnown: true, AccountID: "111111111111", AccountKnown: true}},
		{"unknown", obj(unknown), obj(unknown), acct},
		{"empty", obj(str("")), obj(str("")), acct},
		{"whole config unknown", tftypes.NewValue(rt, tftypes.UnknownValue), obj(str("cn-north-1")), acct},
		{"null keeps provider", obj(null), obj(str("eu-west-1")), aws},
		{"schema without region", noRegion, noRegion, aws},
		{"non-string region", numRegion, numRegion, aws},
		{"no config reads resource", dynNull, obj(str("cn-north-1")),
			engine.ProviderInfo{Region: "cn-north-1", RegionKnown: true, Partition: "aws-cn", PartitionKnown: true, AccountID: "111111111111", AccountKnown: true}},
		{"no config, resource region unknown", tftypes.NewValue(rt, nil), obj(unknown), acct},
		{"no config, null resource", dynNull, dynNull, aws},
	} {
		got := resourceProvider(aws, &engine.Activation{Config: c.config, Resource: c.resource})
		if got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
	// A deletion guard binds the resource (prior) region, never the config's.
	cnAcct := engine.ProviderInfo{Region: "cn-north-1", RegionKnown: true, Partition: "aws-cn", PartitionKnown: true,
		AccountID: "111111111111", AccountKnown: true}
	for _, c := range []struct {
		name             string
		config, resource tftypes.Value
		want             engine.ProviderInfo
	}{
		{"guard: config names a new region", obj(str("us-east-1")), obj(str("cn-north-1")), cnAcct},
		{"guard: prior region null keeps provider", obj(str("cn-north-1")), obj(null), aws},
		{"guard: prior region unknown", obj(str("cn-north-1")), obj(unknown), acct},
	} {
		got := resourceProvider(aws, &engine.Activation{Config: c.config, Resource: c.resource, RegionFromResource: true})
		if got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
	if got := resourceProvider(engine.ProviderInfo{}, &engine.Activation{Config: obj(null), Resource: obj(null)}); got != (engine.ProviderInfo{}) {
		t.Errorf("null region over an unknown provider: %+v, want unknown", got)
	}
}

// regionPolicySchemas is policySchemas with the v6 region argument.
type regionPolicySchemas struct{ policySchemas }

func (regionPolicySchemas) Resource(typ string) (*tfprotov5.Schema, bool) {
	if typ != "aws_s3_bucket_policy" {
		return nil, false
	}
	return &tfprotov5.Schema{Block: &tfprotov5.SchemaBlock{Attributes: []*tfprotov5.SchemaAttribute{
		{Name: "policy", Type: tftypes.String, Optional: true},
		{Name: "region", Type: tftypes.String, Optional: true, Computed: true}}}}, true
}

// TestEvalResourceRegion: through eval and the real celeng
// compiler, a control reading provider.partition sees the resource's own
// region over the provider-level one: an aws-cn principal passes for a
// cn-north-1 resource under an aws provider, an unknown resource region is
// unresolved even with the provider partition known, and a null one uses
// the provider partition.
func TestEvalResourceRegion(t *testing.T) {
	ctls, err := bundle.ParseControls([]byte(`[{"id": "s3_policy_principals_in_account", "version": "1.0.0", "kind": "resource",
  "resource_type": "aws_s3_bucket_policy", "reads": ["policy"], "presence_mode": "effective", "on": ["create", "update"],
  "expr": "iam.parse(resource.policy).statements.all(s, iam.principals_in_account(s, \"111111111111\", provider.partition))",
  "action": "deny", "severity": "high", "message": "Only principals of the account.", "exemption_coverable": []}]`))
	if err != nil {
		t.Fatal(err)
	}
	cs := iamControlSet(t, ctls)
	typ := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"policy": tftypes.String, "region": tftypes.String}}
	policy := tftypes.NewValue(tftypes.String,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws-cn:iam::111111111111:root"},"Action":"s3:GetObject","Resource":"*"}]}`)
	aws := engine.ProviderInfo{Region: "us-east-1", RegionKnown: true, Partition: "aws", PartitionKnown: true}
	for _, c := range []struct {
		name   string
		region tftypes.Value
		want   engine.State
	}{
		{"resource in cn-north-1", tftypes.NewValue(tftypes.String, "cn-north-1"), engine.Pass},
		{"resource region unknown", tftypes.NewValue(tftypes.String, tftypes.UnknownValue), engine.NotEvaluable},
		{"resource region null", tftypes.NewValue(tftypes.String, nil), engine.Fail},
	} {
		cfg := &Configured{Controls: cs, Schemas: regionPolicySchemas{}, Provider: aws}
		cfg.compiler = celeng.NewCompilerFor(cfg.Schemas, cs, "sha256:e562")
		l := New(Options{})
		l.testPerResource = 10 * time.Second // verdicts, not the 50 ms budget under load
		v := tftypes.NewValue(typ, map[string]tftypes.Value{"policy": policy, "region": c.region})
		out := l.eval(context.Background(), cfg, profile.Dim{}, &cs.All()[0], &engine.Activation{Resource: v, Config: v, Op: engine.OpCreate})
		if out.State != c.want {
			t.Errorf("%s: state %v (err %v), want %v", c.name, out.State, out.Err, c.want)
		}
		if c.want == engine.NotEvaluable && out.Err != engine.ErrUnresolved {
			t.Errorf("%s: err %v, want %v", c.name, out.Err, engine.ErrUnresolved)
		}
	}
}

// regionDBType is dbType with the v6 region argument.
var regionDBType = func() tftypes.Object {
	m := map[string]tftypes.Type{"region": tftypes.String}
	for k, v := range dbType.AttributeTypes {
		m[k] = v
	}
	return tftypes.Object{AttributeTypes: m}
}()

type regionDBSchemas struct{ dbSchemas }

func (regionDBSchemas) Resource(typ string) (*tfprotov5.Schema, bool) {
	s, ok := dbSchemas{}.Resource(typ)
	if ok {
		s.Block.Attributes = append(s.Block.Attributes, &tfprotov5.SchemaAttribute{Name: "region", Type: tftypes.String, Optional: true, Computed: true})
	}
	return s, ok
}

// regionDB is a hook value of regionDBType: opBad in region, or null.
func regionDB(t *testing.T, region string, isNull bool) *hook.Value {
	t.Helper()
	v := tftypes.NewValue(regionDBType, nil)
	if !isNull {
		v = tftypes.NewValue(regionDBType, map[string]tftypes.Value{
			"storage_encrypted": tftypes.NewValue(tftypes.Bool, false), "kms_key_id": tftypes.NewValue(tftypes.String, "k"),
			"engine": tftypes.NewValue(tftypes.String, "postgres"), "deletion_protection": tftypes.NewValue(tftypes.Bool, true),
			"id": tftypes.NewValue(tftypes.String, "db-1"), "region": tftypes.NewValue(tftypes.String, region)})
	}
	dv, err := tfprotov5.NewDynamicValue(regionDBType, v)
	if err != nil {
		t.Fatal(err)
	}
	return hook.NewValue(dv.MsgPack, nil, func() (tftypes.Type, error) { return regionDBType, nil })
}

// TestReplaceGuardBindsPriorRegion: a replace moving an
// instance from cn-north-1 to us-east-1 under an aws provider. The plan
// deletion guard, its halfCheck (delete half, no config) and the apply
// destroy RPC all bind the prior region, so an exception matching
// provider.partition == 'aws-cn' waives the guard at plan with no half
// warning, and at apply. With the prior in us-east-1 it blocks at plan.
func TestReplaceGuardBindsPriorRegion(t *testing.T) {
	aws := engine.ProviderInfo{Region: "us-east-1", RegionKnown: true, Partition: "aws", PartitionKnown: true}
	cs := stageControlSet(t)
	for _, tc := range []struct {
		name, prior string
		waived      bool
	}{
		{"prior in cn-north-1", "cn-north-1", true},
		{"prior in us-east-1", "us-east-1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, _ := opLifecycle(t, opGuard, `provider.partition == 'aws-cn'`, false)
			c := *l.cfg
			c.Schemas, c.Provider = regionDBSchemas{}, aws
			l.cfg = &c
			res, err := l.Evaluate(context.Background(), &hook.Request{Stage: hook.StagePlan, Kind: hook.KindResource,
				TypeName: "aws_db_instance", Op: hook.OpReplace, Config: regionDB(t, "us-east-1", false),
				Prior: regionDB(t, tc.prior, false), Planned: regionDB(t, "us-east-1", false)})
			if err != nil {
				t.Fatal(err)
			}
			d := diagnosed(res, opGuard)
			switch {
			case tc.waived && d != nil:
				t.Errorf("plan: diagnostic %+v, want waived with no half warning", d)
			case !tc.waived && (d == nil || d.Severity != hook.SeverityError):
				t.Errorf("plan: diagnostic %+v, want blocked", d)
			}
			env := &hook.EnvelopeHeader{V: 1}
			env.CTF.Op, env.CTF.ControlVersionsDigest = hook.OpReplace, cs.VersionsDigest("aws_db_instance")
			res, err = l.Evaluate(context.Background(), &hook.Request{Stage: hook.StageApplyPre, Kind: hook.KindResource,
				TypeName: "aws_db_instance", Op: hook.OpReplace, Config: regionDB(t, "", true),
				Prior: regionDB(t, tc.prior, false), Planned: regionDB(t, "", true), Envelope: env})
			if err != nil {
				t.Fatal(err)
			}
			if d := diagnosed(res, opGuard); (d == nil) != tc.waived {
				t.Errorf("apply destroy: diagnostic %+v, want waived %v (plan and apply must agree)", d, tc.waived)
			}
		})
	}
}

// TestHalfCheckRebindsProvider: halfCheck drops the
// config of the delete half and must rebind the provider from the
// resource, not keep the binding computed with the config.
func TestHalfCheckRebindsProvider(t *testing.T) {
	l, _ := opLifecycle(t, opGuard, `provider.partition == 'aws-cn'`, false)
	c := *l.cfg
	c.Schemas, c.Provider = regionDBSchemas{}, engine.ProviderInfo{Region: "us-east-1", RegionKnown: true, Partition: "aws", PartitionKnown: true}
	ctl := c.Controls.For("aws_db_instance", bundle.OnDelete)[0]
	prior, err := regionDB(t, "cn-north-1", false).Get()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := regionDB(t, "us-east-1", false).Get()
	if err != nil {
		t.Fatal(err)
	}
	// An activation without the guard flag: bound reads the config region.
	act := bound(&c, c.Table.Environment, &engine.Activation{Resource: prior, Config: cfg, Prior: prior, Op: engine.OpReplace})
	if act.Provider.Partition != "aws" {
		t.Fatalf("precondition: bound partition %q, want aws", act.Provider.Partition)
	}
	d := l.exceptAll(context.Background(), &c, &ctl, act, nil)
	if d.Applied {
		t.Fatal("precondition: exception applied under the config region")
	}
	d.Applied = true
	if diags := l.halfCheck(context.Background(), &c, &ctl, act, engine.OpDelete, d); len(diags) != 0 {
		t.Errorf("halfCheck kept the config binding: %+v", diags)
	}
}
