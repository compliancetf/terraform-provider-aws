package celeng

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/interpreter"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/enginetest"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/lib"
	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
)

// crossCase is one testdata/crosscheck case;
// untagged fields match their lower-case JSON keys.
type crossCase struct {
	ID, Schema   string
	ResourceType string   `json:"resource_type"`
	LoadDiags    []string `json:"load_diags"` // load diagnostic codes the control must produce
	Control      json.RawMessage
	Bindings     struct {
		Op, Env, Resource, Config, Prior json.RawMessage
		Provider                         map[string]json.RawMessage
	}
	Expect struct {
		State        engine.State
		ErrClass     engine.ErrClass `json:"err_class"`
		UnknownPaths []string        `json:"unknown_paths"`
	}
}

var testOpts = Options{PerResourceBudget: 10 * time.Second} // no deadline outside the timeout tests

// TestEvaluateCrosscheck runs testdata/crosscheck/{unknown,errors} through Load and Evaluate.
func TestEvaluateCrosscheck(t *testing.T) {
	s := awsSubset(t)
	for _, group := range []string{"unknown", "errors"} {
		files, _ := filepath.Glob(filepath.Join("..", "..", "..", "testdata", "crosscheck", group, "*.json"))
		for _, f := range files {
			t.Run(group+"/"+strings.TrimSuffix(filepath.Base(f), ".json"), func(t *testing.T) {
				data, err := os.ReadFile(f)
				if err != nil {
					t.Fatal(err)
				}
				dec := json.NewDecoder(bytes.NewReader(data))
				dec.DisallowUnknownFields()
				var tc crossCase
				if err := dec.Decode(&tc); err != nil {
					t.Fatal(err)
				}
				cs, err := bundle.DecodeControls(append(append([]byte("["), tc.Control...), ']'))
				if err != nil {
					t.Fatal(err)
				}
				comp, diags, err := New(testOpts).Load(cs, s, Content{})
				if err != nil {
					t.Fatal(err)
				}
				var codes []string
				for _, d := range diags {
					codes = append(codes, d.Code)
				}
				slices.Sort(codes)
				if want := slices.Sorted(slices.Values(tc.LoadDiags)); !slices.Equal(codes, want) {
					t.Fatalf("load diagnostics %v, want %v", codes, tc.LoadDiags)
				}
				objType := s.ResourceSchemas[tc.ResourceType].Block.ValueType()
				b := Bindings{
					Kind: cs[0].Kind, Type: tc.ResourceType,
					Resource: jsonValue(t, objType, tc.Bindings.Resource),
					Config:   jsonValue(t, objType, tc.Bindings.Config),
					Prior:    jsonValue(t, objType, tc.Bindings.Prior),
				}
				b.Op, _ = jsonString(t, tc.Bindings.Op)
				b.Env, b.EnvKnown = jsonString(t, tc.Bindings.Env)
				b.Provider.Region, b.Provider.RegionKnown = jsonString(t, tc.Bindings.Provider["region"])
				b.Provider.AccountID, b.Provider.AccountKnown = jsonString(t, tc.Bindings.Provider["account_id"])
				b.Provider.Partition, b.Provider.PartitionKnown = jsonString(t, tc.Bindings.Provider["partition"])
				rs := comp.Evaluate(context.Background(), b, nil)
				if len(rs) != 1 {
					t.Fatalf("%d results", len(rs))
				}
				r := rs[0]
				if r.State == engine.Pass && tc.Expect.State != engine.Pass {
					t.Fatalf("SAFETY: pass, want %s", tc.Expect.State)
				}
				if r.State != tc.Expect.State || r.ErrClass != tc.Expect.ErrClass || !slices.Equal(r.UnknownPaths, tc.Expect.UnknownPaths) || r.ControlID != cs[0].ID || r.Version != cs[0].Version {
					t.Fatalf("got %+v, want %+v", r, tc.Expect)
				}
			})
		}
	}
}

// jsonValue and jsonString read fixture values (enginetest.Value, String).
func jsonValue(t *testing.T, typ tftypes.Type, raw json.RawMessage) tftypes.Value {
	return enginetest.Value(t, typ, raw)
}

func jsonString(t *testing.T, raw json.RawMessage) (string, bool) { return enginetest.String(t, raw) }

func dbControl(id, expr string, reads ...string) bundle.Control {
	c := *testControl(bundle.KindResource, bundle.PresenceEffective, expr, reads...)
	c.ID, c.Version, c.ResourceType, c.Action = id, "1.0.0", "aws_db_instance", bundle.ActionDeny
	return c
}

func dbBindings(t *testing.T, resource string) Bindings {
	s := awsSubset(t)
	return Bindings{Kind: bundle.KindResource, Type: "aws_db_instance", Op: "create", Env: "prod", EnvKnown: true,
		Resource: jsonValue(t, s.ResourceSchemas["aws_db_instance"].Block.ValueType(), json.RawMessage(resource))}
}

const heavyExpr = `[0,1,2,3,4,5,6,7,8,9].all(a, [0,1,2,3,4,5,6,7,8,9].all(b, [0,1,2,3,4,5,6,7,8,9].all(c, [0,1,2,3,4,5,6,7,8,9].all(d, [0,1,2,3,4,5,6,7,8,9].all(e, [0,1,2,3,4,5,6,7,8,9].all(f, [0,1,2].all(g, resource.storage_encrypted)))))))`

func states(rs []Result) string {
	var out []string
	for _, r := range rs {
		out = append(out, r.ControlID+"="+r.State.String()+"/"+string(r.ErrClass))
	}
	return strings.Join(out, " ")
}

// TestEvaluateTimeout: a spent budget makes the running and every later control
// timeout; an unknown that absorbed the interrupt is timeout too.
func TestEvaluateTimeout(t *testing.T) {
	cs := []bundle.Control{
		dbControl("heavy", heavyExpr, "storage_encrypted"),
		dbControl("heavy_or_unknown", "resource.kms_key_id != null || "+heavyExpr, "kms_key_id", "storage_encrypted"),
		dbControl("light", "resource.storage_encrypted == true", "storage_encrypted"),
	}
	comp, _, err := New(Options{PerResourceBudget: 20 * time.Millisecond, CostLimit: 1 << 62}).Load(cs, awsSubset(t), Content{})
	if err != nil {
		t.Fatal(err)
	}
	b := dbBindings(t, `{"storage_encrypted": true}`)
	if got, want := states(comp.Evaluate(context.Background(), b, nil)), "heavy=not_evaluable/timeout heavy_or_unknown=not_evaluable/timeout light=not_evaluable/timeout"; got != want {
		t.Fatalf("budget: %s, want %s", got, want)
	}
	only := func(id string) func(*bundle.Control) bool { return func(c *bundle.Control) bool { return c.ID == id } }
	b = dbBindings(t, `{"storage_encrypted": true, "kms_key_id": {"$unknown": true}}`)
	if got, want := states(comp.Evaluate(context.Background(), b, only("heavy_or_unknown"))), "heavy_or_unknown=not_evaluable/timeout"; got != want {
		t.Fatalf("absorbed interrupt: %s, want %s", got, want)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if got, want := states(comp.Evaluate(canceled, b, only("light"))), "light=not_evaluable/timeout"; got != want {
		t.Fatalf("canceled caller: %s, want %s", got, want)
	}
}

// TestEvaluateAbsorbedUnresolved: an action missing from the catalog is
// unresolved; CEL absorbing that error (err || true) is still unresolved.
func TestEvaluateAbsorbedUnresolved(t *testing.T) {
	cs := []bundle.Control{dbControl("absorbed",
		`iam.grants(iam.parse(resource.kms_key_id).statements[0], "s3:nosuchaction") || true`, "kms_key_id")}
	comp, _, err := New(Options{PerResourceBudget: time.Second}).Load(cs, awsSubset(t), Content{IAMCatalog: fixtureCatalog(t)})
	if err != nil {
		t.Fatal(err)
	}
	b := dbBindings(t, `{"kms_key_id": "{\"Statement\":{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:getobject\",\"Resource\":\"*\"}}"}`)
	if got, want := states(comp.Evaluate(context.Background(), b, nil)), "absorbed=not_evaluable/unresolved"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

// TestEvaluateClassify pins what fixtures cannot reach: sentinels, a decided
// result racing the deadline, env scope and paths without map keys.
func TestEvaluateClassify(t *testing.T) {
	live := context.Background()
	expired, cancel := context.WithCancel(live)
	cancel()
	reads := []Read{{Var: varResource, Path: "kms_key_id"}, {Var: varResource, Path: "tags"}, {Var: varPrior, Path: "tags"}}
	trail := func(v string, qs ...string) *types.AttributeTrail {
		a := types.NewAttributeTrail(v)
		for _, q := range qs {
			a = types.QualifyAttribute(a, q)
		}
		return a
	}
	unk := func(ts ...*types.AttributeTrail) *types.Unknown {
		var u *types.Unknown
		for i, tr := range ts {
			u = types.MergeUnknowns(u, types.NewUnknown(int64(i+1), tr))
		}
		return u
	}
	cost := interpreter.EvalCancelledError{Cause: interpreter.CostLimitExceeded}
	for _, tc := range []struct {
		name     string
		ctx      context.Context
		val      ref.Val
		err      error
		envKnown bool
		want     string
	}{
		{"pass racing the deadline", expired, types.True, nil, true, "pass/ []"},
		{"unknown after the deadline", expired, unk(trail("resource", "kms_key_id")), nil, true, "not_evaluable/timeout []"},
		{"error after the deadline", expired, types.NewErr("x"), types.NewErr("x").(error), true, "not_evaluable/timeout []"},
		{"cost limit beats the deadline", expired, nil, cost, true, "not_evaluable/limit []"},
		{"unresolved sentinel", live, nil, types.WrapErr(lib.ErrUnresolved).(error), true, "not_evaluable/unresolved []"},
		{"limit sentinel", live, nil, types.WrapErr(lib.ErrLimit).(error), true, "not_evaluable/limit []"},
		{"invalid sentinel", live, nil, types.WrapErr(lib.ErrInvalid).(error), true, "not_evaluable/type_error []"},
		{"sentinel text is not the sentinel", live, nil, types.NewErr("%s", lib.ErrUnresolved.Error()).(error), true, "not_evaluable/type_error []"},
		{"nil value", live, nil, nil, true, "not_evaluable/type_error []"},
		{"map key never output", live, unk(trail("resource", "tags", "BOBTHECORP-MARKER-1")), nil, true, "unknown/ [tags]"},
		{"element index dropped", live, unk(types.QualifyAttribute(trail("prior", "tags"), int64(0))), nil, true, "unknown/ [tags]"},
		{"whole variable", live, unk(trail("resource")), nil, true, "unknown/ [kms_key_id tags]"},
		{"unrelated trail is the variable", live, unk(trail("resource", "arn")), nil, true, "unknown/ [resource]"},
		{"env unknown is untrusted scope", live, unk(trail("env"), trail("resource", "kms_key_id")), nil, false, "not_evaluable/scope_untrusted []"},
		{"provider keeps its prefix", live, unk(trail("provider", "account_id")), nil, false, "unknown/ [provider.account_id]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, ec, paths := classify(tc.ctx, tc.val, tc.err, reads, nil, tc.envKnown)
			if got := st.String() + "/" + string(ec) + " [" + strings.Join(paths, " ") + "]"; got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

// TestUnknownPathsMapCut: an attribute-shaped constant key below
// a map attribute, top level or in a nested block, or below a map-nested
// block, is cut at the map; an object attribute keeps its step, a dynamic
// value is cut like a map, and a step the schema lacks is cut (fail
// closed). Without a schema only the first step is kept.
func TestUnknownPathsMapCut(t *testing.T) {
	str := tftypes.String
	b := &tfprotov5.SchemaBlock{
		Attributes: []*tfprotov5.SchemaAttribute{
			{Name: "tags", Type: tftypes.Map{ElementType: str}, Optional: true},
			{Name: "settings", Type: tftypes.Object{AttributeTypes: map[string]tftypes.Type{
				"owner_key": str, "labels": tftypes.Map{ElementType: str}}}, Optional: true},
			{Name: "rules", Type: tftypes.List{ElementType: tftypes.Map{ElementType: tftypes.Object{
				AttributeTypes: map[string]tftypes.Type{"port": tftypes.Number}}}}, Optional: true},
			{Name: "extra", Type: tftypes.DynamicPseudoType, Optional: true},
		},
		BlockTypes: []*tfprotov5.SchemaNestedBlock{{TypeName: "rule", Nesting: tfprotov5.SchemaNestedBlockNestingModeList,
			Block: &tfprotov5.SchemaBlock{Attributes: []*tfprotov5.SchemaAttribute{
				{Name: "labels", Type: tftypes.Map{ElementType: str}, Optional: true},
				{Name: "mode", Type: tftypes.Object{AttributeTypes: map[string]tftypes.Type{"owner_key": str}}, Optional: true},
			}}}, {TypeName: "mrules", Nesting: tfprotov5.SchemaNestedBlockNestingModeMap,
			Block: &tfprotov5.SchemaBlock{Attributes: []*tfprotov5.SchemaAttribute{{Name: "port", Type: tftypes.Number, Optional: true}}}}},
	}
	for path, want := range map[string]string{
		"tags.owner_key":            "tags",
		"tags":                      "tags",
		"rule.labels.owner_key":     "rule.labels",
		"settings.owner_key":        "settings.owner_key",
		"settings.labels.owner_key": "settings.labels",
		"rule.mode.owner_key":       "rule.mode.owner_key",
		"rules.owner_key.port":      "rules",
		"extra.owner_key":           "extra",
		"mrules.owner_key.port":     "mrules",
		"mrules":                    "mrules",
		"no_such.owner_key":         "no_such",
		"rule.no_such.owner_key":    "rule",
		"settings.no_such.x":        "settings",
	} {
		trail := types.NewAttributeTrail(varResource)
		for _, s := range strings.Split(path, ".") {
			trail = types.QualifyAttribute(trail, s)
		}
		u := types.NewUnknown(1, trail)
		got := unknownPaths(u, []Read{{Var: varResource, Path: path}}, b)
		if !slices.Equal(got, []string{want}) {
			t.Errorf("%s: %v, want [%s]", path, got, want)
		}
		first, _, _ := strings.Cut(path, ".")
		if got := unknownPaths(u, []Read{{Var: varResource, Path: path}}, nil); !slices.Equal(got, []string{first}) {
			t.Errorf("%s without a schema: %v, want [%s]", path, got, first)
		}
	}
}

// TestEvaluateIsolation: errors never abort other controls; keep, kind and type
// select controls; a type missing from the schema is no_such_attribute.
func TestEvaluateIsolation(t *testing.T) {
	widget := dbControl("widget", "resource.arn == ''", "arn")
	widget.ResourceType = "aws_bobthecorp_widget"
	guard := *testControl(bundle.KindDeletionGuard, "", "prior.storage_encrypted == true", "storage_encrypted")
	guard.ID, guard.Version, guard.ResourceType, guard.Action = "guard", "1.0.0", "aws_db_instance", bundle.ActionDeny
	cs := []bundle.Control{
		dbControl("broken", "resource.no_such == true", "no_such"),
		dbControl("encrypted", "resource.storage_encrypted == true", "storage_encrypted"),
		dbControl("skipped", "resource.storage_encrypted == false", "storage_encrypted"),
		widget, guard,
	}
	comp, _, err := New(testOpts).Load(cs, awsSubset(t), Content{})
	if err != nil {
		t.Fatal(err)
	}
	keep := func(c *bundle.Control) bool { return c.ID != "skipped" }
	b := dbBindings(t, `{"storage_encrypted": true}`)
	if got, want := states(comp.Evaluate(context.Background(), b, keep)), "broken=not_evaluable/no_such_attribute encrypted=pass/"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	b.Type = "aws_bobthecorp_widget"
	if got, want := states(comp.Evaluate(context.Background(), b, nil)), "widget=not_evaluable/no_such_attribute"; got != want {
		t.Fatalf("missing type: got %s, want %s", got, want)
	}
	b = dbBindings(t, `null`)
	b.Kind, b.Prior = bundle.KindDeletionGuard, dbBindings(t, `{"storage_encrypted": false}`).Resource
	if got, want := states(comp.Evaluate(context.Background(), b, nil)), "guard=fail/"; got != want {
		t.Fatalf("deletion guard: got %s, want %s", got, want)
	}
}

// TestMissingReadBelowMap: a map key is data, but the value type below it is
// still the schema's; a field missing from a map(object) value is missing,
// and so is an in test of it on the object.
func TestMissingReadBelowMap(t *testing.T) {
	obj := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"port": tftypes.Number}}
	b := &tfprotov5.SchemaBlock{Attributes: []*tfprotov5.SchemaAttribute{
		{Name: "rules", Type: tftypes.Map{ElementType: obj}, Optional: true},
		{Name: "tags", Type: tftypes.Map{ElementType: tftypes.String}, Optional: true},
	}}
	for path, want := range map[string]bool{
		"rules": false, "rules.k": false, "rules.k.port": false, "rules.k.no_such": true,
		"tags.owner": false, "tags.owner.x": true,
	} {
		if got := missingRead(b, []Read{{Var: "resource", Path: path}}); got != want {
			t.Errorf("%s: missing = %v, want %v", path, got, want)
		}
	}
	ch, err := check(`!("no_such" in resource.rules.k) && resource.rules.all(k, "port" in resource.rules[k])`)
	if diagCode(err) != "control_dynamic_access" { // a dynamic map key
		t.Fatalf("dynamic key: %v %v", ch, err)
	}
	if ch, err = check(`!("no_such" in resource.rules.k)`); err != nil {
		t.Fatal(err)
	}
	reads, err := schemaReads(b, ch)
	if err != nil || !missingRead(b, reads) {
		t.Fatalf("in test on a map(object) value: reads %v, err %v", reads, err)
	}
}

// TestLoadIAMCatalogMissing: a bundle with an iam.* control and
// no action catalog is rejected iam_catalog_missing; without IAM controls it loads.
func TestLoadIAMCatalogMissing(t *testing.T) {
	plain := dbControl("plain", "resource.storage_encrypted", "storage_encrypted")
	for _, expr := range []string{
		`iam.parse(resource.kms_key_id).statements.all(s, s.effect == "Deny")`,
		`iam.grants({"actions": ["*"]}, "s3:getobject") || resource.storage_encrypted`,
	} {
		cs := []bundle.Control{plain, dbControl("iam", expr, "kms_key_id", "storage_encrypted")}
		if _, _, err := New(testOpts).Load(cs, awsSubset(t), Content{}); diagCode(err) != "iam_catalog_missing" {
			t.Fatalf("%s: %v, want iam_catalog_missing", expr, err)
		}
		if _, _, err := New(testOpts).Load(cs, awsSubset(t), Content{IAMCatalog: fixtureCatalog(t)}); err != nil {
			t.Fatalf("%s with a catalog: %v", expr, err)
		}
	}
	if _, _, err := New(testOpts).Load([]bundle.Control{plain}, awsSubset(t), Content{}); err != nil {
		t.Fatalf("no IAM control: %v", err)
	}
}

func fixtureCatalog(t *testing.T) *iampolicy.Catalog {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/iam/actions-fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	cat, err := iampolicy.LoadCatalog(raw)
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

// TestPriorComputedOnlyDecided: a deny deletion guard reading the
// Computed-only prior.arn loads and decides from stored state.
func TestPriorComputedOnlyDecided(t *testing.T) {
	guard := *testControl(bundle.KindDeletionGuard, "", "prior.arn != ''", "arn")
	guard.ID, guard.Version, guard.ResourceType, guard.Action = "guard", "1.0.0", "aws_db_instance", bundle.ActionDeny
	comp, _, err := New(testOpts).Load([]bundle.Control{guard}, awsSubset(t), Content{})
	if err != nil {
		t.Fatal(err)
	}
	for prior, want := range map[string]string{
		`{"arn": "arn:aws:rds:eu-west-1:111111111111:db:bobthecorp"}`: "guard=pass/",
		`{"arn": ""}`: "guard=fail/",
	} {
		b := dbBindings(t, `null`)
		b.Kind, b.Prior = bundle.KindDeletionGuard, dbBindings(t, prior).Resource
		if got := states(comp.Evaluate(context.Background(), b, nil)); got != want {
			t.Fatalf("prior %s: got %s, want %s", prior, got, want)
		}
	}
}

// TestNewDocCacheBytes: Options.DocCacheBytes reaches the process
// document cache. Two controls read one new document: under the default cap
// the second is a cache hit; under a cap below one entry both decode.
func TestNewDocCacheBytes(t *testing.T) {
	t.Cleanup(func() { New(Options{DocCacheBytes: lib.DefaultDocCacheBytes}) })
	cs := []bundle.Control{
		dbControl("a", `json.path(resource.kms_key_id, "/a") == 1`, "kms_key_id"),
		dbControl("b", `json.path(resource.kms_key_id, "/b") == null`, "kms_key_id"),
	}
	decodes := func(capBytes int) int {
		comp, _, err := New(Options{PerResourceBudget: time.Second, DocCacheBytes: capBytes}).Load(cs, awsSubset(t), Content{})
		if err != nil {
			t.Fatal(err)
		}
		doc := fmt.Sprintf(`{\"a\": 1, \"n\": %d}`, time.Now().UnixNano()) // a document no other run decoded
		before := lib.DocDecodes()
		if got, want := states(comp.Evaluate(context.Background(), dbBindings(t, `{"kms_key_id": "`+doc+`"}`), nil)), "a=pass/ b=pass/"; got != want {
			t.Fatalf("cap %d: %s, want %s", capBytes, got, want)
		}
		return lib.DocDecodes() - before
	}
	if n := decodes(lib.DefaultDocCacheBytes); n != 1 {
		t.Fatalf("default cap: %d decodes, want 1", n)
	}
	if n := decodes(1); n != 2 {
		t.Fatalf("cap 1: %d decodes, want 2 (nothing cached)", n)
	}
}
