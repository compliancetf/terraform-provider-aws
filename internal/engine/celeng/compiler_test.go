package celeng

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
)

type respSource struct {
	*tfprotov5.GetProviderSchemaResponse
}

func (s respSource) Resource(typ string) (*tfprotov5.Schema, bool) {
	x, ok := s.ResourceSchemas[typ]
	return x, ok
}

func (s respSource) DataSource(typ string) (*tfprotov5.Schema, bool) {
	x, ok := s.DataSourceSchemas[typ]
	return x, ok
}

func (s respSource) EphemeralResource(typ string) (*tfprotov5.Schema, bool) {
	x, ok := s.EphemeralResourceSchemas[typ]
	return x, ok
}

// TestCompiler: celeng as the engine.Compiler maps the 0B activation onto
// one control and its outcome back; it fails closed without schemas, on a
// load error and on a type the upstream lacks.
func TestCompiler(t *testing.T) {
	src := respSource{awsSubset(t)}
	sc, _ := src.Resource("aws_db_instance")
	typ := sc.ValueType().(tftypes.Object)
	with := func(attr string, v tftypes.Value) tftypes.Value {
		m := map[string]tftypes.Value{}
		for n, at := range typ.AttributeTypes {
			m[n] = tftypes.NewValue(at, nil)
		}
		m[attr] = v
		return tftypes.NewValue(typ, m)
	}
	enc := dbControl("enc", "resource.storage_encrypted == true", "storage_encrypted")
	// A minute: the verdicts below do not test the budget; the
	// spent-deadline case sets its own.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cc := NewCompiler(src)
	if id := cc.ID(); id != "cel" {
		t.Errorf("ID = %q, want cel", id)
	}
	p, err := cc.Compile(&enc, typ)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		v    tftypes.Value
		want engine.State
	}{
		{with("storage_encrypted", tftypes.NewValue(tftypes.Bool, true)), engine.Pass},
		{with("storage_encrypted", tftypes.NewValue(tftypes.Bool, false)), engine.Fail},
		{with("storage_encrypted", tftypes.NewValue(tftypes.Bool, tftypes.UnknownValue)), engine.Unknown},
	} {
		if got := p.Eval(ctx, &engine.Activation{Resource: c.v, Op: engine.OpCreate}); got.State != c.want {
			t.Errorf("got %+v, want %v", got, c.want)
		}
	}
	got := p.Eval(ctx, &engine.Activation{Resource: with("storage_encrypted", tftypes.NewValue(tftypes.Bool, tftypes.UnknownValue))})
	if len(got.UnknownPaths) != 1 || got.UnknownPaths[0] != "storage_encrypted" {
		t.Errorf("unknown paths %v", got.UnknownPaths)
	}
	cfg := dbControl("cfg", "config.storage_encrypted == true", "storage_encrypted")
	cfg.PresenceMode = bundle.PresenceConfigured
	if p, err := cc.Compile(&cfg, typ); err != nil {
		t.Fatal(err)
	} else if got := p.Eval(ctx, &engine.Activation{Config: with("storage_encrypted", tftypes.NewValue(tftypes.Bool, true))}); got.State != engine.Pass {
		t.Errorf("configured: got %+v, want pass", got)
	}

	if _, err := NewCompiler(nil).Compile(&enc, typ); err == nil {
		t.Error("compiled without a schema source")
	}
	bad := dbControl("bad", "config.storage_encrypted == true", "storage_encrypted") // effective may not read config
	_, err1 := cc.Compile(&bad, typ)
	_, err2 := cc.Compile(&bad, typ)
	if err1 == nil || err1 != err2 { //nolint:errorlint // identity: the error is kept, not loaded again
		t.Errorf("load error %v, again %v: want the same kept error", err1, err2)
	}
	gone := dbControl("gone", "resource.storage_encrypted == true", "storage_encrypted")
	gone.ResourceType = "aws_no_such_type"
	var ce *engine.CompileError
	if _, err := cc.Compile(&gone, typ); !errors.As(err, &ce) || ce.Class != engine.ErrNoSuchAttribute {
		t.Errorf("missing type: got %v, want a no_such_attribute CompileError", err)
	}
	path := dbControl("path", "resource.no_such_attr == true", "no_such_attr")
	if _, err := cc.Compile(&path, typ); !errors.As(err, &ce) || ce.Class != engine.ErrNoSuchAttribute {
		t.Errorf("missing path: got %v, want a no_such_attribute CompileError", err)
	}

	// The lifecycle owns the per-resource deadline (noBudget); without one
	// Eval applies defaultBudget, and a spent deadline is timeout.
	spent, cancelSpent := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelSpent()
	if got := p.Eval(spent, &engine.Activation{Resource: with("storage_encrypted", tftypes.NewValue(tftypes.Bool, true))}); got.State != engine.NotEvaluable || got.Err != engine.ErrTimeout {
		t.Errorf("spent deadline: got %+v, want not_evaluable/timeout", got)
	}
	// A program whose (kind, type) the Compiled lacks yields no result.
	odd := *p.(*compiledProgram) //nolint:forcetypeassert // Compile returns *compiledProgram
	odd.typ = "aws_s3_bucket"
	if got := odd.Eval(ctx, &engine.Activation{}); got.State != engine.NotEvaluable || got.Err != engine.ErrUnresolved {
		t.Errorf("no result: got %+v, want not_evaluable/unresolved", got)
	}
}

// TestCompilerContentDigest: the Compiler keys the prefilter memo
// by the content digest it is given, not by the bundle digests. One set under
// two coverable maps has two content digests; programs compiled under them
// never share a memo entry, even through one memo.
func TestCompilerContentDigest(t *testing.T) {
	set, b := swapSet(t, "a")
	ctl := b.Controls[0]
	da := set.ContentDigest(nil)
	db := set.ContentDigest(map[string][]string{ctl.ID: {"grant"}})
	if da == db || da == set.Digest() {
		t.Fatalf("content digests %s %s, bundle digest %s: want three distinct", da, db, set.Digest())
	}
	src := respSource{awsSubset(t)}
	compile := func(d string) *Compiled {
		p, err := NewCompilerFor(src, set, d).Compile(&ctl, nil)
		if err != nil {
			t.Fatal(err)
		}
		c := p.(*compiledProgram).c //nolint:forcetypeassert // Compile returns *compiledProgram
		if c.digest != d {
			t.Fatalf("memo key digest %q, want the content digest %q", c.digest, d)
		}
		return c
	}
	a, bc := compile(da), compile(db)
	in := dbBindings(t, `{"kms_key_id": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"kms:decrypt\",\"Resource\":\"*\"}]}"}`)
	p := &a.progs(t, ctl.Kind, ctl.ResourceType)[0]
	ka, okA := a.memoKey(p, in)
	kb, okB := bc.memoKey(p, in)
	if !okA || !okB || ka == kb {
		t.Fatalf("memo keys %x (%v), %x (%v): want two distinct usable keys", ka, okA, kb, okB)
	}
	if rs := a.Evaluate(context.Background(), in, nil); len(rs) != 1 || rs[0].State != engine.Pass || rs[0].Memoized {
		t.Fatalf("a: %+v", rs)
	}
	bc.memo = a.memo // share a's entry: b must still miss it
	if rs := bc.Evaluate(context.Background(), in, nil); len(rs) != 1 || rs[0].State != engine.Pass || rs[0].Memoized {
		t.Fatalf("b reused a's memo entry: %+v", rs)
	}
}

// TestCheckCatalogs: a control that calls iam.* needs its bundle's
// catalog, decided from the parsed expression, so a control that fails a
// later load check (here control_reads_missing) is still rejected.
func TestCheckCatalogs(t *testing.T) {
	cat, err := iampolicy.LoadCatalog(mustRead(t, "../../../testdata/iam/actions-fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	ctl := func(expr string, reads ...string) bundle.Control {
		return bundle.Control{ID: "c", Kind: bundle.KindResource, ResourceType: "aws_iam_policy", Reads: reads, Expr: &expr}
	}
	iamExpr := `iam.parse(resource.policy).statements.all(s, !iam.grants(s, "kms:decrypt"))`
	for _, tc := range []struct {
		name string
		c    bundle.Control
		cat  *iampolicy.Catalog
		want bool // iam_catalog_missing
	}{
		{"iam without catalog", ctl(iamExpr, "policy"), nil, true},
		{"iam, wrong reads, without catalog", ctl(iamExpr, "description"), nil, true},
		{"root-qualified iam", ctl(`.iam.parse(resource.policy).statements.size() == 0`, "policy"), nil, true},
		{"iam with catalog", ctl(iamExpr, "policy"), cat, false},
		{"no iam call", ctl(`resource.policy != "iam.parse"`, "policy"), nil, false},
		{"does not parse", ctl(`iam.parse(`, "policy"), nil, false},
	} {
		err := CheckCatalogs([]bundle.Control{tc.c}, func(*bundle.Control) *iampolicy.Catalog { return tc.cat })
		var d *LoadDiag
		if got := errors.As(err, &d) && d.Code == "iam_catalog_missing"; got != tc.want || !got && err != nil {
			t.Errorf("%s: %v, want iam_catalog_missing %v", tc.name, err, tc.want)
		}
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// countingSource counts schema lookups.
type countingSource struct {
	respSource
	n *int
}

func (s countingSource) Resource(typ string) (*tfprotov5.Schema, bool) {
	*s.n++
	return s.respSource.Resource(typ)
}

// TestCompilerPaths: declared reads below a map attribute or a
// map-nested block are cut at the map, a declared read the schema lacks is
// cut to its first step, an attribute read is kept, a compiled control's
// schema is reused, and with no schema only first steps are kept.
func TestCompilerPaths(t *testing.T) {
	n := 0
	cc := NewCompiler(countingSource{respSource{awsSubset(t)}, &n})
	c := dbControl("tag", `resource.tags["owner_key"] == "x" && resource.storage_encrypted`, "storage_encrypted", "tags.owner_key")
	if _, err := cc.Compile(&c, nil); err != nil {
		t.Fatal(err)
	}
	before := n
	if got, want := cc.Paths(&c), []string{"storage_encrypted", "tags"}; !slices.Equal(got, want) {
		t.Errorf("Paths = %v, want %v", got, want)
	}
	if n != before {
		t.Errorf("Paths looked up %d schemas after Compile", n-before)
	}
	if got, want := NewCompiler(nil).Paths(&c), []string{"storage_encrypted", "tags"}; !slices.Equal(got, want) {
		t.Errorf("no schema: Paths = %v, want %v", got, want)
	}
	// An unused declared read the schema lacks only warns at Load.
	un := dbControl("un", `resource.storage_encrypted`, "no_such.owner_key", "storage_encrypted")
	if _, err := cc.Compile(&un, nil); err != nil {
		t.Fatal(err)
	}
	if got, want := cc.Paths(&un), []string{"no_such", "storage_encrypted"}; !slices.Equal(got, want) {
		t.Errorf("unresolved read: Paths = %v, want %v", got, want)
	}
	// A declared read below a map-nested block, from a type compile never saw.
	mb := &tfprotov5.SchemaBlock{BlockTypes: []*tfprotov5.SchemaNestedBlock{{TypeName: "mrules",
		Nesting: tfprotov5.SchemaNestedBlockNestingModeMap, Block: &tfprotov5.SchemaBlock{
			Attributes: []*tfprotov5.SchemaAttribute{{Name: "port", Type: tftypes.Number, Optional: true}}}}}}
	src := respSource{&tfprotov5.GetProviderSchemaResponse{ResourceSchemas: map[string]*tfprotov5.Schema{"aws_x": {Block: mb}}}}
	mc := dbControl("m", `true`, "mrules.k.port")
	mc.ResourceType = "aws_x"
	if got, want := NewCompiler(src).Paths(&mc), []string{"mrules"}; !slices.Equal(got, want) {
		t.Errorf("map-nested block: Paths = %v, want %v", got, want)
	}
}
