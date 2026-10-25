package celeng

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
)

// TestSelector: an exception selector binds type beside the control
// variables, maps the CEL outcome like a control, and never passes on a
// type outside the schemas or past the deadline. internal/exceptions holds
// the selector oracle (TestException*).
func TestSelector(t *testing.T) {
	src := respSource{awsSubset(t)}
	sc, _ := src.Resource("aws_db_instance")
	typ := sc.ValueType().(tftypes.Object)
	vals := map[string]tftypes.Value{}
	for n, at := range typ.AttributeTypes {
		vals[n] = tftypes.NewValue(at, nil)
	}
	vals["storage_encrypted"] = tftypes.NewValue(tftypes.Bool, tftypes.UnknownValue)
	a := &engine.Activation{Resource: tftypes.NewValue(typ, vals), Op: engine.OpCreate}
	// A long deadline: these check verdicts, not the 50 ms budget under load.
	long, cancelLong := context.WithTimeout(context.Background(), time.Minute)
	defer cancelLong()
	for _, c := range []struct {
		expr, typ string
		want      engine.State
		class     engine.ErrClass
	}{
		{"type == 'aws_db_instance' && op == 'create'", "aws_db_instance", engine.Pass, ""},
		{"type == 'aws_s3_bucket'", "aws_db_instance", engine.Fail, ""},
		{"resource.storage_encrypted", "aws_db_instance", engine.Unknown, ""},
		{"resource.engine.size() > 1", "aws_db_instance", engine.NotEvaluable, engine.ErrTypeError},
		{"true", "aws_nope", engine.NotEvaluable, engine.ErrNoSuchAttribute},
	} {
		s, err := CompileSelector(c.expr)
		if err != nil {
			t.Fatalf("%q: %v", c.expr, err)
		}
		if got := s.Eval(long, src, bundle.KindResource, c.typ, a); got.State != c.want || got.Err != c.class {
			t.Errorf("%q on %s: %+v, want %s/%s", c.expr, c.typ, got, c.want, c.class)
		}
	}
	// One compiled selector, many concurrent evaluations (go test -race).
	shared, _ := CompileSelector("type == 'aws_db_instance' && resource.storage_encrypted")
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if got := shared.Eval(long, src, bundle.KindResource, "aws_db_instance", a); got.State != engine.Unknown {
				t.Errorf("concurrent: %+v", got)
			}
		})
	}
	wg.Wait()
	s, _ := CompileSelector("true")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := s.Eval(ctx, src, bundle.KindResource, "aws_db_instance", a); got.State != engine.NotEvaluable || got.Err != engine.ErrTimeout {
		t.Errorf("spent budget: %+v", got)
	}
	if got := s.Eval(long, nil, bundle.KindDataSource, "aws_db_instance", a); got.Err != engine.ErrNoSuchAttribute {
		t.Errorf("no schemas: %+v", got)
	}
	for expr, want := range map[string]string{
		"type ==": "does not compile at 1:8", "'x'": "output type is not bool",
		"iam.grants(resource, 's3:GetObject')": "iam.* is not allowed in a selector",
	} {
		if _, err := CompileSelector(expr); err == nil || err.Error() != want {
			t.Errorf("%q: %v, want %q", expr, err, want)
		}
	}
}

// TestSelectorCaps: the v0.1 input caps count every
// list, set, tuple and map element of a bound value, every string and the
// container depth; at the cap the selector evaluates, over it the outcome is
// not_evaluable/limit.
func TestSelectorCaps(t *testing.T) {
	var keyed func(n int) tftypes.Value
	strs := func(n int) tftypes.Value {
		es := make([]tftypes.Value, n)
		for i := range es {
			es[i] = tftypes.NewValue(tftypes.String, "a")
		}
		return tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, es)
	}
	half := strs(selectorMaxElements / 2)
	m := func(a, b tftypes.Value) tftypes.Value {
		typ := tftypes.Map{ElementType: tftypes.Set{ElementType: tftypes.String}}
		return tftypes.NewValue(typ, map[string]tftypes.Value{"a": a, "b": b})
	}
	str := func(n int) tftypes.Value { return tftypes.NewValue(tftypes.String, strings.Repeat("a", n)) }
	// nested is d containers deep, alternating list and object, around a string.
	nested := func(d int) tftypes.Value {
		v := tftypes.NewValue(tftypes.String, "a")
		for i := range d {
			if i%2 == 0 {
				v = tftypes.NewValue(tftypes.List{ElementType: v.Type()}, []tftypes.Value{v})
			} else {
				v = tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{"x": v.Type()}},
					map[string]tftypes.Value{"x": v})
			}
		}
		return v
	}
	keyed = func(n int) tftypes.Value {
		return tftypes.NewValue(tftypes.Map{ElementType: tftypes.String},
			map[string]tftypes.Value{strings.Repeat("k", n): tftypes.NewValue(tftypes.String, "v")})
	}
	for _, c := range []struct {
		name string
		v    tftypes.Value
		over bool
	}{
		{"elements at cap", strs(selectorMaxElements), false},
		{"elements over cap", strs(selectorMaxElements + 1), true},
		{"nested map counts its entries", m(half, half), true}, // 2 + 10,000
		{"string at cap", str(selectorMaxString), false},
		{"string over cap", str(selectorMaxString + 1), true},
		{"unknown", tftypes.NewValue(tftypes.String, tftypes.UnknownValue), false},
		{"null", tftypes.NewValue(tftypes.String, nil), false},
		{"zero value", tftypes.Value{}, false},
		{"map key at cap", keyed(selectorMaxString), false},
		{"map key over cap", keyed(selectorMaxString + 1), true},
		{"nested map key over cap", tftypes.NewValue(tftypes.Map{ElementType: keyed(1).Type()},
			map[string]tftypes.Value{"a": keyed(selectorMaxString + 1)}), true},
		{"depth at cap", nested(selectorMaxDepth), false},
		{"depth over cap", nested(selectorMaxDepth + 1), true},
		{"depth far over cap", nested(2000), true},
	} {
		if got := overCap(c.v); got != c.over {
			t.Errorf("%s: overCap %v, want %v", c.name, got, c.over)
		}
	}
	src := respSource{awsSubset(t)}
	sc, _ := src.Resource("aws_db_instance")
	typ := sc.ValueType().(tftypes.Object)
	vals := map[string]tftypes.Value{}
	for n, at := range typ.AttributeTypes {
		vals[n] = tftypes.NewValue(at, nil)
	}
	s, _ := CompileSelector("true")
	// A long deadline: at-cap inputs are large; this checks caps, not the 50 ms budget.
	long, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	eval := func(v tftypes.Value) []engine.Outcome {
		var out []engine.Outcome
		for _, a := range []*engine.Activation{{Resource: v}, {Config: v}, {Prior: v}} {
			out = append(out, s.Eval(long, src, bundle.KindResource, "aws_db_instance", a))
		}
		return out
	}
	for name, set := range map[string]func(){
		"string":  func() { vals["engine"] = str(selectorMaxString + 1) },
		"map key": func() { vals["tags"] = keyed(selectorMaxString + 1) },
	} {
		for k, at := range typ.AttributeTypes {
			vals[k] = tftypes.NewValue(at, nil)
		}
		set()
		for i, got := range eval(tftypes.NewValue(typ, vals)) { // resource, config, prior
			if got.State != engine.NotEvaluable || got.Err != engine.ErrLimit {
				t.Errorf("%s over cap in variable %d: %+v", name, i, got)
			}
		}
	}
	for i, got := range eval(nested(selectorMaxDepth + 1)) { // deep values fail closed
		if got.State != engine.NotEvaluable || got.Err != engine.ErrLimit {
			t.Errorf("depth over cap in variable %d: %+v", i, got)
		}
	}
	vals["engine"] = tftypes.NewValue(tftypes.String, nil)
	vals["tags"] = keyed(selectorMaxString)
	for i, got := range eval(tftypes.NewValue(typ, vals)) {
		if got.State != engine.Pass {
			t.Errorf("map key at cap in variable %d: %+v", i, got)
		}
	}
}
