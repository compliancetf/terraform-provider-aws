package celeng

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/engine/lib"
)

func companionSchema() *tfprotov5.Schema {
	return &tfprotov5.Schema{Block: &tfprotov5.SchemaBlock{
		Attributes: []*tfprotov5.SchemaAttribute{
			{Name: "bucket", Type: tftypes.String, Required: true},
			{Name: "tags", Type: tftypes.Map{ElementType: tftypes.String}, Optional: true},
		},
		BlockTypes: []*tfprotov5.SchemaNestedBlock{{
			TypeName: "versioning_configuration", Nesting: tfprotov5.SchemaNestedBlockNestingModeList,
			Block: &tfprotov5.SchemaBlock{Attributes: []*tfprotov5.SchemaAttribute{
				{Name: "status", Type: tftypes.String, Required: true},
				{Name: "mfa_delete", Type: tftypes.String, Optional: true},
			}},
		}},
	}}
}

// TestCompanionReads: a companion_expr is analyzed as a resource expr over
// the companion variable; a dynamic access or another variable fails.
func TestCompanionReads(t *testing.T) {
	for _, tc := range []struct {
		name, expr string
		want       []string
		code       string
	}{
		{"select chain", "companion.versioning_configuration[0].status == 'Enabled'", []string{"versioning_configuration.status"}, ""},
		{"comprehension", "companion.versioning_configuration.exists(v, v.status == 'Enabled' && v.mfa_delete != 'Enabled')",
			[]string{"versioning_configuration.mfa_delete", "versioning_configuration.status"}, ""},
		{"map key", `companion.tags["Owner"] != "" || has(companion.bucket)`, []string{"bucket", "tags"}, ""},
		{"dynamic", "dyn(companion.versioning_configuration)[0].status == 'Enabled'", nil, "control_dynamic_access"},
		{"whole object", "companion.versioning_configuration[0] == {'status': 'Enabled'}", nil, "control_dynamic_access"},
		{"other variable", "resource.bucket == 'x'", nil, "control_expr"},
		{"not bool", "size(companion.tags)", nil, "control_expr"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CompanionReads(tc.expr, companionSchema())
			var d *LoadDiag
			switch {
			case tc.code != "":
				if !errors.As(err, &d) || d.Code != tc.code {
					t.Fatalf("err = %v, want %s", err, tc.code)
				}
			case err != nil:
				t.Fatal(err)
			case !slices.Equal(got, tc.want):
				t.Errorf("reads %q, want %q", got, tc.want)
			}
		})
	}
}

// recorder wraps a value so evaluation records each attribute path it
// selects (a map key is a step, a list index is not) and each container it
// sizes, iterates or tests membership in.
type recorder struct{ seen map[string]bool }

func (r recorder) wrap(v ref.Val, path string) ref.Val {
	switch x := v.(type) {
	case traits.Mapper:
		return recMap{x, r, path}
	case traits.Lister:
		return recList{x, r, path}
	}
	return v
}

func (r recorder) step(path string, k ref.Val) string {
	s, _ := k.Value().(string)
	if path == "" {
		return s
	}
	return path + "." + s
}

type recMap struct {
	traits.Mapper
	r    recorder
	path string
}

func (m recMap) Get(k ref.Val) ref.Val {
	p := m.r.step(m.path, k)
	m.r.seen[p] = true
	return m.r.wrap(m.Mapper.Get(k), p)
}

func (m recMap) Find(k ref.Val) (ref.Val, bool) {
	p := m.r.step(m.path, k)
	m.r.seen[p] = true
	v, ok := m.Mapper.Find(k)
	if !ok {
		return v, ok
	}
	return m.r.wrap(v, p), ok
}

func (m recMap) Contains(k ref.Val) ref.Val {
	m.r.seen[m.r.step(m.path, k)] = true
	return m.Mapper.Contains(k)
}

func (m recMap) Size() ref.Val { m.r.seen[m.path] = true; return m.Mapper.Size() }

func (m recMap) Iterator() traits.Iterator { m.r.seen[m.path] = true; return m.Mapper.Iterator() }

type recList struct {
	traits.Lister
	r    recorder
	path string
}

func (l recList) Get(i ref.Val) ref.Val { return l.r.wrap(l.Lister.Get(i), l.path) }

func (l recList) Size() ref.Val { l.r.seen[l.path] = true; return l.Lister.Size() }

func (l recList) Contains(v ref.Val) ref.Val { l.r.seen[l.path] = true; return l.Lister.Contains(v) }

func (l recList) Iterator() traits.Iterator {
	l.r.seen[l.path] = true
	return recIter{l.Lister.Iterator(), l.r, l.path}
}

type recIter struct {
	traits.Iterator
	r    recorder
	path string
}

func (it recIter) Next() ref.Val { return it.r.wrap(it.Iterator.Next(), it.path) }

// TestCompanionReadsCoverEvaluation evaluates each companion_expr over
// recording companions that drive it true and false, through both sides of
// every branch, and checks that every path evaluation touched lies on a
// read CompanionReads returned: under it, or a container on the way to it,
// whose step the read's type signature pins.
func TestCompanionReadsCoverEvaluation(t *testing.T) {
	env, err := companionEnv()
	if err != nil {
		t.Fatal(err)
	}
	fixtures := []map[string]any{
		{"bucket": "b", "tags": map[string]any{"k": "v", "Owner": "o"},
			"versioning_configuration": []any{map[string]any{"status": "Enabled", "mfa_delete": "Disabled"}}},
		{"bucket": "", "tags": map[string]any{"k": "x"},
			"versioning_configuration": []any{map[string]any{"status": "Suspended", "mfa_delete": "Enabled"}}},
		{"bucket": nil, "tags": map[string]any{}, "versioning_configuration": []any{}},
		{"bucket": "b", "tags": map[string]any{},
			"versioning_configuration": []any{map[string]any{"status": "Suspended", "mfa_delete": "Enabled"}}},
	}
	for _, expr := range []string{
		"companion.versioning_configuration[0].status == 'Enabled'",
		"companion.versioning_configuration.exists(v, v.status == 'Enabled') ? companion.bucket != '' : companion.tags['k'] == 'v'",
		"companion.versioning_configuration.all(v, v.mfa_delete == 'Disabled') || size(companion.tags) > 0",
		"!has(companion.bucket) || companion.versioning_configuration.size() == 1 && 'Owner' in companion.tags",
	} {
		reads, err := CompanionReads(expr, companionSchema())
		if err != nil {
			t.Fatalf("%s: %v", expr, err)
		}
		a, iss := env.Compile(expr)
		if iss.Err() != nil {
			t.Fatal(iss.Err())
		}
		prg, err := env.Program(a)
		if err != nil {
			t.Fatal(err)
		}
		r := recorder{seen: map[string]bool{}}
		results := map[string]bool{}
		for _, f := range fixtures {
			out, _, _ := prg.Eval(map[string]any{varCompanion: r.wrap(types.DefaultTypeAdapter.NativeToValue(f), ""),
				lib.DeadlineVar: time.Now().Add(time.Minute), lib.UnresolvedVar: new(bool)})
			results[fmt.Sprint(out)] = true
		}
		if !results["true"] || !results["false"] {
			t.Errorf("%s: results %v, want true and false", expr, results)
		}
		if len(r.seen) == 0 {
			t.Fatalf("%s: nothing recorded", expr)
		}
		for p := range r.seen {
			if !slices.ContainsFunc(reads, func(rd string) bool { return segPrefix(rd, p) || segPrefix(p, rd) }) {
				t.Errorf("%s: evaluation reads %s, not on %q", expr, p, reads)
			}
		}
	}
}
