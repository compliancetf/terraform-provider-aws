package exceptions

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/pkg/engine/enginetest"
)

const vectorsPath = "../../pkg/engine/testdata/selector_vectors.json"

// TestSelectorVectors keeps pkg/engine/testdata/selector_vectors.json, the
// cross-check vectors of the public selector engine, equal to the selector
// cases of this package's tests (TestExceptionSelector,
// TestExceptionSelectorCompile, TestExceptionSetMapShapes,
// TestExceptionV01Verdicts) and the outcomes the engine gives them. Each
// outcome must also give the exception verdict lookup gives the same case.
// -update rewrites the file.
func TestSelectorVectors(t *testing.T) {
	var vs []enginetest.Vector
	add := func(name, expr string, a *engine.Activation) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		sel, err := celeng.CompileSelector(expr)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out := sel.Eval(ctx, selSchemas, bundle.KindResource, selCtl.ResourceType, a)
		if got, want := map[engine.State]string{engine.Pass: "apply", engine.Fail: "none", engine.Unknown: "pending",
			engine.NotEvaluable: "rejected"}[out.State], verdict(decide(t, ctx, expr, a)); got != want {
			t.Fatalf("%s: outcome %v is %s, lookup gives %s", name, out, got, want)
		}
		v := enginetest.Vector{Name: name, Selector: expr, Type: selCtl.ResourceType, Op: string(a.Op), Env: a.Env,
			EnvKnown: a.EnvKnown, Provider: enginetest.ProviderOf(a.Provider),
			Want: &enginetest.Want{State: out.State, Err: out.Err, UnknownPaths: out.UnknownPaths}}
		for _, x := range []struct {
			v   tftypes.Value
			out *json.RawMessage
		}{{a.Resource, &v.Resource}, {a.Config, &v.Config}, {a.Prior, &v.Prior}} {
			if *x.out, err = enginetest.Encode(x.v); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		vs = append(vs, v)
	}
	for _, tc := range selectorCases(t) {
		a := selectorBase(t)
		if tc.act != nil {
			tc.act(a)
		}
		add("selector/"+tc.name, tc.expr, a)
	}
	for _, tc := range setMapCases() {
		add("set_map/"+tc.name, tc.expr, &engine.Activation{Resource: selValue(t, tc.res)})
	}
	for i, r := range v01Rows(t) {
		add(fmt.Sprintf("v01/%03d %s/%s %s", i, r.Check.Op, r.Case, r.Name), v01CEL(t, r), &engine.Activation{Resource: selValue(t, r.Resource)})
	}
	for _, expr := range slices.Sorted(maps.Keys(selectorCompileErrors)) {
		_, err := celeng.CompileSelector(expr)
		if err == nil || "match: "+err.Error() != selectorCompileErrors[expr] {
			t.Fatalf("compile %q: %v", expr, err)
		}
		vs = append(vs, enginetest.Vector{Name: "compile/" + expr, Selector: expr, CompileError: err.Error()})
	}

	attrs := map[string]any{}
	for _, a := range selSchemas[selCtl.ResourceType].Block.Attributes {
		ty, err := a.Type.MarshalJSON() //nolint:staticcheck // the `terraform providers schema -json` type form
		if err != nil {
			t.Fatal(err)
		}
		attrs[a.Name] = map[string]any{"type": json.RawMessage(ty), "optional": true}
	}
	schema, err := json.Marshal(map[string]any{"version": 0, "block": map[string]any{"attributes": attrs}})
	if err != nil {
		t.Fatal(err)
	}
	got := vectorsJSON(t, enginetest.File{
		Comment: "Selector cross-check vectors generated from the exception selector tests of internal/exceptions; see README.md. Do not edit: go test ./internal/exceptions -run TestSelectorVectors -update",
		Schemas: map[string]json.RawMessage{selCtl.ResourceType: schema},
		Vectors: vs,
	})

	// The encoding must give back the values the engine saw.
	f := new(enginetest.File)
	if err := json.Unmarshal(got, f); err != nil {
		t.Fatal(err)
	}
	for i := range f.Vectors {
		v := &f.Vectors[i]
		if v.CompileError != "" {
			continue
		}
		in, err := f.Input(v)
		if err != nil {
			t.Fatal(err)
		}
		if !in.Schema.ValueType().Equal(selType) {
			t.Fatalf("%s: schema round trip gives %s", v.Name, in.Schema.ValueType())
		}
		for _, x := range [][2]json.RawMessage{{v.Resource, mustEncode(t, in.Resource)}, {v.Config, mustEncode(t, in.Config)}, {v.Prior, mustEncode(t, in.Prior)}} {
			if !bytes.Equal(x[0], x[1]) {
				t.Fatalf("%s: value does not round trip", v.Name)
			}
		}
	}

	if *update {
		if err := os.WriteFile(vectorsPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale: go test ./internal/exceptions -run TestSelectorVectors -update", vectorsPath)
	}
}

func mustEncode(t *testing.T, v tftypes.Value) json.RawMessage {
	t.Helper()
	b, err := enginetest.Encode(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// vectorsJSON writes f with one vector per line, so a changed case is a
// one-line diff.
func vectorsJSON(t *testing.T, f enginetest.File) []byte {
	t.Helper()
	line := func(x any) []byte {
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false) // selectors keep their < > &
		if err := enc.Encode(x); err != nil {
			t.Fatal(err)
		}
		return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "{\n  \"_comment\": %s,\n  \"schemas\": %s,\n  \"vectors\": [\n", line(f.Comment), line(f.Schemas))
	for i, v := range f.Vectors {
		sep := ","
		if i == len(f.Vectors)-1 {
			sep = ""
		}
		fmt.Fprintf(&buf, "    %s%s\n", line(v), sep)
	}
	buf.WriteString("  ]\n}\n")
	return buf.Bytes()
}
