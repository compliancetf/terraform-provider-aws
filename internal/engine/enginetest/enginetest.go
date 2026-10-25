// Package enginetest holds the fixture readers the engine tests and the
// cross-check runner (test/crosscheck) share: the captured AWS schema subset
// and fixture JSON to tftypes values.
package enginetest

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/fixturejson"
)

// AWSSubset reads testdata/schemas/aws-subset.json (terraform providers
// schema -json) at path into the tfprotov5 response Load receives at
// runtime: names, flags, types, nesting modes and nested blocks.
func AWSSubset(t testing.TB, path string) *tfprotov5.GetProviderSchemaResponse {
	t.Helper()
	type block struct {
		Attributes map[string]struct {
			Type                                    json.RawMessage
			Optional, Required, Computed, Sensitive bool
		} `json:"attributes"`
		BlockTypes map[string]struct {
			Nesting string `json:"nesting_mode"`
			Block   block  `json:"block"`
		} `json:"block_types"`
	}
	type schemas map[string]struct {
		Block block `json:"block"`
	}
	var doc struct {
		ProviderSchemas map[string]struct {
			Resources   schemas `json:"resource_schemas"`
			DataSources schemas `json:"data_source_schemas"`
			Ephemerals  schemas `json:"ephemeral_resource_schemas"`
		} `json:"provider_schemas"`
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var conv func(b block) *tfprotov5.SchemaBlock
	conv = func(b block) *tfprotov5.SchemaBlock {
		out := &tfprotov5.SchemaBlock{}
		for n, a := range b.Attributes {
			typ, err := tftypes.ParseJSONType(a.Type) //nolint:staticcheck // reads `terraform providers schema -json` type strings in a test fixture
			if err != nil {
				t.Fatalf("%s: %v", n, err)
			}
			out.Attributes = append(out.Attributes, &tfprotov5.SchemaAttribute{Name: n, Type: typ, Optional: a.Optional, Required: a.Required, Computed: a.Computed, Sensitive: a.Sensitive})
		}
		nesting := map[string]tfprotov5.SchemaNestedBlockNestingMode{"single": tfprotov5.SchemaNestedBlockNestingModeSingle, "list": tfprotov5.SchemaNestedBlockNestingModeList, "set": tfprotov5.SchemaNestedBlockNestingModeSet}
		for n, nb := range b.BlockTypes {
			out.BlockTypes = append(out.BlockTypes, &tfprotov5.SchemaNestedBlock{TypeName: n, Nesting: nesting[nb.Nesting], Block: conv(nb.Block)})
		}
		return out
	}
	m := func(s schemas) map[string]*tfprotov5.Schema {
		out := map[string]*tfprotov5.Schema{}
		for n, x := range s {
			out[n] = &tfprotov5.Schema{Block: conv(x.Block)}
		}
		return out
	}
	p := doc.ProviderSchemas["registry.terraform.io/hashicorp/aws"]
	return &tfprotov5.GetProviderSchemaResponse{ResourceSchemas: m(p.Resources), DataSourceSchemas: m(p.DataSources), EphemeralResourceSchemas: m(p.Ephemerals)}
}

// Value builds a value of typ from fixture JSON (fixturejson.Value): absent,
// null or missing attributes are null, {"$unknown": true} is unknown. An
// error fails the test, naming the test (the fixture file) and the path.
func Value(t testing.TB, typ tftypes.Type, raw json.RawMessage) tftypes.Value {
	t.Helper()
	v, err := fixturejson.Value(typ, raw)
	if err != nil {
		t.Fatalf("%s: %v", t.Name(), err)
	}
	return v
}

// String reads a fixture string: absent or {"$unknown": true} is unknown; a
// JSON null or any other value fails the test.
func String(t testing.TB, raw json.RawMessage) (s string, known bool) {
	t.Helper()
	s, known, err := fixturejson.String(raw)
	if err != nil {
		t.Fatalf("%s: %v", t.Name(), err)
	}
	return s, known
}

// SensitiveStrings returns every known string inside v (an object of blk)
// under an attribute the schema marks Sensitive, nested blocks included.
func SensitiveStrings(blk *tfprotov5.SchemaBlock, v tftypes.Value) []string {
	var out []string
	var attrs map[string]tftypes.Value
	if !v.IsKnown() || v.IsNull() || v.As(&attrs) != nil {
		return nil
	}
	for _, a := range blk.Attributes {
		if a.Sensitive {
			out = append(out, stringLeaves(attrs[a.Name])...)
		}
	}
	for _, nb := range blk.BlockTypes {
		bv := attrs[nb.TypeName]
		var elems []tftypes.Value
		switch {
		case nb.Nesting == tfprotov5.SchemaNestedBlockNestingModeSingle || nb.Nesting == tfprotov5.SchemaNestedBlockNestingModeGroup:
			elems = []tftypes.Value{bv}
		case !bv.IsKnown() || bv.IsNull():
		case nb.Nesting == tfprotov5.SchemaNestedBlockNestingModeMap:
			var m map[string]tftypes.Value
			if err := bv.As(&m); err != nil {
				panic(fmt.Sprintf("enginetest: block %s: %v", nb.TypeName, err)) // a built value of the wrong shape is a test bug
			}
			for _, e := range m {
				elems = append(elems, e)
			}
		default:
			if err := bv.As(&elems); err != nil {
				panic(fmt.Sprintf("enginetest: block %s: %v", nb.TypeName, err)) // never skip a block silently: the leak scan would go vacuous
			}
		}
		for _, e := range elems {
			out = append(out, SensitiveStrings(nb.Block, e)...)
		}
	}
	return out
}

func stringLeaves(v tftypes.Value) (out []string) {
	_ = tftypes.Walk(v, func(_ *tftypes.AttributePath, x tftypes.Value) (bool, error) { //nolint:errcheck // the callback never returns an error
		var s string
		if x.IsKnown() && !x.IsNull() && x.Type().Is(tftypes.String) && x.As(&s) == nil {
			out = append(out, s)
		}
		return true, nil
	})
	return out
}
