package bundlegen

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
)

var _ hook.SchemaSource = Schemas{}

func writeSchema(t *testing.T, resources string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "schema.json")
	doc := `{"provider_schemas": {"registry.terraform.io/hashicorp/aws": {"resource_schemas": ` + resources + `}}}`
	if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSchemaSource: LoadSchemas converts schema JSON to tfprotov5 schemas
// (flags, types, nesting modes, item limits, sorted names) that celeng.Load
// accepts.
func TestSchemaSource(t *testing.T) {
	s, err := LoadSchemas(writeSchema(t, `{"aws_x": {"version": 3, "block": {
		"attributes": {"z": {"type": "string", "optional": true}, "a": {"type": ["list","number"], "required": true, "sensitive": true}, "c": {"type": "bool", "computed": true}},
		"block_types": {
			"one": {"nesting_mode": "list", "max_items": 1, "block": {"attributes": {"s": {"type": "string", "optional": true}}}},
			"many": {"nesting_mode": "set", "min_items": 1, "block": {}},
			"sg": {"nesting_mode": "single", "block": {}},
			"mp": {"nesting_mode": "map", "block": {}},
			"gr": {"nesting_mode": "group", "block": {}}}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	x, ok := s.Resource("aws_x")
	if !ok || x.Version != 3 {
		t.Fatalf("aws_x: %v %v", x, ok)
	}
	if _, ok := s.Resource("aws_y"); ok {
		t.Error("aws_y found")
	}
	if _, ok := s.DataSource("aws_x"); ok {
		t.Error("data source aws_x found")
	}
	if _, ok := s.EphemeralResource("aws_x"); ok {
		t.Error("ephemeral aws_x found")
	}
	var names []string
	for _, a := range x.Block.Attributes {
		names = append(names, a.Name)
	}
	if strings.Join(names, ",") != "a,c,z" {
		t.Errorf("attribute order %v", names)
	}
	a := x.Block.Attributes[0]
	if !a.Type.Equal(tftypes.List{ElementType: tftypes.Number}) || !a.Required || !a.Sensitive || a.Optional || a.Computed {
		t.Errorf("attribute a: %+v", a)
	}
	modes := map[string]tfprotov5.SchemaNestedBlockNestingMode{}
	for _, nb := range x.Block.BlockTypes {
		modes[nb.TypeName] = nb.Nesting
	}
	want := map[string]tfprotov5.SchemaNestedBlockNestingMode{
		"gr": tfprotov5.SchemaNestedBlockNestingModeGroup, "many": tfprotov5.SchemaNestedBlockNestingModeSet,
		"mp": tfprotov5.SchemaNestedBlockNestingModeMap, "one": tfprotov5.SchemaNestedBlockNestingModeList,
		"sg": tfprotov5.SchemaNestedBlockNestingModeSingle,
	}
	for n, m := range want {
		if modes[n] != m {
			t.Errorf("block %s nesting %v, want %v", n, modes[n], m)
		}
	}
	if nb := x.Block.BlockTypes[3]; nb.TypeName != "one" || nb.MaxItems != 1 || nb.Block.Attributes[0].Name != "s" {
		t.Errorf("block order or limits: %+v", nb)
	}
	if nb := x.Block.BlockTypes[1]; nb.TypeName != "many" || nb.MinItems != 1 {
		t.Errorf("block many: %+v", nb)
	}

	in := loadInputs(t, inputs, true)
	c := in.Authored["rds_bobthecorp_storage_encrypted"][0]
	if _, _, err := celeng.Load([]bundle.Control{c}, in.Schemas.ProviderSchema()); err != nil {
		t.Errorf("celeng.Load on converted schemas: %v", err)
	}
}

func TestSchemaSourceErrors(t *testing.T) {
	for name, res := range map[string]string{
		"nesting":     `{"aws_x": {"block": {"block_types": {"b": {"nesting_mode": "tuple", "block": {}}}}}}`,
		"no type":     `{"aws_x": {"block": {"attributes": {"a": {"optional": true}}}}}`,
		"bad type":    `{"aws_x": {"block": {"attributes": {"a": {"type": ["frob"]}}}}}`,
		"nested_type": `{"aws_x": {"block": {"attributes": {"a": {"nested_type": {"attributes": {}, "nesting_mode": "single"}}}}}}`,
		"no block":    `{"aws_x": {"version": 1}}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadSchemas(writeSchema(t, res))
			var ge *Error
			if !errors.As(err, &ge) || ge.Code != "E_INPUT" {
				t.Fatalf("got %v, want E_INPUT", err)
			}
		})
	}
}

// TestSchemaCompatDigest: the digest of the embedded CIS controls against a
// schema built from internal/embedded/testdata/schema_compat.tsv equals the
// schema_compat_digest of the embedded CIS manifest (P0B definition).
func TestSchemaCompatDigest(t *testing.T) {
	raw, err := os.ReadFile("../embedded/testdata/schema_compat.tsv")
	if err != nil {
		t.Fatal(err)
	}
	// type -> attribute -> cty type JSON; "a.b" reads become a set(object)
	// attribute a, unless a is listed itself with its full type.
	attrs := map[string]map[string]string{}
	objs := map[string]map[string]map[string]json.RawMessage{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		f := strings.Split(line, "\t")
		if attrs[f[0]] == nil {
			attrs[f[0]], objs[f[0]] = map[string]string{}, map[string]map[string]json.RawMessage{}
		}
		if top, sub, ok := strings.Cut(f[1], "."); ok {
			if objs[f[0]][top] == nil {
				objs[f[0]][top] = map[string]json.RawMessage{}
			}
			objs[f[0]][top][sub] = json.RawMessage(f[2])
			continue
		}
		attrs[f[0]][f[1]] = f[2]
	}
	res := map[string]any{}
	for typ, as := range attrs {
		block := map[string]any{}
		for n, ty := range as {
			block[n] = map[string]any{"type": json.RawMessage(ty), "optional": true}
		}
		for n, o := range objs[typ] {
			if _, whole := as[n]; whole {
				continue
			}
			block[n] = map[string]any{"type": []any{"set", []any{"object", o}}, "optional": true}
		}
		res[typ] = map[string]any{"block": map[string]any{"attributes": block}}
	}
	rj, _ := json.Marshal(res)
	s, err := LoadSchemas(writeSchema(t, string(rj)))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../embedded/cis/controls.json")
	if err != nil {
		t.Fatal(err)
	}
	cs, err := bundle.ParseControls(data)
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		SchemaCompatDigest string `json:"schema_compat_digest"`
	}
	mj, err := os.ReadFile("../embedded/cis/manifest.json")
	if err != nil || json.Unmarshal(mj, &m) != nil {
		t.Fatal(err)
	}
	got, err := SchemaCompatDigest(cs, s)
	if err != nil {
		t.Fatal(err)
	}
	if got != m.SchemaCompatDigest {
		t.Errorf("SchemaCompatDigest = %s, want %s", got, m.SchemaCompatDigest)
	}

	cs[0].Reads = []string{"no_such_read"}
	var ge *Error
	if _, err := SchemaCompatDigest(cs, s); !errors.As(err, &ge) || ge.Code != "E_SCHEMA_TYPE" {
		t.Errorf("unknown read: got %v, want E_SCHEMA_TYPE", err)
	}
}

// TestRejectFloats: generated files carry integers only; a float value fails
// the emit with E_EMIT.
func TestRejectFloats(t *testing.T) {
	for _, v := range []string{"7.5", "7.0", "1e3", "-2E-1"} {
		t.Run(v, func(t *testing.T) {
			_, err := canonicalJSON(map[string]any{"value": json.Number(v)})
			var ge *Error
			if !errors.As(err, &ge) || ge.Code != "E_EMIT" || !strings.Contains(ge.Msg, "float") {
				t.Fatalf("got %v, want E_EMIT float", err)
			}
		})
	}
}

// TestSchemaCompatDynamic: a read below a dynamic attribute resolves to
// dynamic, as celeng resolves it at runtime; an unknown kind is named.
func TestSchemaCompatDynamic(t *testing.T) {
	s, err := LoadSchemas(writeSchema(t, `{"aws_x": {"block": {"attributes": {"dyn": {"type": "dynamic", "optional": true}}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	c := bundle.Control{ID: "x", Kind: bundle.KindResource, ResourceType: "aws_x", Reads: []string{"dyn.a"}}
	got, err := SchemaCompatDigest([]bundle.Control{c}, s)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("aws_x\tdyn.a\t\"dynamic\""))
	if want := "sha256:" + hex.EncodeToString(sum[:]); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	c.Kind = "frob"
	if _, err := SchemaCompatDigest([]bundle.Control{c}, s); err == nil || !strings.Contains(err.Error(), "unknown kind") {
		t.Errorf("unknown kind: %v", err)
	}
}
