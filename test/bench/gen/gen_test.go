package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/enginetest"
	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
)

var update = flag.Bool("update", false, "rewrite testdata/bench/reference-bundle.json")

const (
	repo       = "../../.."
	schemaFile = repo + "/testdata/schemas/aws-subset.json"
	bundleFile = repo + "/testdata/bench/reference-bundle.json"
	catalog    = repo + "/testdata/controls/catalog-iam/" + iampolicy.CatalogFile
)

// TestDeterminism is the oracle: the same seed gives the same digest,
// another seed other instances (compared without the seed field), and the document holds n instances over every
// resource type of the subset with about 10% unknowns.
func TestDeterminism(t *testing.T) {
	raw, d1, err := build(schemaFile, 1, 500)
	if err != nil {
		t.Fatal(err)
	}
	if _, d2, err := build(schemaFile, 1, 500); err != nil || d2 != d1 {
		t.Fatalf("seed 1 twice: %s then %s (%v)", d1, d2, err)
	}
	var doc Doc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	s := schema(t)
	sub, err := ParseSchema(mustRead(t, schemaFile))
	if err != nil {
		t.Fatal(err)
	}
	if one, two := marshal(t, mustGenerate(t, sub, 1)), marshal(t, mustGenerate(t, sub, 2)); bytes.Equal(one, two) {
		t.Fatal("seeds 1 and 2 give the same instances")
	} else if !bytes.Equal(one, marshal(t, doc.Instances)) {
		t.Fatal("Generate(seed 1) differs from the built document's instances")
	}
	types, unknowns, updates := map[string]bool{}, 0, 0
	for _, in := range doc.Instances {
		types[in.ResourceType] = true
		if slices.ContainsFunc(slices.Collect(maps.Values(in.Config)), isUnknown) {
			unknowns++
		}
		if in.Op == "update" {
			updates++
		}
	}
	if doc.Format != Format || doc.N != 500 || len(doc.Instances) != 500 || len(types) != len(s.ResourceSchemas) {
		t.Fatalf("%s n=%d: %d instances over %d types, want 500 over %d", doc.Format, doc.N, len(doc.Instances), len(types), len(s.ResourceSchemas))
	}
	if unknowns < 30 || unknowns > 70 || updates < 150 || updates > 250 {
		t.Errorf("%d instances with an unknown, %d updates: want about 50 and 200", unknowns, updates)
	}
}

func mustGenerate(t *testing.T, s Schema, seed uint64) []Instance {
	t.Helper()
	out, err := Generate(s, seed, 500)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestUnhandledSchema requires Generate to fail, naming the type or nesting
// mode, on a schema it cannot draw, never to drop the attribute or block;
// an optional attribute or an empty list fails too, so the
// result does not depend on what a seed happens to draw.
func TestUnhandledSchema(t *testing.T) {
	for _, tc := range []struct{ name, block, want string }{
		{"required dynamic", `{"attributes":{"x":{"type":"dynamic","required":true}}}`, `attribute x: unhandled cty type "dynamic"`},
		{"optional dynamic", `{"attributes":{"x":{"type":"dynamic","optional":true}}}`, `attribute x: unhandled cty type "dynamic"`},
		{"computed dynamic", `{"attributes":{"x":{"type":"dynamic","computed":true}}}`, `attribute x: unhandled cty type "dynamic"`},
		{"tuple", `{"attributes":{"x":{"type":["tuple",["string","number"]],"required":true}}}`, `attribute x: unhandled cty type "tuple"`},
		{"dynamic in a list", `{"attributes":{"x":{"type":["list","dynamic"],"required":true}}}`, `attribute x: unhandled cty type "dynamic"`},
		{"object attr dynamic", `{"attributes":{"x":{"type":["object",{"a":"dynamic"}],"required":true}}}`, `attribute x: a: unhandled cty type "dynamic"`},
		{"unknown kind", `{"attributes":{"x":{"type":["capsule","string"],"required":true}}}`, `attribute x: unhandled cty type "capsule"`},
		{"malformed", `{"attributes":{"x":{"type":["list"],"required":true}}}`, `attribute x: unhandled cty type ["list"]`},
		{"optional names not a list", `{"attributes":{"x":{"type":["object",{"a":"string"},42],"required":true}}}`, `attribute x: unhandled cty type ["object",{"a":"string"},42]`},
		{"optional names null", `{"attributes":{"x":{"type":["object",{"a":"string"},null],"required":true}}}`, `attribute x: unhandled cty type ["object",{"a":"string"},null]`},
		{"optional name undeclared", `{"attributes":{"x":{"type":["object",{"a":"string"},["b"]],"required":true}}}`, `attribute x: unhandled cty type ["object",{"a":"string"},["b"]]`},
		{"object attrs null", `{"attributes":{"x":{"type":["object",null],"required":true}}}`, `attribute x: unhandled cty type ["object",null]`},
		{"map nesting", `{"block_types":{"b":{"nesting_mode":"map","block":{}}}}`, `block b: unhandled nesting mode "map"`},
		{"nested map nesting", `{"block_types":{"o":{"nesting_mode":"single","block":{"block_types":{"b":{"nesting_mode":"map","block":{}}}}}}}`, `block o: block b: unhandled nesting mode "map"`},
		{"nested dynamic", `{"block_types":{"o":{"nesting_mode":"list","block":{"attributes":{"x":{"type":"dynamic","optional":true}}}}}}`, `block o: attribute x: unhandled cty type "dynamic"`},
	} {
		var b block
		if err := json.Unmarshal([]byte(tc.block), &b); err != nil {
			t.Fatal(err)
		}
		for seed := range uint64(4) {
			if out, err := Generate(Schema{"aws_bobthecorp": b}, seed, 2); err == nil || err.Error() != "aws_bobthecorp: "+tc.want {
				t.Errorf("%s seed %d: error %v (instances %v), want %q", tc.name, seed, err, out, tc.want)
			}
		}
	}
	if out, err := Generate(Schema{}, 1, 1); err == nil || err.Error() != "no resource types to draw from" {
		t.Errorf("empty schema: error %v (instances %v), want no resource types", err, out)
	}
	// The object form with optional attribute names is drawn in full.
	var b block
	if err := json.Unmarshal([]byte(`{"attributes":{"x":{"type":["object",{"a":"string","b":"number"},["b"]],"required":true}}}`), &b); err != nil {
		t.Fatal(err)
	}
	out, err := Generate(Schema{"aws_bobthecorp": b}, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if x, ok := out[0].Config["x"].(map[string]any); !ok || len(x) != 2 {
		t.Errorf("optional-attrs object: %v, want both attributes", out[0].Config["x"])
	}
}

// TestSetMinItems requires a set block to keep min_items distinct elements
// after dedup: a two-value element domain refills a two-element
// set, and one that cannot reach min_items fails naming the block path.
func TestSetMinItems(t *testing.T) {
	setOf := func(minItems int) block {
		var b block
		raw := fmt.Sprintf(`{"block_types":{"o":{"nesting_mode":"single","min_items":1,"block":{"block_types":{"s":{"nesting_mode":"set","min_items":%d,"block":{"attributes":{"x":{"type":"bool","required":true}}}}}}}}}`, minItems)
		if err := json.Unmarshal([]byte(raw), &b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	for seed := range uint64(20) {
		out, err := Generate(Schema{"aws_bobthecorp": setOf(2)}, seed, 20)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		for _, in := range out {
			for _, obj := range []map[string]any{in.Config, in.Prior} {
				o, ok := obj["o"].(map[string]any)
				if !ok || isUnknown(o) {
					continue // update-only prior, or the drawn unknown
				}
				s, _ := o["s"].([]any)
				if len(s) != 2 || len(unique(slices.Clone(s))) != 2 {
					t.Fatalf("seed %d: set %v, want 2 distinct elements", seed, s)
				}
			}
		}
	}
	want := "aws_bobthecorp: block o.s: 2 distinct set elements after 100 extra draws, want min_items 3"
	if out, err := Generate(Schema{"aws_bobthecorp": setOf(3)}, 1, 1); err == nil || err.Error() != want {
		t.Errorf("bool set min_items 3: error %v (instances %v), want %q", err, out, want)
	}
}

// TestReferenceBundle rebuilds testdata/bench/reference-bundle.json from the
// fixture controls (embedded CIS, catalog-iam, content-sample and the
// crosscheck groups except errors and limits, whose controls exist to raise
// error classes), checks it loads clean against aws-subset.json, and runs
// every generated seed-1 instance through it. A real control (CIS, catalog-iam,
// content-sample) may only be not_evaluable as unresolved (an IAM principal
// the policy names by wildcard or another account); the crosscheck probes,
// written for one input each, may fail on generated nulls, but under 10% of
// all results are not_evaluable, so the benchmark measures evaluation.
func TestReferenceBundle(t *testing.T) {
	raw, probes := referenceBundle(t)
	if *update {
		if err := os.WriteFile(bundleFile, raw, 0o644); err != nil { //nolint:gosec // committed fixture
			t.Fatal(err)
		}
	}
	if got, err := os.ReadFile(bundleFile); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("%s is stale (%v): go test ./test/bench/gen -run TestReferenceBundle -update", bundleFile, err)
	}
	cs, err := bundle.DecodeControls(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) < 100 {
		t.Fatalf("%d controls, want about 120", len(cs))
	}
	data, err := os.ReadFile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	cat, err := iampolicy.LoadCatalog(data)
	if err != nil {
		t.Fatal(err)
	}
	s := schema(t)
	comp, diags, err := celeng.New(celeng.Options{PerResourceBudget: time.Minute}).
		Load(cs, s, celeng.Content{Digest: "sha256:reference-bundle", IAMCatalog: cat})
	if err != nil || len(diags) > 0 {
		t.Fatalf("load: %v, diagnostics %+v", err, diags)
	}
	instances, _, err := build(schemaFile, 1, 500)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct{ Instances []map[string]json.RawMessage }
	if err := json.Unmarshal(instances, &doc); err != nil {
		t.Fatal(err)
	}
	states, perType := map[engine.State]int{}, map[string]int{}
	for i, in := range doc.Instances {
		var typ, op string
		if json.Unmarshal(in["resource_type"], &typ) != nil || json.Unmarshal(in["op"], &op) != nil {
			t.Fatalf("instance %d: no resource_type or op", i)
		}
		ty := s.ResourceSchemas[typ].Block.ValueType()
		b := celeng.Bindings{Kind: bundle.KindResource, Type: typ, Op: op, Env: "prod", EnvKnown: true,
			Resource: value(t, ty, in["planned"]), Config: value(t, ty, in["config"]), Prior: value(t, ty, in["prior"]),
			Provider: celeng.ProviderInfo{Region: "eu-west-1", RegionKnown: true, AccountID: "111111111111", AccountKnown: true, Partition: "aws", PartitionKnown: true}}
		rs := comp.Evaluate(context.Background(), b, nil)
		perType[typ] += len(rs)
		if len(rs) == 0 && !uncovered[typ] {
			t.Errorf("instance %d %s: no control evaluated", i, typ)
		}
		for _, r := range rs {
			states[r.State]++
			if r.ErrClass != engine.ErrNone && r.ErrClass != engine.ErrUnresolved && !probes[r.ControlID] {
				t.Errorf("instance %d %s: %s %s/%s", i, typ, r.ControlID, r.State, r.ErrClass)
			}
		}
	}
	for typ := range uncovered {
		if n, ok := perType[typ]; !ok || n > 0 {
			t.Errorf("%s: %d results (generated %v); it has controls now, drop it from uncovered", typ, n, ok)
		}
	}
	total := 0
	for _, n := range states {
		total += n
	}
	if states[engine.Pass] == 0 || states[engine.Fail] == 0 || states[engine.NotEvaluable]*10 >= total {
		t.Errorf("results %v: want passing and failing controls, under 10%% not_evaluable", states)
	}
	t.Logf("%d controls, results by state %v", len(cs), states)
}

// uncovered are the generated resource types no fixture control targets:
// the three types of the deferred content not_equals intents
// and two with no control in any fixture source. Their instances evaluate no
// control; every other instance must evaluate at least one.
var uncovered = map[string]bool{
	"aws_ecs_task_definition": true, "aws_lambda_function_url": true, "aws_launch_template": true,
	"aws_secretsmanager_secret_version": true, "aws_vpc_security_group_egress_rule": true,
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // repo fixture
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// value builds the instance value; JSON null is a null object.
func value(t *testing.T, ty tftypes.Type, raw json.RawMessage) tftypes.Value {
	if string(raw) == "null" {
		raw = nil
	}
	return enginetest.Value(t, ty, raw)
}

// referenceBundle collects the fixture controls in source order, drops exact
// repeats and suffixes the id of a different control on a taken (id, kind,
// resource_type) key with its source, then sorts by key. probes are the ids
// taken from the crosscheck groups.
func referenceBundle(t *testing.T) (raw []byte, probes map[string]bool) {
	t.Helper()
	type src struct{ glob, tag string }
	srcs := []src{{"internal/embedded/cis/controls.json", "cis"}, {"testdata/controls/catalog-iam/*.json", "catalog"},
		{"testdata/controls/content-sample/*.json", "sample"}, {"testdata/crosscheck/*/*.json", "xc"}}
	seen, probes := map[string]string{}, map[string]bool{}
	var out []map[string]any
	add := func(raw json.RawMessage, tag string) {
		var c map[string]any
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		canon, _ := json.Marshal(c)
		key := fmt.Sprint(c["id"], "|", c["kind"], "|", c["resource_type"])
		switch prev, ok := seen[key]; {
		case ok && prev == string(canon):
			return
		case ok:
			c["id"] = fmt.Sprint(c["id"], "_", tag)
			key = fmt.Sprint(c["id"], "|", c["kind"], "|", c["resource_type"])
			if _, ok := seen[key]; ok {
				t.Fatalf("%s: control key %s taken twice", tag, key)
			}
			canon, _ = json.Marshal(c)
		}
		seen[key] = string(canon)
		probes[fmt.Sprint(c["id"])] = probes[fmt.Sprint(c["id"])] || tag == "xc"
		out = append(out, c)
	}
	for _, s := range srcs {
		files, err := filepath.Glob(filepath.Join(repo, s.glob))
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: %d files (%v)", s.glob, len(files), err)
		}
		for _, f := range files {
			if slash := filepath.ToSlash(f); strings.Contains(slash, "/errors/") || strings.Contains(slash, "/limits/") ||
				filepath.Base(f) == iampolicy.CatalogFile || filepath.Base(f) == "not-expressible.json" {
				continue
			}
			data, err := os.ReadFile(f) //nolint:gosec // repo fixture
			if err != nil {
				t.Fatal(err)
			}
			var file struct {
				Control  json.RawMessage
				Controls []json.RawMessage
			}
			if s.tag == "cis" {
				err = json.Unmarshal(data, &file.Controls)
			} else {
				err = json.Unmarshal(data, &file)
			}
			if err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			if file.Control != nil {
				file.Controls = append(file.Controls, file.Control)
			}
			for _, c := range file.Controls {
				add(c, s.tag)
			}
		}
	}
	slices.SortFunc(out, func(a, b map[string]any) int {
		return strings.Compare(fmt.Sprint(a["resource_type"], "|", a["id"], "|", a["kind"]), fmt.Sprint(b["resource_type"], "|", b["id"], "|", b["kind"]))
	})
	var buf bytes.Buffer
	buf.WriteString("[\n")
	for i, c := range out {
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false) // keep && and < readable in expressions
		if err := enc.Encode(c); err != nil {
			t.Fatal(err)
		}
		buf.Truncate(buf.Len() - 1) // Encode's newline
		if i < len(out)-1 {
			buf.WriteByte(',')
		}
		buf.WriteByte('\n')
	}
	buf.WriteString("]\n")
	return buf.Bytes(), probes
}

func schema(t *testing.T) *tfprotov5.GetProviderSchemaResponse {
	return enginetest.AWSSubset(t, schemaFile)
}

func isUnknown(v any) bool {
	m, ok := v.(map[string]any)
	return ok && len(m) == 1 && m["$unknown"] == true
}
