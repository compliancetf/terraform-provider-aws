package verdict

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// The goldens are the frozen instance_key goldens shared with ctfkit
// (testdata/instancekey; _edge_dupkey and _edge_surrogate are plan JSON parsing
// cases with no tftypes form). Each key is recomputed from plan.json and
// schema.json through the provider's tftypes path: the planned value is
// built with unknowns from after_unknown and sent through msgpack like a
// PlannedState, then masked with the golden unknown_paths.

type golden struct {
	Entries []struct {
		Address string `json:"address"`
		Deposed string `json:"deposed"`
		Error   string `json:"error"`
		Keys    []struct {
			Field             string     `json:"field"`
			Form              Form       `json:"form"`
			Key               string     `json:"key"`
			PriorIdentityKind string     `json:"prior_identity_kind"`
			UnknownPaths      [][]string `json:"unknown_paths"`
			AfterJCS          string     `json:"after_hashed_jcs"`
			PriorJCS          string     `json:"prior_identity_hashed_jcs"`
		} `json:"keys"`
	} `json:"entries"`
	KLeafHex string `json:"k_leaf_hex"`
	KeyCheck string `json:"key_check"`
}

type planChange struct {
	Address string `json:"address"`
	Deposed string `json:"deposed"`
	Mode    string `json:"mode"`
	Type    string `json:"type"`
	Change  struct {
		Actions        []string `json:"actions"`
		After          any      `json:"after"`
		AfterUnknown   any      `json:"after_unknown"`
		Before         any      `json:"before"`
		BeforeIdentity any      `json:"before_identity"`
	} `json:"change"`
}

const testSecretHex = "494e5345435552452d544553542d5345435245542d696e7374616e63656b6579"

func decodeFile(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func TestInstanceKeyGoldens(t *testing.T) {
	secret, _ := hex.DecodeString(testSecretHex)
	l, err := hkdf.Key(sha256.New, secret, nil, infoLeaf, 32)
	if err != nil {
		t.Fatal(err)
	}
	var leaf [32]byte
	copy(leaf[:], l)
	dirs, err := filepath.Glob("testdata/instancekey/*/expected.json")
	if err != nil || len(dirs) != 21 {
		t.Fatalf("goldens: %d dirs, %v", len(dirs), err)
	}
	keys := 0
	for _, exp := range dirs {
		dir := filepath.Dir(exp)
		var g golden
		var cg golden
		var plan struct {
			ResourceChanges []planChange `json:"resource_changes"`
		}
		var schema struct {
			ProviderSchemas map[string]struct {
				Resources map[string]struct {
					Block json.RawMessage `json:"block"`
				} `json:"resource_schemas"`
			} `json:"provider_schemas"`
		}
		decodeFile(t, exp, &g)
		decodeFile(t, filepath.Join(dir, "canonical.json"), &cg)
		decodeFile(t, filepath.Join(dir, "plan.json"), &plan)
		decodeFile(t, filepath.Join(dir, "schema.json"), &schema)
		if g.KLeafHex != hex.EncodeToString(leaf[:]) {
			t.Fatalf("%s: k_leaf differs", dir)
		}
		var changes []planChange
		for _, rc := range plan.ResourceChanges {
			noop := len(rc.Change.Actions) == 1 && (rc.Change.Actions[0] == "no-op" || rc.Change.Actions[0] == "read")
			if rc.Mode == "managed" && (!noop || rc.Deposed != "") {
				changes = append(changes, rc)
			}
		}
		if len(changes) != len(g.Entries) {
			t.Fatalf("%s: %d managed changes, %d entries", dir, len(changes), len(g.Entries))
		}
		for i, e := range g.Entries {
			rc := changes[i]
			if e.Error != "" {
				continue // plan JSON refusals; the tftypes cases have unit tests
			}
			var block json.RawMessage
			for _, ps := range schema.ProviderSchemas {
				block = ps.Resources[rc.Type].Block
			}
			typ := blockType(t, block)
			for j, k := range e.Keys {
				name := e.Address + "/" + e.Deposed + "/" + string(k.Form)
				planned := tftypes.NewValue(typ, nil)
				var prior json.RawMessage
				if k.Form != FormDelete {
					planned = msgpackRoundTrip(t, typ, build(t, typ, rc.Change.After, rc.Change.AfterUnknown))
				}
				switch k.PriorIdentityKind {
				case KindIdentity:
					prior, _ = json.Marshal(rc.Change.BeforeIdentity)
				case KindID:
					prior, _ = json.Marshal(map[string]any{"id": rc.Change.Before.(map[string]any)["id"]})
				}
				got, err := Key(leaf, rc.Type, k.Form, planned, k.UnknownPaths, prior)
				if err != nil {
					t.Errorf("%s: %v", name, err)
					continue
				}
				if got != k.Key {
					ck := cg.Entries[i].Keys[j]
					after, _ := afterJCS(leaf, k.Form, planned, k.UnknownPaths)
					pj := []byte("null")
					if k.Form != FormCreate {
						pj, _ = priorTree(leaf, prior)
					}
					t.Errorf("%s: key %s, want %s\n after %s\n want  %s\n prior %s\n want  %s", name, got, k.Key, after, ck.AfterJCS, pj, ck.PriorJCS)
				}
				keys++
			}
		}
	}
	if keys < 40 {
		t.Fatalf("only %d keys checked", keys)
	}
}

// blockType is the tftypes type of a terraform providers schema -json block.
func blockType(t *testing.T, raw json.RawMessage) tftypes.Type {
	t.Helper()
	var b struct {
		Attributes map[string]struct {
			Type   json.RawMessage `json:"type"`
			Nested *struct {
				Attributes  json.RawMessage `json:"attributes"`
				NestingMode string          `json:"nesting_mode"`
			} `json:"nested_type"`
		} `json:"attributes"`
		BlockTypes map[string]struct {
			Block       json.RawMessage `json:"block"`
			NestingMode string          `json:"nesting_mode"`
		} `json:"block_types"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	attrs := map[string]tftypes.Type{}
	for n, a := range b.Attributes {
		if a.Nested != nil {
			inner, _ := json.Marshal(map[string]json.RawMessage{"attributes": a.Nested.Attributes})
			attrs[n] = nest(a.Nested.NestingMode, blockType(t, inner))
			continue
		}
		at, err := tftypes.ParseJSONType(a.Type) //nolint:staticcheck // the cty JSON type syntax of the schema file
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		attrs[n] = at
	}
	for n, bt := range b.BlockTypes {
		attrs[n] = nest(bt.NestingMode, blockType(t, bt.Block))
	}
	return tftypes.Object{AttributeTypes: attrs}
}

func nest(mode string, o tftypes.Type) tftypes.Type {
	switch mode {
	case "list":
		return tftypes.List{ElementType: o}
	case "set":
		return tftypes.Set{ElementType: o}
	case "map":
		return tftypes.Map{ElementType: o}
	}
	return o // single, group
}

// build is the tftypes value of plan JSON j with after_unknown u.
func build(t *testing.T, typ tftypes.Type, j, u any) tftypes.Value {
	t.Helper()
	if u == true {
		return tftypes.NewValue(typ, tftypes.UnknownValue)
	}
	if j == nil || dynamicBearing(typ) && !typ.Is(tftypes.DynamicPseudoType) {
		// The key omits a dynamic-bearing value, and a mixed list of dynamic
		// has no tftypes form.
		return tftypes.NewValue(typ, nil)
	}
	um, _ := u.(map[string]any)
	ul, _ := u.([]any)
	at := func(i int) any {
		if i < len(ul) {
			return ul[i]
		}
		return nil
	}
	switch tt := typ.(type) {
	case tftypes.Object:
		jm := j.(map[string]any)
		vals := map[string]tftypes.Value{}
		for n, a := range tt.AttributeTypes {
			vals[n] = build(t, a, jm[n], um[n])
		}
		return tftypes.NewValue(tt, vals)
	case tftypes.Map:
		vals := map[string]tftypes.Value{}
		for k, e := range j.(map[string]any) {
			vals[k] = build(t, tt.ElementType, e, um[k])
		}
		return tftypes.NewValue(tt, vals)
	case tftypes.List, tftypes.Set, tftypes.Tuple:
		var vals []tftypes.Value
		for i, e := range j.([]any) {
			var et tftypes.Type
			switch tt := tt.(type) {
			case tftypes.List:
				et = tt.ElementType
			case tftypes.Set:
				et = tt.ElementType
			case tftypes.Tuple:
				et = tt.ElementTypes[i]
			}
			vals = append(vals, build(t, et, e, at(i)))
		}
		return tftypes.NewValue(tt, vals)
	}
	if typ.Is(tftypes.DynamicPseudoType) {
		return build(t, implied(j), j, u)
	}
	switch j := j.(type) {
	case json.Number:
		if text, err := NumberText(j.String()); err == nil && text == "0" {
			return tftypes.NewValue(typ, new(big.Float)) // a zero spelling with a huge exponent
		}
		f, _, err := big.ParseFloat(j.String(), 10, 512, big.ToNearestEven)
		if err != nil {
			t.Fatal(err)
		}
		return tftypes.NewValue(typ, f)
	default:
		return tftypes.NewValue(typ, j)
	}
}

// implied is the concrete type of a dynamic JSON value (the key omits it).
func implied(j any) tftypes.Type {
	switch j := j.(type) {
	case string:
		return tftypes.String
	case bool:
		return tftypes.Bool
	case json.Number:
		return tftypes.Number
	case []any:
		var ets []tftypes.Type
		for _, e := range j {
			ets = append(ets, implied(e))
		}
		return tftypes.Tuple{ElementTypes: ets}
	case map[string]any:
		ats := map[string]tftypes.Type{}
		for k, e := range j {
			ats[k] = implied(e)
		}
		return tftypes.Object{AttributeTypes: ats}
	}
	return tftypes.String
}

// msgpackRoundTrip sends v through msgpack like Core's PlannedState.
func msgpackRoundTrip(t *testing.T, typ tftypes.Type, v tftypes.Value) tftypes.Value {
	t.Helper()
	dv, err := tfprotov5.NewDynamicValue(typ, v)
	if err != nil {
		t.Fatal(err)
	}
	out, err := dv.Unmarshal(typ)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestKeyRefusals: the tftypes-side refusals give no key (so nothing
// matches and a required change blocks).
func TestKeyRefusals(t *testing.T) {
	var leaf [32]byte
	setT := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"st": tftypes.Set{ElementType: tftypes.String}, "n": tftypes.Number}}
	val := func(st, n tftypes.Value) tftypes.Value {
		return tftypes.NewValue(setT, map[string]tftypes.Value{"st": st, "n": n})
	}
	strs := tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{tftypes.NewValue(tftypes.String, "a")})
	num := func(s string) tftypes.Value {
		f, _, _ := big.ParseFloat(s, 10, 512, big.ToNearestEven)
		return tftypes.NewValue(tftypes.Number, f)
	}
	unknownSet := tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{tftypes.NewValue(tftypes.String, tftypes.UnknownValue)})
	for name, tc := range map[string]struct {
		v       tftypes.Value
		unknown [][]string
	}{
		"unknown outside paths": {val(unknownSet, num("1")), nil},
		"step into a set":       {val(unknownSet, num("1")), [][]string{{"st", "0"}}},
		"undeclared path":       {val(strs, num("1")), [][]string{{"bogus"}}},
		"exponent too large":    {val(strs, num("10e1000")), nil},
		"exponent too small":    {val(strs, num("1e-1001")), nil},
		"whole value unknown":   {tftypes.NewValue(setT, tftypes.UnknownValue), nil},
	} {
		if _, err := Key(leaf, "edge_thing", FormCreate, tc.v, tc.unknown, nil); err == nil {
			t.Errorf("%s: key computed", name)
		}
	}
	if _, err := Key(leaf, "edge_thing", FormCreate, val(unknownSet, num("1")), [][]string{{"st"}}, nil); err != nil {
		t.Errorf("masked set: %v", err)
	}
	mapT := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"tags": tftypes.Map{ElementType: tftypes.String}}}
	tags := tftypes.NewValue(mapT, map[string]tftypes.Value{"tags": tftypes.NewValue(tftypes.Map{ElementType: tftypes.String},
		map[string]tftypes.Value{"": tftypes.NewValue(tftypes.String, tftypes.UnknownValue), "a": tftypes.NewValue(tftypes.String, "b")})})
	if _, err := Key(leaf, "edge_thing", FormCreate, tags, [][]string{{"tags", ""}}, nil); err != nil {
		t.Errorf("empty map key path: %v", err)
	}
	if _, err := Key(leaf, "edge_thing", FormCreate, tags, [][]string{{""}}, nil); err == nil {
		t.Error("empty attribute step accepted")
	}
	for name, prior := range map[string]string{"no leaf": `{"arn":null}`, "not object": `"x"`, "duplicate": `{"id":"a","id":"b"}`} {
		if _, err := Key(leaf, "edge_thing", FormDelete, tftypes.Value{}, nil, json.RawMessage(prior)); err == nil {
			t.Errorf("prior %s: key computed", name)
		}
	}
}
