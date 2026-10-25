//go:build conformance

package harness

// An in-repo stand-in for `ctfkit gate plan` and `ctfkit gate sign`:
// plan to a planfile, read its plan JSON
// and the provider schemas, compute each change's instance_key and
// delete_key with internal/verdict.Key from the plan side (instance_key
// FORMAT.md v1 kind rules) and sign the verdict. The provider recomputes
// every key from the apply request, so a pass proves the plan side and the
// provider side agree. It never matches controls itself: every entry starts
// with no decisions and a test sets the ones it needs.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/verdict"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict/verdicttest"
)

// Plan is a saved plan: its planfile (relative to the work dir), digest
// (sha256 of the planfile bytes, B7), decoded plan JSON and the plan run's
// output.
type Plan struct {
	File, Digest string
	Doc          PlanDoc
	Out          Result
}

// PlanDoc is the part of a plan JSON document the stand-ins read.
type PlanDoc struct {
	ResourceChanges []PlanChange `json:"resource_changes"`
	Configuration   struct {
		ProviderConfig map[string]struct {
			Expressions map[string]struct {
				ConstantValue json.RawMessage `json:"constant_value"`
			} `json:"expressions"`
		} `json:"provider_config"`
	} `json:"configuration"`
}

// PlanChange is the part of a plan JSON resource change the stand-ins read.
type PlanChange struct {
	Address         string `json:"address"`
	PreviousAddress string `json:"previous_address"`
	Type            string `json:"type"`
	Mode            string `json:"mode"`
	Deposed         string `json:"deposed"`
	ActionReason    string `json:"action_reason"`
	Change          struct {
		Actions        []string                   `json:"actions"`
		Importing      json.RawMessage            `json:"importing"`
		Before         map[string]json.RawMessage `json:"before"`
		After          map[string]json.RawMessage `json:"after"`
		AfterUnknown   map[string]any             `json:"after_unknown"`
		BeforeIdentity map[string]json.RawMessage `json:"before_identity"`
	} `json:"change"`
}

// SavePlan runs `plan -out=<name>.tfplan` (refresh on) with args and reads
// the plan.
func (r *Run) SavePlan(name string, args ...string) *Plan {
	r.T.Helper()
	p := &Plan{File: name + ".tfplan"}
	p.Out = r.Must(append([]string{"plan", "-no-color", "-input=false", "-out=" + p.File}, args...)...)
	b, err := os.ReadFile(filepath.Join(r.Work, p.File))
	if err != nil {
		r.T.Fatal(err)
	}
	sum := sha256.Sum256(b)
	p.Digest = "sha256:" + hex.EncodeToString(sum[:])
	r.Decode(r.Must("show", "-json", p.File).Stdout, &p.Doc)
	return p
}

// Gate is one gated plan: the run secret and the verdict entries computed
// from the plan.
type Gate struct {
	*Plan
	Secret    []byte
	Instances []verdict.Instance
	Changes   []PlanChange // the managed changes of the plan, in plan order
	Schemas   map[string]Schema
}

// GatePlan saves a plan (SavePlan) and builds one verdict entry per managed
// change (no-op and read changes carry no entry: nothing applies them).
// Every entry starts with no decisions.
func (r *Run) GatePlan(name string, args ...string) *Gate {
	r.T.Helper()
	g := &Gate{Plan: r.SavePlan(name, args...), Secret: make([]byte, 32)}
	if _, err := rand.Read(g.Secret); err != nil {
		r.T.Fatal(err)
	}
	g.Schemas = r.Schemas()
	leaf := verdicttest.Leaf(r.T, g.Secret)
	for _, c := range g.Doc.ResourceChanges {
		if c.Mode != "managed" {
			continue
		}
		g.Changes = append(g.Changes, c)
		in, ok, err := InstanceFor(leaf, g.Schemas, c)
		if err != nil {
			r.T.Fatalf("gate plan %s: %v", c.Address, err)
		}
		if ok {
			g.Instances = append(g.Instances, in)
		}
	}
	return g
}

// GateSign signs g's entries (after edit, when set) plus extra and the
// top-level baselines (by digest) under binding b with k (Sign).
func (r *Run) GateSign(g *Gate, k verdicttest.Key, b verdicttest.Binding, edit func([]verdict.Instance), extra []verdict.Instance, baselines ...string) {
	r.T.Helper()
	ins := slices.Clone(g.Instances)
	if edit != nil {
		edit(ins)
	}
	ins = append(ins, extra...)
	refs := make([]verdict.BaselineRef, len(baselines))
	for i, d := range baselines {
		refs[i] = verdict.BaselineRef{Digest: d}
	}
	var err error
	if b.Instances, err = json.Marshal(ins); err == nil {
		b.Baselines, err = json.Marshal(refs)
	}
	if err != nil {
		r.T.Fatal(err)
	}
	b.Secret = g.Secret
	r.Sign(k, b)
}

// Schema is one resource type's attribute types and whether it has an
// identity schema.
type Schema struct {
	Attrs    map[string]tftypes.Type
	Identity bool
}

// Schemas reads `providers schema -json` for the proxy's resource types.
func (r *Run) Schemas() map[string]Schema {
	r.T.Helper()
	var doc struct {
		Providers map[string]struct {
			Resources map[string]struct {
				Block struct {
					Attributes map[string]struct {
						Type json.RawMessage `json:"type"`
					} `json:"attributes"`
				} `json:"block"`
			} `json:"resource_schemas"`
			Identities map[string]json.RawMessage `json:"resource_identity_schemas"`
		} `json:"provider_schemas"`
	}
	r.Decode(r.Must("providers", "schema", "-json").Stdout, &doc)
	p, ok := doc.Providers[ProviderSource]
	if !ok {
		r.T.Fatalf("providers schema: no %s", ProviderSource)
	}
	out := map[string]Schema{}
	for typ, rs := range p.Resources {
		s := Schema{Attrs: map[string]tftypes.Type{}}
		_, s.Identity = p.Identities[typ]
		for name, a := range rs.Block.Attributes {
			// shortcut: primitive attributes only (the fake upstream has no
			// others); a nested or collection type needs a full plan JSON adapter.
			var tn string
			at, known := tftypes.Type(nil), false
			if json.Unmarshal(a.Type, &tn) == nil {
				at, known = map[string]tftypes.Type{"string": tftypes.String, "number": tftypes.Number, "bool": tftypes.Bool}[tn]
			}
			if !known {
				r.T.Fatalf("providers schema: %s.%s has type %s, the gate stand-in reads primitives only", typ, name, a.Type)
			}
			s.Attrs[name] = at
		}
		out[typ] = s
	}
	return out
}

// InstanceFor is the verdict entry of change c, ok false for an action
// that applies nothing (no-op, read).
func InstanceFor(leaf [32]byte, sch map[string]Schema, c PlanChange) (verdict.Instance, bool, error) {
	in := verdict.Instance{Address: c.Address, Deposed: c.Deposed, Type: c.Type, Refreshed: "true", UnknownPaths: [][]string{},
		Decisions: []verdict.Decision{}, NotEvaluable: []verdict.NotEvaluable{}, Exceptions: []string{}, Baselines: []string{}, BreakGlass: []string{}}
	acts := c.Change.Actions
	create, del := slices.Contains(acts, "create"), slices.Contains(acts, "delete")
	switch {
	case slices.Equal(acts, []string{"update"}):
		in.Action = "update"
	case create && del:
		in.Action = "replace"
	case create:
		in.Action = "create"
	case del:
		in.Action = "delete"
	default:
		return in, false, nil
	}
	s, ok := sch[c.Type]
	if !ok {
		return in, false, fmt.Errorf("no schema for %s", c.Type)
	}
	if in.Action != "delete" {
		planned, unknown, err := PlannedValue(s, c.Change.After, c.Change.AfterUnknown)
		if err != nil {
			return in, false, err
		}
		in.UnknownPaths = unknown
		form := verdict.FormUpdate
		if in.Action != "update" {
			form = verdict.FormCreate
		}
		var prior json.RawMessage
		kind := verdict.KindNone
		if form == verdict.FormUpdate {
			if kind, prior, err = PriorIdentity(s, c); err != nil {
				return in, false, err
			}
		}
		if in.InstanceKey, err = verdict.Key(leaf, c.Type, form, planned, unknown, prior); err != nil {
			return in, false, err
		}
		in.PriorIdentityKind = kind
	}
	if del {
		kind, prior, err := PriorIdentity(s, c)
		if err == nil {
			in.DeleteKey, err = verdict.Key(leaf, c.Type, verdict.FormDelete, tftypes.Value{}, nil, prior)
		}
		if err != nil {
			return in, false, err
		}
		in.PriorIdentityKind, in.DeleteDecisions = kind, []verdict.Decision{}
	}
	return in, true, nil
}

// PriorIdentity is the FORMAT.md v1 prior (native) identity of an update or
// delete: kind identity from change.before_identity when the type has an
// identity schema and the object has a non-null leaf, else kind id
// {"id": before.id} (the identity object takes precedence over the id).
// The destroy half of a tainted replace is always kind id, whatever
// before_identity holds (FORMAT.md v1 rule 1: OpenTofu plans a tainted
// object with its identity; the provider keys that half kind id).
func PriorIdentity(s Schema, c PlanChange) (string, json.RawMessage, error) {
	tainted := c.ActionReason == "replace_because_tainted"
	if s.Identity && !tainted && slices.ContainsFunc(mapsValues(c.Change.BeforeIdentity), func(v json.RawMessage) bool { return string(v) != "null" }) {
		b, err := json.Marshal(c.Change.BeforeIdentity)
		return verdict.KindIdentity, b, err
	}
	var id string
	if err := json.Unmarshal(c.Change.Before["id"], &id); err != nil || id == "" {
		return "", nil, fmt.Errorf("prior state has no id: %w", err)
	}
	b, err := json.Marshal(map[string]string{"id": id})
	return verdict.KindID, b, err
}

func mapsValues(m map[string]json.RawMessage) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// PlannedValue is the object of s from plan JSON values (after, or before
// for a prior object) and after_unknown, with each unknown top-level
// attribute as an unknown path (sorted).
func PlannedValue(s Schema, vals map[string]json.RawMessage, unknown map[string]any) (tftypes.Value, [][]string, error) {
	types := map[string]tftypes.Type{}
	out := map[string]tftypes.Value{}
	var paths [][]string
	for name, typ := range s.Attrs {
		if typ == nil {
			return tftypes.Value{}, nil, fmt.Errorf("attribute %s: unsupported type", name)
		}
		types[name] = typ
		if unknown[name] == true {
			out[name] = tftypes.NewValue(typ, tftypes.UnknownValue)
			paths = append(paths, []string{name})
			continue
		}
		raw, ok := vals[name]
		if !ok || string(raw) == "null" {
			out[name] = tftypes.NewValue(typ, nil)
			continue
		}
		var v any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			return tftypes.Value{}, nil, err
		}
		if n, ok := v.(json.Number); ok {
			f, _, err := big.ParseFloat(n.String(), 10, 512, big.ToNearestEven)
			if err != nil {
				return tftypes.Value{}, nil, err
			}
			v = f
		}
		out[name] = tftypes.NewValue(typ, v)
	}
	slices.SortFunc(paths, func(a, b []string) int { return strings.Compare(a[0], b[0]) })
	if paths == nil {
		paths = [][]string{}
	}
	return tftypes.NewValue(tftypes.Object{AttributeTypes: types}, out), paths, nil
}
