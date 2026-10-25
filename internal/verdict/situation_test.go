package verdict

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/verdict/verdicttest"
)

type situationCase struct {
	Verdict  bool        `json:"verdict"`
	Required bool        `json:"required"`
	Delete   bool        `json:"delete"`
	Type     string      `json:"type"`
	Matches  []*Instance `json:"matches"`
	Graph    []struct {
		ID           string `json:"id"`
		Version      string `json:"version"`
		Message      string `json:"message"`
		FailSeverity string `json:"fail_severity"`
	} `json:"graph"`
	Excepted []string `json:"excepted"`
	Want     []Row    `json:"want"`
}

// apply is the situation input of c.
func (c situationCase) apply() Apply {
	a := Apply{Required: c.Required, Type: c.Type, Delete: c.Delete, Matches: c.Matches,
		Excepted: func(id string) bool { return slices.Contains(c.Excepted, id) }}
	if c.Verdict {
		a.Verdict = &Verdict{}
	}
	for _, g := range c.Graph {
		a.Graph = append(a.Graph, Graph{ID: g.ID, Version: g.Version, Message: g.Message, FailSeverity: g.FailSeverity})
	}
	return a
}

// TestSituations runs testdata/situations: the situation table rows, given
// the matched entries of the RPC's own half.
func TestSituations(t *testing.T) {
	files, _ := filepath.Glob("testdata/situations/*.json")
	if len(files) < 20 {
		t.Fatalf("%d situation fixtures", len(files))
	}
	for _, f := range files {
		t.Run(strings.TrimSuffix(filepath.Base(f), ".json"), func(t *testing.T) {
			var c situationCase
			b, err := os.ReadFile(f)
			if err == nil {
				err = json.Unmarshal(b, &c)
			}
			if err != nil {
				t.Fatal(err)
			}
			got := Situation(c.apply())
			if len(got) != len(c.Want) {
				t.Fatalf("rows %+v, want %+v", got, c.Want)
			}
			for i, w := range c.Want {
				g := got[i]
				if g.Control != w.Control || g.Version != w.Version || g.Result != w.Result || g.Severity != w.Severity || w.Text != "" && g.Text != w.Text {
					t.Errorf("row %d: %+v, want %+v", i, g, w)
				}
			}
		})
	}
}

// matchVerdict is a verdict with entries keyed by a fresh run key.
func matchVerdict(t *testing.T) *Verdict {
	t.Helper()
	v := &Verdict{}
	if _, err := rand.Read(v.leaf[:]); err != nil {
		t.Fatal(err)
	}
	return v
}

var bucketType = tftypes.Object{AttributeTypes: map[string]tftypes.Type{"bucket": tftypes.String, "id": tftypes.String}}

func bucket(name string, id any) tftypes.Value {
	return tftypes.NewValue(bucketType, map[string]tftypes.Value{
		"bucket": tftypes.NewValue(tftypes.String, name), "id": tftypes.NewValue(tftypes.String, id)})
}

func mustKey(t *testing.T, v *Verdict, form Form, planned tftypes.Value, unknown [][]string, prior string) string {
	t.Helper()
	var p json.RawMessage
	if prior != "" {
		p = json.RawMessage(prior)
	}
	k, err := Key(v.leaf, "aws_s3_bucket", form, planned, unknown, p)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestMatchForms: each RPC matches only its own form and field
// and the derived prior kind.
func TestMatchForms(t *testing.T) {
	v := matchVerdict(t)
	planned := bucket("bobthecorp-logs", "bobthecorp-logs")
	unknownID := tftypes.NewValue(bucketType, map[string]tftypes.Value{
		"bucket": tftypes.NewValue(tftypes.String, "bobthecorp-logs"), "id": tftypes.NewValue(tftypes.String, tftypes.UnknownValue)})
	prior := `{"id":"bobthecorp-logs"}`
	create := Instance{Address: "aws_s3_bucket.c", Type: "aws_s3_bucket", Action: "create", PriorIdentityKind: KindNone,
		InstanceKey: mustKey(t, v, FormCreate, unknownID, [][]string{{"id"}}, ""), UnknownPaths: [][]string{{"id"}}}
	update := Instance{Address: "aws_s3_bucket.u", Type: "aws_s3_bucket", Action: "update", PriorIdentityKind: KindID,
		InstanceKey: mustKey(t, v, FormUpdate, planned, nil, prior)}
	del := Instance{Address: "aws_s3_bucket.d", Type: "aws_s3_bucket", Action: "delete", PriorIdentityKind: KindID,
		DeleteKey: mustKey(t, v, FormDelete, tftypes.Value{}, nil, prior)}
	deposed := del
	deposed.Address, deposed.Deposed = "aws_s3_bucket.x", "b0b7ec01"
	deposed.DeleteKey = mustKey(t, v, FormDelete, tftypes.Value{}, nil, `{"id":"bobthecorp-logs-old"}`)
	v.Doc.Instances = []Instance{create, update, del}
	v.idx = buildIndex(v.Doc.Instances)
	addrs := func(q Query) []string {
		t.Helper()
		ms, _ := v.Match(q)
		var out []string
		for _, m := range ms {
			out = append(out, m.Address)
		}
		return out
	}
	for name, tc := range map[string]struct {
		q    Query
		want []string
	}{
		"create": {Query{Form: FormCreate, Type: "aws_s3_bucket", Planned: unknownID}, []string{"aws_s3_bucket.c"}},
		// H2: identical planned attributes, but an update RPC never matches the create-form entry.
		"update":            {Query{Form: FormUpdate, Type: "aws_s3_bucket", Planned: planned, PriorKind: KindID, Prior: json.RawMessage(prior)}, []string{"aws_s3_bucket.u"}},
		"update wrong kind": {Query{Form: FormUpdate, Type: "aws_s3_bucket", Planned: planned, PriorKind: KindIdentity, Prior: json.RawMessage(prior)}, nil},
		"destroy":           {Query{Form: FormDelete, Type: "aws_s3_bucket", PriorKind: KindID, Prior: json.RawMessage(prior)}, []string{"aws_s3_bucket.d"}},
		"other type":        {Query{Form: FormDelete, Type: "aws_s3_bucket_policy", PriorKind: KindID, Prior: json.RawMessage(prior)}, nil},
	} {
		if got := addrs(tc.q); !slices.Equal(got, tc.want) {
			t.Errorf("%s: matched %v, want %v", name, got, tc.want)
		}
	}
	// A create-form entry with the planned attributes of the update: still only the update matches it.
	v.Doc.Instances = []Instance{{Address: "aws_s3_bucket.cf", Type: "aws_s3_bucket", Action: "create", PriorIdentityKind: KindNone,
		InstanceKey: mustKey(t, v, FormCreate, planned, nil, "")}}
	v.idx = buildIndex(v.Doc.Instances)
	if got := addrs(Query{Form: FormUpdate, Type: "aws_s3_bucket", Planned: planned, PriorKind: KindID, Prior: json.RawMessage(prior)}); got != nil {
		t.Errorf("update RPC matched the create-form entry %v", got)
	}
	// Replace: the destroy RPC matches delete_key, the create RPC instance_key.
	repl := Instance{Address: "aws_s3_bucket.r", Type: "aws_s3_bucket", Action: "replace", PriorIdentityKind: KindID,
		InstanceKey: mustKey(t, v, FormCreate, planned, nil, ""), DeleteKey: mustKey(t, v, FormDelete, tftypes.Value{}, nil, prior)}
	v.Doc.Instances = []Instance{repl, deposed}
	v.idx = buildIndex(v.Doc.Instances)
	if got := addrs(Query{Form: FormCreate, Type: "aws_s3_bucket", Planned: planned}); !slices.Equal(got, []string{"aws_s3_bucket.r"}) {
		t.Errorf("replace create half: %v", got)
	}
	if got := addrs(Query{Form: FormDelete, Type: "aws_s3_bucket", PriorKind: KindID, Prior: json.RawMessage(prior)}); !slices.Equal(got, []string{"aws_s3_bucket.r"}) {
		t.Errorf("replace destroy half: %v", got)
	}
	// A standalone deposed cleanup matches its delete-scoped entry only.
	if got := addrs(Query{Form: FormDelete, Type: "aws_s3_bucket", PriorKind: KindID, Prior: json.RawMessage(`{"id":"bobthecorp-logs-old"}`)}); !slices.Equal(got, []string{"aws_s3_bucket.x"}) {
		t.Errorf("deposed cleanup: %v", got)
	}
}

// TestValidateInstances: structural defects reject the whole verdict at load.
func TestValidateInstances(t *testing.T) {
	k := "sha256:" + strings.Repeat("a", 64)
	ok := func() Instance {
		return Instance{Address: "aws_s3_bucket.a", Type: "aws_s3_bucket", Action: "delete", PriorIdentityKind: KindID, Refreshed: "true",
			DeleteKey: k, DeleteDecisions: []Decision{}}
	}
	for name, mut := range map[string]func(*Instance){
		"deposed non-delete":       func(in *Instance) { in.Deposed, in.Action, in.InstanceKey = "b0b7ec01", "replace", k },
		"delete with instance_key": func(in *Instance) { in.InstanceKey = k },
		"create with prior kind":   func(in *Instance) { in.Action, in.InstanceKey, in.DeleteKey, in.DeleteDecisions = "create", k, "", nil },
		"no-op with a key":         func(in *Instance) { in.Action = "no-op" },
		"duplicate decision": func(in *Instance) {
			d := Decision{Control: "c", Version: "1.0.0", Result: ResultPass, Action: "deny"}
			in.DeleteDecisions = []Decision{d, d}
		},
		"unknown result": func(in *Instance) {
			in.DeleteDecisions = []Decision{{Control: "c", Version: "1.0.0", Result: "unknown", Action: "deny"}}
		},
		"unlisted exception":  func(in *Instance) { in.Exceptions = []string{k} },
		"delete unknown path": func(in *Instance) { in.UnknownPaths = [][]string{{"id"}} },
		"bad reason":          func(in *Instance) { in.NotEvaluable = []NotEvaluable{{Control: "c", Reason: "maybe"}} },
	} {
		in := ok()
		mut(&in)
		if err := (&Document{Instances: []Instance{in}}).validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := (&Document{Instances: []Instance{ok()}}).validate(); err != nil {
		t.Fatalf("valid delete entry: %v", err)
	}
	// FORMAT.md allows any map key in an unknown path, the empty one included.
	create := Instance{Address: "aws_s3_bucket.a", Type: "aws_s3_bucket", Action: "create", PriorIdentityKind: KindNone, Refreshed: "true",
		InstanceKey: k, UnknownPaths: [][]string{{"tags", ""}}}
	if err := (&Document{Instances: []Instance{create}}).validate(); err != nil {
		t.Fatalf("empty map key in unknown_paths: %v", err)
	}
}

// TestRequiredArraysAtLoad: a required nested array given
// as explicit null, or left out, rejects the whole verdict at parse; [] is
// accepted.
func TestRequiredArraysAtLoad(t *testing.T) {
	k := `"sha256:` + strings.Repeat("a", 64) + `"`
	base := map[string]string{"address": `"aws_s3_bucket.a"`, "type": `"aws_s3_bucket"`, "action": `"delete"`, "prior_identity_kind": `"id"`,
		"refreshed": `"true"`, "delete_key": k, "unknown_paths": `[]`, "decisions": `[]`, "delete_decisions": `[]`, "not_evaluable": `[]`,
		"exceptions": `[]`, "baselines": `[]`, "break_glass": `[]`}
	doc := func(member, value string) []byte {
		t.Helper()
		in := map[string]json.RawMessage{}
		for m, v := range base {
			if m != member || value != "" {
				if m == member {
					v = value
				}
				in[m] = json.RawMessage(v)
			}
		}
		raw, _ := json.Marshal([]any{in})
		d := verdicttest.Doc(t, verdicttest.Binding{OrgID: "bobthecorp", IssuedAt: time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC), Instances: raw}, make([]byte, 32))
		d["signature"] = json.RawMessage(`{"alg":"ES256","kid":"k","value":"v"}`)
		out, _ := json.Marshal(d)
		return out
	}
	if _, _, _, err := parse(doc("", "")); err != nil {
		t.Fatalf("all arrays []: %v", err)
	}
	for _, m := range []string{"unknown_paths", "decisions", "delete_decisions", "not_evaluable", "exceptions", "baselines", "break_glass"} {
		for _, v := range []string{"null", ""} { // explicit null, member left out
			if _, _, _, err := parse(doc(m, v)); err == nil {
				t.Errorf("%s=%q: accepted", m, v)
			}
		}
	}
}

// TestSituationBreakGlass: a covered fail or not_evaluable row
// blocks no more and carries the override id, a covered provisional one is
// proven, pending and pass are never overridden, and an uncovered control
// keeps its row.
func TestSituationBreakGlass(t *testing.T) {
	for result, want := range map[string]Row{
		ResultFail:         {Result: SitFail, Severity: SevWarning, BreakGlassID: "ovr-01"},
		ResultNotEvaluable: {Result: SitNotEvaluable, Severity: SevWarning, BreakGlassID: "ovr-01"},
		ResultProvisional:  {Result: SitExcepted, Severity: SevNone, BreakGlassID: "ovr-01"},
		ResultPending:      {Result: SitPending, Severity: SevWarning},
		ResultPass:         {Result: SitPass, Severity: SevNone},
	} {
		in := &Instance{Address: "aws_s3_bucket.a", Decisions: []Decision{{Control: "c1", Version: "1", Result: result}, {Control: "c2", Version: "1", Result: result}}}
		a := Apply{Verdict: &Verdict{}, Type: "aws_s3_bucket", Matches: []*Instance{in},
			Graph: []Graph{{ID: "c1", Version: "1", FailSeverity: SevError}, {ID: "c2", Version: "1", FailSeverity: SevError}},
			BreakGlass: func(control, r string) (string, bool) {
				return "ovr-01", control == "c1" && r != ResultPending && r != ResultPass
			}}
		rows := Situation(a)
		if g := rows[0]; g.Result != want.Result || g.Severity != want.Severity || g.BreakGlassID != want.BreakGlassID {
			t.Errorf("%s covered: %+v, want %+v", result, g, want)
		}
		if g := rows[1]; g.BreakGlassID != "" || result != ResultPass && result != ResultPending && g.Severity != SevError {
			t.Errorf("%s uncovered: %+v", result, g)
		}
	}
}
