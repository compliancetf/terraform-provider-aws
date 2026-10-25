package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/evidence"
)

// verdictGolden is the recording fake of a verdict gate golden: the entries
// it holds and the keys Match must receive, in order ([] = never called).
type verdictGolden struct {
	Entries  []goldenKey `json:"entries"`
	WantKeys []goldenKey `json:"want_keys"`
}

// goldenKey is an InstanceKey in golden form; type_name defaults to the
// golden's type for the mutation forms.
type goldenKey struct {
	Form              KeyForm         `json:"form"`
	TypeName          string          `json:"type_name,omitempty"`
	Planned           json.RawMessage `json:"planned,omitempty"`
	PriorIdentityKind string          `json:"prior_identity_kind,omitempty"`
	PriorIdentity     json.RawMessage `json:"prior_identity,omitempty"`
	Method            string          `json:"method,omitempty"`
	Request           string          `json:"request,omitempty"`
}

// recordingVerdict matches by exact equality of every key field and records
// each key it receives.
type recordingVerdict struct {
	entries []InstanceKey
	got     []InstanceKey
}

func (r *recordingVerdict) Match(_ context.Context, k InstanceKey) error {
	r.got = append(r.got, k)
	for _, e := range r.entries {
		if e.Equal(k) {
			return nil
		}
	}
	return errors.New("no verdict entry matches this instance")
}

func (k goldenKey) key(t *testing.T, typeName string) InstanceKey {
	t.Helper()
	out := InstanceKey{Form: k.Form, TypeName: k.TypeName, PriorIdentityKind: k.PriorIdentityKind, Method: k.Method}
	if k.Form != KeyRPC {
		out.Planned = tftypes.NewValue(dbType, nil)
		if out.TypeName == "" {
			out.TypeName = typeName
		}
	}
	if len(k.Planned) > 0 {
		out.Planned = objValue(t, k.Planned)
	}
	if len(k.PriorIdentity) > 0 {
		var buf bytes.Buffer
		if err := json.Compact(&buf, k.PriorIdentity); err != nil {
			t.Fatal(err)
		}
		out.PriorIdentity = buf.Bytes()
	}
	if k.Request != "" {
		out.Request = []byte(k.Request)
	}
	return out
}

// TestVerdictGate runs the verdict gate goldens: the apply_pre gate
// for every type and op, the key forms and the RPC scope. Each
// zero-control golden runs again with verdict_required false and must pass
// without diagnostics, Match calls or gate results.
func TestVerdictGate(t *testing.T) {
	for _, pattern := range []string{"apply_verdict_gate_*.json", "verdict_gate_*.json"} {
		runStages(t, pattern, installVerdict(false))
	}
	runStages(t, "apply_verdict_gate_*_zero_control.json", installVerdict(true))
}

func installVerdict(notRequired bool) func(*testing.T, *stageGolden, *Lifecycle) {
	return func(t *testing.T, g *stageGolden, l *Lifecycle) {
		if g.Stage == "" {
			t.Skip("proxy-level: the method never reaches Evaluate (internal/proxy TestVerdictGateScope)")
		}
		if notRequired {
			g.Verdict = &verdictGolden{WantKeys: []goldenKey{}}
			g.Want.Diagnostics = []wantDiag{}
			g.Want.Evidence.Results = []wantResult{}
			l.cfg.Table.VerdictRequired = false
		}
		if g.Verdict == nil {
			return // the production noVerdict stub
		}
		rec := &recordingVerdict{}
		for _, e := range g.Verdict.Entries {
			rec.entries = append(rec.entries, e.key(t, g.TypeName))
		}
		l.verdict = rec
		t.Cleanup(func() {
			want := []InstanceKey{}
			for _, k := range g.Verdict.WantKeys {
				want = append(want, k.key(t, g.TypeName))
			}
			if got := rec.got; len(got) != len(want) || !slices.EqualFunc(got, want, func(a, b InstanceKey) bool {
				// Planned is checked by the match outcome; the form fields here.
				a.Planned, b.Planned = tftypes.Value{}, tftypes.Value{}
				return a.Equal(b)
			}) {
				t.Errorf("Match keys\n got %+v\nwant %+v", got, want)
			}
		})
	}
}

// TestNoVerdict pins the no-verdict stub text and that a zero Lifecycle fails
// closed through it.
func TestNoVerdict(t *testing.T) {
	const want = "This change needs a verdict (profile sets verdict_required). Apply through ctfkit apply or the configured runner."
	if err := (&Lifecycle{}).verdictSource().Match(context.Background(), InstanceKey{Form: KeyCreate}); err == nil || err.Error() != want {
		t.Fatalf("noVerdict = %v, want %q", err, want)
	}
	if _, ok := New(Options{}).verdict.(noVerdict); !ok {
		t.Fatal("New must install noVerdict")
	}
}

func checkNoEvalRecord(t *testing.T, recs []evidence.Record) {
	t.Helper()
	for _, r := range recs {
		if r.Kind == evidence.KindEval {
			t.Fatalf("want no eval record, got %+v", r)
		}
	}
}

// TestVerdictGateGoldensNamed keeps the golden set the task names.
func TestVerdictGateGoldensNamed(t *testing.T) {
	var names []string
	for _, n := range []string{"create", "update", "delete"} {
		names = append(names, "apply_verdict_gate_"+n+"_zero_control", "apply_verdict_gate_key_form_"+n)
	}
	for _, n := range []string{"read", "read_data", "read_data_deferred", "plan", "import", "configure", "validate", "schema", "invoke_action", "unclassified"} {
		names = append(names, "verdict_gate_rpc_scope_"+n)
	}
	for _, n := range names {
		if m, _ := filepath.Glob(filepath.Join("testdata/stages", n+".json")); len(m) != 1 {
			t.Errorf("missing golden %s", n)
		}
	}
}

// TestBothHalves runs the replace halves oracle at plan: both
// halves fire with their half and a block in either blocks. A tainted (or
// -replace) replacement reaches the provider as a create with a null prior,
// so only its create half is visible at plan.
func TestBothHalves(t *testing.T) {
	requireGoldens(t, "plan_replace_both_halves", "plan_deposed_destroy_both_halves", "plan_tainted_replace_both_halves")
	runStages(t, "plan_*_both_halves.json")
}

// requireGoldens fails when a golden the oracle names is missing, so a glob
// never passes on fewer files.
func requireGoldens(t *testing.T, names ...string) {
	t.Helper()
	for _, n := range names {
		if _, err := os.Stat(filepath.Join("testdata/stages", n+".json")); err != nil {
			t.Errorf("missing golden %s", n)
		}
	}
}

// TestOwnHalf runs the apply side of the oracle: each RPC runs only its
// own half and hands Verdict exactly one recomputed key, its own.
func TestOwnHalf(t *testing.T) {
	requireGoldens(t, "apply_replace_destroy_rpc_own_half", "apply_replace_create_rpc_own_half",
		"apply_deposed_cleanup_standalone_own_half", "apply_partial_apply_deposed_cleanup_own_half", "apply_one_byte_key_own_half")
	runStages(t, "apply_*_own_half.json", installVerdict(false))
}

// TestVerdictKeys pins the key contract: Equal is exact, so a key that
// differs from an entry in any field by one byte does not match.
func TestVerdictKeys(t *testing.T) {
	planned := func(engine string) tftypes.Value {
		return objValue(t, json.RawMessage(`{"storage_encrypted":true,"engine":"`+engine+`"}`))
	}
	base := InstanceKey{Form: KeyUpdate, TypeName: "aws_db_instance", Planned: planned("postgres"),
		PriorIdentityKind: "id", PriorIdentity: json.RawMessage(`{"id":"db-1"}`),
		Method: "/tfplugin5.Provider/X", Request: []byte{0x0a, 0x01}}
	if same := base; !base.Equal(same) {
		t.Fatal("a key must equal an identical key")
	}
	for name, mutate := range map[string]func(*InstanceKey){
		"form":           func(k *InstanceKey) { k.Form = KeyCreate },
		"type_name":      func(k *InstanceKey) { k.TypeName = "aws_db_instancf" },
		"planned":        func(k *InstanceKey) { k.Planned = planned("postgret") },
		"identity_kind":  func(k *InstanceKey) { k.PriorIdentityKind = "if" },
		"prior_identity": func(k *InstanceKey) { k.PriorIdentity = json.RawMessage(`{"id":"db-2"}`) },
		"identity_space": func(k *InstanceKey) { k.PriorIdentity = json.RawMessage(`{"id": "db-1"}`) },
		"method":         func(k *InstanceKey) { k.Method = "/tfplugin5.Provider/Y" },
		"request":        func(k *InstanceKey) { k.Request = []byte{0x0a, 0x02} },
		"request_extra":  func(k *InstanceKey) { k.Request = []byte{0x0a, 0x01, 0x00} },
	} {
		k := base
		mutate(&k)
		if base.Equal(k) || k.Equal(base) {
			t.Errorf("%s: a one-byte difference matched", name)
		}
	}
	// The delete and rpc forms the own-half goldens rely on.
	del := InstanceKey{Form: KeyDelete, TypeName: "aws_db_instance", Planned: tftypes.NewValue(dbType, nil),
		PriorIdentityKind: "id", PriorIdentity: json.RawMessage(`{"id":"db-1"}`)}
	rpc := InstanceKey{Form: KeyRPC, Method: "/tfplugin5.Provider/X", Request: []byte{0x0a}}
	for name, c := range map[string]struct {
		a, b InstanceKey
		want bool
	}{
		"delete_same":           {del, func() InstanceKey { k := del; k.PriorIdentity = json.RawMessage(`{"id":"db-1"}`); return k }(), true},
		"delete_one_byte":       {del, func() InstanceKey { k := del; k.PriorIdentity = json.RawMessage(`{"id":"db-2"}`); return k }(), false},
		"delete_zero_planned":   {del, func() InstanceKey { k := del; k.Planned = tftypes.Value{}; return k }(), false},
		"delete_dynamic_null":   {del, func() InstanceKey { k := del; k.Planned = tftypes.NewValue(tftypes.DynamicPseudoType, nil); return k }(), false},
		"rpc_same":              {rpc, func() InstanceKey { k := rpc; k.Request = []byte{0x0a}; return k }(), true},
		"rpc_request_one_byte":  {rpc, func() InstanceKey { k := rpc; k.Request = []byte{0x0b}; return k }(), false},
		"rpc_nil_empty_request": {InstanceKey{Form: KeyRPC}, InstanceKey{Form: KeyRPC, Request: []byte{}}, true},
	} {
		if got := c.a.Equal(c.b); got != c.want || c.b.Equal(c.a) != c.want {
			t.Errorf("%s: Equal = %v, want %v", name, got, c.want)
		}
	}
}
