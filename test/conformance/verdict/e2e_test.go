//go:build conformance

package verdict

// Verdict E2E conformance: gate plan to apply,
// collision, tamper, no verdict, prior_identity round trip, envelope
// mutation, replace (create-before-destroy, destroy-before-create),
// tainted and deposed objects, standalone deposed cleanup after a partial
// apply, key files. Every failing case asserts fail closed: Terraform exits
// non-zero and the blocked change never reaches state. Rotation and
// revocation are in rotation_test.go. What needs ctfkit itself
// (`ctfkit apply` refusing a plan, `gate sign` refusing a non-delete entry
// for a deposed object, the 20-type plan) is out of scope here; gatePlan
// stands in for gate plan and gate sign.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/verdict"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict/verdicttest"
	"github.com/compliancetf/terraform-provider-aws/test/conformance/harness"
)

const header = `terraform {
  required_providers {
    fake = { source = "registry.compliance.tf/compliancetf/aws" }
  }
}
`

// thingsTF: fake_thing has an identity schema (prior kind identity where
// the binary sends identities), fake_replace none (kind id).
const thingsTF = header + `
variable "size" {
  type    = number
  default = 2
}

resource "fake_thing" "a" {
  name = "bobthecorp-a"
  size = var.size
}

resource "fake_replace" "b" {
  name = "bobthecorp-b"
  size = var.size
}
`

// replaceTF is one fake_replace whose name change forces a replace; cbd
// sets create_before_destroy.
func replaceTF(cbd bool) string {
	return header + fmt.Sprintf(`
variable "name" {
  type    = string
  default = "bobthecorp-r1"
}

variable "size" {
  type    = number
  default = 2
}

resource "fake_replace" "r" {
  name = var.name
  size = var.size
  lifecycle {
    create_before_destroy = %t
  }
}
`, cbd)
}

// graphControls puts two graph controls on each fake type: a companion
// control the create and update halves decide (decisions) and a deletion
// guard whose companion is that type, which the destroy half decides
// (delete_decisions). A type with graph
// controls looks up its verdict entry on every mutation even without
// verdict_required, and under hard_fail a no_match, collision or failing
// decision blocks.
var graphControls = `[{"id": "fake_thing_size_max", "version": "1.0.0", "kind": "resource", "resource_type": "fake_thing",
  "reads": ["size"], "presence_mode": "effective", "on": ["create", "update"],
  "expr": "resource.size != null && resource.size <= 10", "action": "deny", "severity": "high",
  "message": "fake_thing size must be at most 10.", "fix": "Set size to 10 or less.", "exemption_coverable": []}` +
	graphPair("fake_replace", "fake_thing") + graphPair("fake_thing", "fake_replace") + "]"

func graphPair(typ, other string) string {
	return fmt.Sprintf(`,
 {"id": "%[1]s_companion", "version": "1.0.0", "kind": "graph", "resource_type": "%[1]s",
  "graph": {"rule": "companion_present", "companion_type": "%[2]s", "link_attr": "name", "target_attrs": ["name"]},
  "action": "deny", "severity": "high", "message": "%[1]s has no %[2]s companion.", "fix": "Add the companion."},
 {"id": "%[1]s_guard", "version": "1.0.0", "kind": "graph", "resource_type": "%[2]s",
  "graph": {"rule": "companion_absent_forbidden", "companion_type": "%[1]s", "link_attr": "name", "target_attrs": ["name"]},
  "action": "deny", "severity": "high", "message": "Deleting %[1]s leaves %[2]s without its companion.", "fix": "Delete %[2]s first."}`, typ, other)
}

// Diagnostics of a blocked half (internal/verdict situation texts).
const (
	diagNoMatch   = "No verdict entry matches this %s instance"
	diagCompanion = "fake_replace_companion: fake_replace has no fake_thing companion."
	diagGuard     = "fake_replace_guard: Deleting fake_replace leaves fake_thing without its companion."
)

// badKey is a well-formed key no change has.
var badKey = "sha256:" + strings.Repeat("f", 64)

// mutations are the envelope edits of the 0B envelope_mutation scenario:
// each either fails the envelope check or leaves the RPC-derived key and
// decision unchanged.
var mutations = []string{
	`{"v": 2}`, `{"strip": true}`,
	`{"ctf": {"op": "create"}}`, `{"ctf": {"op": "update"}}`, `{"ctf": {"op": "replace"}}`, `{"ctf": {"op": "delete"}}`,
	`{"ctf": {"op": "import"}}`, `{"ctf": {"op": "change"}}`, `{"ctf": {"imported": true}}`,
	`{"ctf": {"prior_identity_kind": "none"}}`, `{"ctf": {"prior_identity_kind": "id"}}`,
	`{"ctf": {"prior_identity_kind": "identity", "prior_identity": {"id": "bobthecorp-other"}}}`,
	`{"ctf": {"control_versions_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"}}`,
}

func newKey(t *testing.T) verdicttest.Key {
	return verdicttest.NewKey(t, time.Now().Add(-24*time.Hour))
}

// applyGated gates a plan with planArgs, signs it after edit and applies
// the planfile.
func (r *run) applyGated(k verdicttest.Key, edit func([]verdict.Instance), planArgs ...string) (*gate, result) {
	r.T.Helper()
	g := r.gatePlan(planArgs...)
	r.gateSign(g, k, edit)
	return g, r.TF("apply", "-no-color", "-input=false", g.File)
}

// object is one state object of an address.
type object struct{ id, deposed, status string }

// objects lists the state objects of address (type.name, root module).
func (r *run) objects(address string) []object {
	r.T.Helper()
	typ, name, _ := strings.Cut(address, ".")
	var out []object
	rs, _ := r.State()["resources"].([]any)
	for _, x := range rs {
		res, _ := x.(map[string]any)
		if res["type"] != typ || res["name"] != name || res["mode"] != "managed" {
			continue
		}
		insts, _ := res["instances"].([]any)
		for _, y := range insts {
			in, _ := y.(map[string]any)
			attrs, _ := in["attributes"].(map[string]any)
			o := object{}
			o.id, _ = attrs["id"].(string)
			o.deposed, _ = in["deposed"].(string)
			o.status, _ = in["status"].(string)
			out = append(out, o)
		}
	}
	return out
}

// blocked fails unless res exited non-zero with every want in stderr
// (whitespace folded: Terraform wraps diagnostics), no apply completed and
// the state's resources equal before's.
func (r *run) blocked(res result, before map[string]any, want ...string) {
	r.T.Helper()
	stderr := strings.Join(strings.Fields(res.Stderr), " ")
	ok := res.Exit != 0 && !strings.Contains(res.Stdout, "Apply complete")
	for _, w := range want {
		ok = ok && strings.Contains(stderr, strings.Join(strings.Fields(w), " "))
	}
	if !ok {
		r.T.Fatalf("want a blocked apply with %q: exit %d\n--- stdout\n%s--- stderr\n%s", want, res.Exit, res.Stdout, res.Stderr)
	}
	if b, a := resources(before), resources(r.State()); !reflect.DeepEqual(b, a) {
		r.T.Fatalf("a blocked apply changed state\n--- before\n%v\n--- after\n%v", b, a)
	}
}

// blockedApply snapshots state, then runs apply with args and checks it
// blocked: the baseline is always taken before the apply (an argument
// expression r.State() next to r.TF(...) would run after it).
func (r *run) blockedApply(args []string, want ...string) {
	r.T.Helper()
	before := r.State()
	r.blocked(r.TF(append([]string{"apply", "-no-color", "-input=false"}, args...)...), before, want...)
}

// resources is a state's resources, [] for no state.
func resources(st map[string]any) []any {
	rs, _ := st["resources"].([]any)
	if rs == nil {
		rs = []any{}
	}
	return rs
}

// ok fails unless res exited 0.
func ok(t *testing.T, res result) {
	t.Helper()
	if res.Exit != 0 {
		t.Fatalf("apply: exit %d\n--- stdout\n%s--- stderr\n%s", res.Exit, res.Stdout, res.Stderr)
	}
}

// decide sets every entry's graph decisions: its type's companion in
// decisions (instance_key half), the guard of its deletion in delete_decisions (delete_key
// half).
func decide(ins []verdict.Instance, companionResult, guardResult string) {
	for i := range ins {
		if ins[i].InstanceKey != "" {
			ins[i].Decisions = []verdict.Decision{{Control: ins[i].Type + "_companion", Version: "1.0.0", Result: companionResult, Action: "deny"}}
		}
		if ins[i].DeleteKey != "" {
			ins[i].DeleteDecisions = []verdict.Decision{{Control: ins[i].Type + "_guard", Version: "1.0.0", Result: guardResult, Action: "deny"}}
		}
	}
}

func pass(ins []verdict.Instance) { decide(ins, verdict.ResultPass, verdict.ResultPass) }

// gated is the trust of the scenarios that decide graph controls: graph
// controls on both fake types make every mutation look up its entry and
// enforce its own half and decisions, without verdict_required
// (TestRequiredExistingState covers existing state under verdict_required).
func gated(k verdicttest.Key) runOpt {
	return runOpt{Keys: []verdicttest.Key{k}, Controls: graphControls}
}

// TestGatePlanToApply: a gated create, update and destroy each apply the
// sealed planfile, the provider recomputing every key from the apply
// request. The update and delete entries carry the prior identity kind the
// plan side derived (prior_identity round trip).
func TestGatePlanToApply(t *testing.T) {
	k := newKey(t)
	r := newRun(t, thingsTF, gated(k))
	g, res := r.applyGated(k, pass)
	ok(t, res)
	if len(g.Instances) != 2 || g.Instances[0].Action != "create" || g.Instances[0].PriorIdentityKind != verdict.KindNone {
		t.Fatalf("create entries %+v", g.Instances)
	}
	if a, b := r.objects("fake_thing.a"), r.objects("fake_replace.b"); len(a) != 1 || len(b) != 1 {
		t.Fatalf("after create: %v %v", a, b)
	}
	g, res = r.applyGated(k, pass, "-var", "size=3")
	ok(t, res)
	for _, c := range g.Changes {
		in := entry(g.Instances, c.Address, c.Deposed)
		if in == nil {
			t.Fatalf("no update entry for %s", c.Address)
		}
		want := verdict.KindID
		if in.Type == "fake_thing" && c.Change.BeforeIdentity != nil {
			want = verdict.KindIdentity
		}
		if in.Action != "update" || in.PriorIdentityKind != want {
			t.Fatalf("update entry %s: action %s kind %s, want update %s", in.Address, in.Action, in.PriorIdentityKind, want)
		}
	}
	g, res = r.applyGated(k, pass, "-destroy", "-var", "size=3")
	ok(t, res)
	for _, in := range g.Instances {
		if in.Action != "delete" || in.DeleteKey == "" || in.InstanceKey != "" {
			t.Fatalf("delete entry %+v", in)
		}
	}
	if a, b := r.objects("fake_thing.a"), r.objects("fake_replace.b"); len(a)+len(b) != 0 {
		t.Fatalf("after destroy: %v %v", a, b)
	}
}

// TestRequiredExistingState: under verdict_required, with no graph
// control on the type, every mutation of existing state needs its own
// entry: update, replace (destroy-before-create) and destroy each apply
// through the gate; plan of existing state proceeds without a verdict
// (UpgradeResourceState passes the gate) while the apply blocks;
// a replace whose delete_key belongs to another change blocks its destroy
// RPC and changes nothing.
func TestRequiredExistingState(t *testing.T) {
	k := newKey(t)
	r := newRun(t, replaceTF(false), runOpt{Keys: []verdicttest.Key{k}, Required: true})
	_, res := r.applyGated(k, nil)
	ok(t, res)
	old := r.objects("fake_replace.r")[0].id

	nv := newRun(t, replaceTF(false), runOpt{Keys: []verdicttest.Key{k}, Required: true})
	if err := os.WriteFile(filepath.Join(nv.Work, "terraform.tfstate"), mustRead(t, filepath.Join(r.Work, "terraform.tfstate")), 0o600); err != nil {
		t.Fatal(err)
	}
	nv.Must("plan", "-no-color", "-input=false", "-var", "size=3")
	nv.blockedApply([]string{"-auto-approve", "-var", "size=3"}, verdict.TextNoVerdict[:40])

	g, res := r.applyGated(k, nil, "-var", "size=3")
	ok(t, res)
	if in := entry(g.Instances, "fake_replace.r", ""); in == nil || in.Action != "update" {
		t.Fatalf("update entry %+v", in)
	}
	before := r.State()
	_, res = r.applyGated(k, func(ins []verdict.Instance) { entry(ins, "fake_replace.r", "").DeleteKey = badKey }, "-var", "size=3", "-var", "name=bobthecorp-r2")
	r.blocked(res, before, fmt.Sprintf(diagNoMatch, "fake_replace")+"; the profile requires a verdict for every change")
	if objs := r.objects("fake_replace.r"); len(objs) != 1 || objs[0].id != old {
		t.Fatalf("a blocked destroy half changed the object: %v", objs)
	}
	g, res = r.applyGated(k, nil, "-var", "size=3", "-var", "name=bobthecorp-r2")
	ok(t, res)
	if in := entry(g.Instances, "fake_replace.r", ""); in == nil || in.Action != "replace" {
		t.Fatalf("replace entry %+v", in)
	}
	if objs := r.objects("fake_replace.r"); len(objs) != 1 || objs[0].id != "bobthecorp-bobthecorp-r2" {
		t.Fatalf("after replace %v", objs)
	}
	_, res = r.applyGated(k, nil, "-destroy", "-var", "size=3", "-var", "name=bobthecorp-r2")
	ok(t, res)
	if objs := r.objects("fake_replace.r"); len(objs) != 0 {
		t.Fatalf("after destroy %v", objs)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestPriorIdentityRoundTrip: the update key binds the prior identity the
// plan side read (kind identity for fake_thing where the binary sends
// identities, else id). An entry keyed on another prior object, or
// recorded under another kind, matches no update RPC and blocks.
func TestPriorIdentityRoundTrip(t *testing.T) {
	k := newKey(t)
	for _, typ := range []string{"fake_thing", "fake_replace"} {
		for _, tc := range []struct {
			name string
			edit func(in *verdict.Instance, other verdict.Instance)
		}{
			{"other prior object", func(in *verdict.Instance, other verdict.Instance) { in.InstanceKey = other.InstanceKey }},
			{"other kind", func(in *verdict.Instance, _ verdict.Instance) {
				in.PriorIdentityKind = map[string]string{verdict.KindID: verdict.KindIdentity, verdict.KindIdentity: verdict.KindID}[in.PriorIdentityKind]
			}},
			{"same", func(*verdict.Instance, verdict.Instance) {}},
		} {
			t.Run(typ+"/"+tc.name, func(t *testing.T) {
				r := newRun(t, header+fmt.Sprintf(`
variable "size" {
  type    = number
  default = 2
}

resource %q "u" {
  name = "bobthecorp-u"
  size = var.size
}
`, typ), gated(k))
				_, res := r.applyGated(k, pass)
				ok(t, res)
				before := r.State()
				g := r.gatePlan("-var", "size=3")
				c := g.Changes[0]
				c.Change.Before = mapsWith(c.Change.Before, "id", `"bobthecorp-other"`)
				if c.Change.BeforeIdentity != nil {
					c.Change.BeforeIdentity = mapsWith(c.Change.BeforeIdentity, "id", `"bobthecorp-other"`)
				}
				other, _, err := harness.InstanceFor(verdicttest.Leaf(t, g.Secret), g.Schemas, c)
				if err != nil {
					t.Fatal(err)
				}
				if other.InstanceKey == g.Instances[0].InstanceKey {
					t.Fatal("the update key ignores the prior identity")
				}
				r.gateSign(g, k, func(ins []verdict.Instance) { pass(ins); tc.edit(&ins[0], other) })
				res = r.TF("apply", "-no-color", "-input=false", g.File)
				if tc.name == "same" {
					ok(t, res)
					return
				}
				r.blocked(res, before, "No verdict entry matches this "+typ+" instance")
			})
		}
	}
}

func mapsWith(m map[string]json.RawMessage, k, v string) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for kk, vv := range m {
		out[kk] = vv
	}
	out[k] = json.RawMessage(v)
	return out
}

// TestNoVerdict: under verdict_required, plan and refresh proceed without
// a verdict (H6) and every apply blocks.
func TestNoVerdict(t *testing.T) {
	r := newRun(t, thingsTF, runOpt{Keys: []verdicttest.Key{newKey(t)}, Required: true})
	r.Must("plan", "-no-color", "-input=false")
	r.blockedApply([]string{"-auto-approve"}, verdict.TextNoVerdict[:40])
}

// TestTamper: a byte edit of the signed verdict, a run key of another
// verdict, a verdict for other control content and a planfile other than
// the gated one each block every apply.
func TestTamper(t *testing.T) {
	k := newKey(t)
	for _, tc := range []struct {
		name string
		do   func(r *run, g *gate) string // returns the planfile to apply
		want string
	}{
		{"verdict byte edit", func(r *run, g *gate) string {
			r.gateSign(g, k, nil)
			p := filepath.Join(r.Work, "gate", "verdict.json")
			b, err := os.ReadFile(p)
			edited := strings.Replace(string(b), `"refreshed":"true"`, `"refreshed":"false"`, 1)
			if err == nil && edited == string(b) {
				t.Fatal("the edit changed no signed byte")
			}
			if err == nil {
				err = os.WriteFile(p, []byte(edited), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			return g.File
		}, "Verdict signature invalid"},
		{"run key of another verdict", func(r *run, g *gate) string {
			r.gateSign(g, k, nil)
			other := make([]byte, 32)
			if err := os.WriteFile(filepath.Join(r.Work, "gate", "ctfkit-run.key"), []byte(hex.EncodeToString(other)), 0o600); err != nil {
				t.Fatal(err)
			}
			return g.File
		}, "Verdict key missing or does not belong to this verdict"},
		{"other control content", func(r *run, g *gate) string {
			b := r.loaded()
			raw, _ := json.Marshal(g.Instances)
			b.Instances, b.Secret, b.ContentDigest = raw, g.Secret, "sha256:"+strings.Repeat("0", 64)
			r.Sign(k, b)
			return g.File
		}, "verdict issued for control content"},
		{"planfile swapped", func(r *run, g *gate) string {
			r.gateSign(g, k, nil)
			r.Must("plan", "-no-color", "-input=false", "-var", "size=5", "-out=other.tfplan")
			return "other.tfplan"
		}, "No verdict entry matches"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRun(t, thingsTF, runOpt{Keys: []verdicttest.Key{k}, Required: true})
			g := r.gatePlan()
			plan := tc.do(r, g)
			r.blockedApply([]string{plan}, tc.want)
		})
	}
}

// TestCollision: two entries sharing one instance key with different
// decisions never pick one (collision blocks); with equal decisions they
// decide alike and apply.
func TestCollision(t *testing.T) {
	const twin = header + `
resource "fake_thing" "companion" {
  name = "bobthecorp-twin"
}

resource "fake_replace" "x" {
  name = "bobthecorp-twin"
}

resource "fake_replace" "y" {
  name = "bobthecorp-twin"
}
`
	k := newKey(t)
	r := newRun(t, twin, gated(k))
	g := r.gatePlan()
	x, y := entry(g.Instances, "fake_replace.x", ""), entry(g.Instances, "fake_replace.y", "")
	if x == nil || y == nil || x.InstanceKey != y.InstanceKey {
		t.Fatalf("twins must share an instance key: %+v %+v", x, y)
	}
	r.gateSign(g, k, func(ins []verdict.Instance) {
		pass(ins)
		entry(ins, "fake_replace.y", "").Decisions[0].Result = verdict.ResultFail
	})
	res := r.TF("apply", "-no-color", "-input=false", g.File)
	if res.Exit == 0 || !strings.Contains(strings.Join(strings.Fields(res.Stderr), " "), "share this instance key") {
		t.Fatalf("collision: exit %d\n%s", res.Exit, res.Stderr)
	}
	if len(r.objects("fake_replace.x"))+len(r.objects("fake_replace.y")) != 0 {
		t.Fatal("a colliding entry applied")
	}
	_, res = r.applyGated(k, pass) // the companion applied above; the twins remain
	ok(t, res)
	if len(r.objects("fake_replace.x"))+len(r.objects("fake_replace.y")) != 2 {
		t.Fatal("twins not created")
	}
}

// TestEnvelopeMutation: a failing decision stays failing under every
// envelope edit, on the create, update and destroy RPC. Next to the real
// entry (failing decision) the verdict lists passing entries under every
// key an edited envelope could steer the provider to (other prior kind,
// other prior object, other form), so an edit that steered the key would
// apply: only the envelope check or the RPC-derived key (H2) can stop it.
// Each edit must yield its expected diagnostic.
func TestEnvelopeMutation(t *testing.T) {
	k := newKey(t)
	r := newRun(t, replaceTF(false), gated(k))
	const (
		invalid  = "Invalid compliance plan envelope"
		disagree = "Envelope disagrees"
		noMatch  = "No verdict entry matches this fake_replace instance"
	)
	check := func(form string, planArgs []string, companionResult, guardResult string, want map[string]string) {
		decision := "fake_replace_companion: fake_replace has no fake_thing companion."
		if form == "delete" {
			decision = "fake_replace_guard: Deleting fake_replace leaves fake_thing without its companion."
		}
		for _, m := range append([]string{""}, mutations...) {
			t.Run(form+"/"+m, func(t *testing.T) {
				r.T = t
				// Re-gate per edit: a blocked apply may leave the planfile stale,
				// and a stale plan must not stand in for the check under test.
				g := r.gatePlan(planArgs...)
				r.gateSign(g, k, func(ins []verdict.Instance) { decide(ins, companionResult, guardResult) }, steered(t, g)...)
				before := r.State()
				r.envelope(m)
				res := r.TF("apply", "-no-color", "-input=false", g.File)
				r.envelope("")
				w, ok := want[m]
				if !ok {
					w = decision
				}
				r.blocked(res, before, w)
			})
		}
		r.T = t
	}
	// A create key needs no envelope: a stripped envelope still decides.
	check("create", nil, verdict.ResultFail, verdict.ResultPass, map[string]string{
		`{"v": 2}`: invalid, `{"ctf": {"op": "change"}}`: invalid,
		`{"ctf": {"prior_identity_kind": "id"}}`:                                                     invalid,
		`{"ctf": {"prior_identity_kind": "identity", "prior_identity": {"id": "bobthecorp-other"}}}`: invalid,
	})
	_, res := r.applyGated(k, pass)
	ok(t, res)
	steeredDiag := map[string]string{
		`{"v": 2}`: invalid, `{"strip": true}`: noMatch, `{"ctf": {"op": "create"}}`: invalid, `{"ctf": {"op": "change"}}`: invalid,
		`{"ctf": {"prior_identity_kind": "none"}}`:                                                   disagree,
		`{"ctf": {"prior_identity_kind": "identity", "prior_identity": {"id": "bobthecorp-other"}}}`: disagree,
	}
	check("update", []string{"-var", "size=3"}, verdict.ResultFail, verdict.ResultPass, steeredDiag)
	check("delete", []string{"-destroy"}, verdict.ResultPass, verdict.ResultFail, steeredDiag)
}

// steered are passing entries under every key an edited envelope could
// steer the one change of g to, other than the key the plan derived: the
// update and delete forms under kind identity and id with the real and
// another prior object, and the create form, for the same planned value.
func steered(t *testing.T, g *gate) []verdict.Instance {
	t.Helper()
	c := g.Changes[0]
	leaf := verdicttest.Leaf(t, g.Secret)
	planned, unknown, err := harness.PlannedValue(g.Schemas[c.Type], c.Change.After, c.Change.AfterUnknown)
	if err != nil {
		t.Fatal(err)
	}
	real := g.Instances[0]
	base := func(n int) verdict.Instance {
		in := real
		in.Address, in.Deposed = fmt.Sprintf("%s.steered_%d", c.Type, n), ""
		in.InstanceKey, in.DeleteKey, in.UnknownPaths = "", "", [][]string{}
		in.Decisions, in.DeleteDecisions = []verdict.Decision{}, nil
		return in
	}
	var out []verdict.Instance
	add := func(form verdict.Form, kind string, prior json.RawMessage) {
		in := base(len(out))
		key, err := verdict.Key(leaf, c.Type, form, planned, map[bool][][]string{true: unknown, false: nil}[form != verdict.FormDelete], prior)
		if err != nil {
			t.Fatal(err)
		}
		switch form {
		case verdict.FormCreate:
			in.Action, in.PriorIdentityKind, in.InstanceKey, in.UnknownPaths = "create", verdict.KindNone, key, unknown
		case verdict.FormUpdate:
			in.Action, in.PriorIdentityKind, in.InstanceKey, in.UnknownPaths = "update", kind, key, unknown
		default:
			in.Action, in.PriorIdentityKind, in.DeleteKey, in.DeleteDecisions = "delete", kind, key, []verdict.Decision{}
		}
		if in.InstanceKey == real.InstanceKey && in.DeleteKey == real.DeleteKey && in.PriorIdentityKind == real.PriorIdentityKind && in.Action == real.Action {
			return // the real derivation: not a steered key
		}
		out = append(out, in)
	}
	var id string
	if raw, ok := c.Change.Before["id"]; ok {
		_ = json.Unmarshal(raw, &id) //nolint:errcheck // a create has no prior id; "" then
	}
	if id == "" {
		id = "bobthecorp-bobthecorp-r1"
	}
	for _, form := range []verdict.Form{verdict.FormUpdate, verdict.FormDelete} {
		for _, kind := range []string{verdict.KindIdentity, verdict.KindID} {
			for _, pid := range []string{id, "bobthecorp-other"} {
				prior, _ := json.Marshal(map[string]string{"id": pid}) //nolint:errcheck // a string map always marshals
				add(form, kind, prior)
			}
		}
	}
	if c.Change.Actions[0] != "create" {
		add(verdict.FormCreate, verdict.KindNone, nil)
	}
	pass(out)
	return out
}

// TestReplace: each RPC of a replace enforces only its own half: the
// destroy RPC matches delete_key and checks delete_decisions, the create
// RPC matches instance_key and checks decisions. Destroy-before-create
// runs the destroy first, create-before-destroy the create; the state
// after a blocked half shows which RPC refused.
func TestReplace(t *testing.T) {
	k := newKey(t)
	for _, cbd := range []bool{false, true} {
		for _, tc := range []struct {
			name string
			edit func([]verdict.Instance)
			dbc  outcome
			cbd  outcome
			diag string // the blocked half's diagnostic
		}{
			{"valid", pass, replaced, replaced, ""},
			{"delete_key of another change", func(ins []verdict.Instance) { pass(ins); entry(ins, "fake_replace.r", "").DeleteKey = badKey }, untouched, deposedLeft, fmt.Sprintf(diagNoMatch, "fake_replace")},
			{"instance_key of another change", func(ins []verdict.Instance) { pass(ins); entry(ins, "fake_replace.r", "").InstanceKey = badKey }, destroyed, untouched, fmt.Sprintf(diagNoMatch, "fake_replace")},
			{"failing delete decision", func(ins []verdict.Instance) { decide(ins, verdict.ResultPass, verdict.ResultFail) }, untouched, deposedLeft, diagGuard},
			{"failing create decision", func(ins []verdict.Instance) { decide(ins, verdict.ResultFail, verdict.ResultPass) }, destroyed, untouched, diagCompanion},
		} {
			t.Run(fmt.Sprintf("cbd=%t/%s", cbd, tc.name), func(t *testing.T) {
				r := newRun(t, replaceTF(cbd), gated(k))
				_, res := r.applyGated(k, pass)
				ok(t, res)
				old := r.objects("fake_replace.r")[0].id
				g, res := r.applyGated(k, tc.edit, "-var", "name=bobthecorp-r2")
				in := entry(g.Instances, "fake_replace.r", "")
				if in == nil || in.Action != "replace" || in.InstanceKey == "" || in.DeleteKey == "" {
					t.Fatalf("replace entry %+v", in)
				}
				want := tc.dbc
				if cbd {
					want = tc.cbd
				}
				checkReplace(t, r, res, old, want, tc.diag)
			})
		}
	}
}

// outcome is what a replace of fake_replace.r left in state.
type outcome int

const (
	untouched   outcome = iota // the first RPC blocked: nothing changed
	destroyed                  // destroy-before-create: destroy ran, create blocked
	deposedLeft                // create-before-destroy: create ran, destroy blocked
	replaced
)

// checkReplace asserts the state a replace of fake_replace.r left.
func checkReplace(t *testing.T, r *run, res result, old string, want outcome, diag string) {
	t.Helper()
	objs := r.objects("fake_replace.r")
	var current, deposed []string
	for _, o := range objs {
		if o.deposed != "" {
			deposed = append(deposed, o.id)
		} else {
			current = append(current, o.id)
		}
	}
	applied := want == replaced
	if applied != (res.Exit == 0) {
		t.Fatalf("apply exit %d\n%s%s", res.Exit, res.Stdout, res.Stderr)
	}
	var good bool
	switch want {
	case untouched:
		good = slices.Equal(current, []string{old}) && len(deposed) == 0
	case destroyed:
		good = len(current) == 0 && len(deposed) == 0
	case deposedLeft:
		good = slices.Equal(current, []string{"bobthecorp-bobthecorp-r2"}) && slices.Equal(deposed, []string{old})
	case replaced:
		good = slices.Equal(current, []string{"bobthecorp-bobthecorp-r2"}) && len(deposed) == 0
	}
	if !good {
		t.Fatalf("outcome %d: current %v deposed %v (old %s)\n%s%s", want, current, deposed, old, res.Stdout, res.Stderr)
	}
	if !applied && !strings.Contains(strings.Join(strings.Fields(res.Stderr), " "), diag) {
		t.Fatalf("blocked without %q:\n%s", diag, res.Stderr)
	}
}

// TestTainted: a tainted object is replaced (destroy-before-create); its
// destroy half is keyed with kind id whatever before_identity holds
// (OpenTofu plans a tainted object with its identity) and each
// RPC enforces only its
// half: a delete_key of another change keeps the tainted object, an
// instance_key of another change lets the destroy run and blocks the
// create.
func TestTainted(t *testing.T) {
	k := newKey(t)
	for _, addr := range []string{"fake_replace.b", "fake_thing.a"} {
		for _, tc := range []struct {
			name        string
			edit        func([]verdict.Instance)
			applied     bool
			oldSurvives bool
		}{
			{"valid", pass, true, false},
			{"delete_key of another change", func(ins []verdict.Instance) { pass(ins); entry(ins, addr, "").DeleteKey = badKey }, false, true},
			{"instance_key of another change", func(ins []verdict.Instance) { pass(ins); entry(ins, addr, "").InstanceKey = badKey }, false, false},
		} {
			t.Run(addr+"/"+tc.name, func(t *testing.T) {
				r := newRun(t, thingsTF, gated(k))
				_, res := r.applyGated(k, pass)
				ok(t, res)
				r.Must("taint", "-no-color", addr)
				g := r.gatePlan()
				in := entry(g.Instances, addr, "")
				if in == nil || in.Action != "replace" || in.PriorIdentityKind != verdict.KindID {
					t.Fatalf("tainted entry %+v", in)
				}
				r.gateSign(g, k, tc.edit)
				res = r.TF("apply", "-no-color", "-input=false", g.File)
				objs := r.objects(addr)
				if tc.applied != (res.Exit == 0) {
					t.Fatalf("apply exit %d\n%s%s", res.Exit, res.Stdout, res.Stderr)
				}
				typ, _, _ := strings.Cut(addr, ".")
				if diag := fmt.Sprintf(diagNoMatch, typ); !tc.applied && !strings.Contains(strings.Join(strings.Fields(res.Stderr), " "), diag) {
					t.Fatalf("blocked without %q:\n%s", diag, res.Stderr)
				}
				switch {
				case tc.applied && (len(objs) != 1 || objs[0].status == "tainted"):
					t.Fatalf("after replace %v", objs)
				case !tc.applied && tc.oldSurvives && (len(objs) != 1 || objs[0].status != "tainted"):
					t.Fatalf("destroy half blocked, want the tainted object kept: %v", objs)
				case !tc.applied && !tc.oldSurvives && len(objs) != 0:
					t.Fatalf("create half blocked after the destroy, want no object: %v", objs)
				}
			})
		}
	}
}

// TestDeposedCleanup: a create-before-destroy whose destroy half blocked
// leaves a deposed object (partial apply). Its standalone cleanup applies
// with a delete-scoped entry only; a missing entry or a non-delete entry
// for the deposed object blocks (E12).
func TestDeposedCleanup(t *testing.T) {
	k := newKey(t)
	r := newRun(t, replaceTF(true), gated(k))
	_, res := r.applyGated(k, pass)
	ok(t, res)
	old := r.objects("fake_replace.r")[0].id
	_, res = r.applyGated(k, func(ins []verdict.Instance) { decide(ins, verdict.ResultPass, verdict.ResultFail) }, "-var", "name=bobthecorp-r2")
	checkReplace(t, r, res, old, deposedLeft, diagGuard)
	var dep string
	for _, o := range r.objects("fake_replace.r") {
		dep = max(dep, o.deposed)
	}
	g := r.gatePlan("-var", "name=bobthecorp-r2")
	if len(g.Instances) != 1 {
		t.Fatalf("cleanup plan entries %+v, want the deposed delete only", g.Instances)
	}
	in := g.Instances[0]
	if in.Deposed != dep || in.Action != "delete" || in.InstanceKey != "" || in.DeleteKey == "" || len(in.Decisions) != 0 {
		t.Fatalf("deposed entry %+v (deposed %s)", in, dep)
	}
	t.Run("no entry", func(t *testing.T) {
		r.T = t
		r.gateSign(g, k, func(ins []verdict.Instance) { pass(ins); ins[0].DeleteKey = badKey })
		r.blockedApply([]string{g.File}, "No verdict entry matches")
	})
	t.Run("non-delete entry", func(t *testing.T) {
		r.T = t
		r.gateSign(g, k, func(ins []verdict.Instance) {
			pass(ins)
			ins[0].Action, ins[0].InstanceKey = "replace", ins[0].DeleteKey
			ins[0].Decisions = []verdict.Decision{{Control: "fake_replace_companion", Version: "1.0.0", Result: verdict.ResultPass, Action: "deny"}}
		})
		r.blockedApply([]string{g.File}, "a deposed object takes only a delete entry")
	})
	r.T = t
	r.gateSign(g, k, pass)
	ok(t, r.TF("apply", "-no-color", "-input=false", g.File))
	if objs := r.objects("fake_replace.r"); len(objs) != 1 || objs[0].deposed != "" || objs[0].id != "bobthecorp-bobthecorp-r2" {
		t.Fatalf("after cleanup %v", objs)
	}
}

// TestKeyFiles: verdict and run key files that are not owner-only regular
// files, a missing run key and a verdict payload in the environment block
// every apply.
func TestKeyFiles(t *testing.T) {
	k := newKey(t)
	for _, tc := range []struct {
		name string
		do   func(t *testing.T, r *run, verdictPath, keyPath string)
		want string
	}{
		{"verdict mode 0644", func(t *testing.T, _ *run, v, _ string) { chmod(t, v, 0o644) }, "The verdict file mode must be exactly 0600."},
		{"verdict symlink", func(t *testing.T, r *run, v, _ string) {
			l := filepath.Join(r.Work, "link.json")
			if err := os.Symlink(v, l); err != nil {
				t.Fatal(err)
			}
			r.Env = append(r.Env, verdict.EnvVerdict+"="+l)
		}, "without following a symlink"},
		{"verdict payload in env", func(t *testing.T, r *run, v, _ string) {
			b, err := os.ReadFile(v)
			if err != nil {
				t.Fatal(err)
			}
			r.Env = append(r.Env, verdict.EnvVerdict+"="+string(b))
		}, "never the verdict itself"},
		{"run key mode 0640", func(t *testing.T, _ *run, _, kp string) { chmod(t, kp, 0o640) }, verdict.SummaryKey},
		{"run key missing", func(t *testing.T, _ *run, _, kp string) {
			if err := os.Remove(kp); err != nil {
				t.Fatal(err)
			}
		}, verdict.SummaryKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRun(t, thingsTF, runOpt{Keys: []verdicttest.Key{k}, Required: true})
			g := r.gatePlan()
			r.gateSign(g, k, nil)
			v, kp := filepath.Join(r.Work, "gate", "verdict.json"), filepath.Join(r.Work, "gate", "ctfkit-run.key")
			tc.do(t, r, v, kp)
			r.blockedApply([]string{g.File}, tc.want)
		})
	}
}

func chmod(t *testing.T, p string, m os.FileMode) {
	t.Helper()
	if err := os.Chmod(p, m); err != nil {
		t.Fatal(err)
	}
}
