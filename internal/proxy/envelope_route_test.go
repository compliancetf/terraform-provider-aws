package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/hook/hooktest"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

func wrapped(t *testing.T, h hook.EnvelopeHeader, upstream string) []byte {
	t.Helper()
	b, err := Wrap(h, []byte(upstream))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// thingNoID is a fake_thing whose id is null.
func thingNoID(t *testing.T) *tfplugin5.DynamicValue {
	t.Helper()
	v := tftypes.NewValue(thingType, map[string]tftypes.Value{"id": tftypes.NewValue(tftypes.String, nil), "name": tftypes.NewValue(tftypes.String, "x")})
	dv, err := tfprotov5.NewDynamicValue(thingType, v)
	if err != nil {
		t.Fatal(err)
	}
	return &tfplugin5.DynamicValue{Msgpack: dv.MsgPack}
}

func TestEnvelopePlanWraps(t *testing.T) {
	for _, ev := range []hook.Evaluator{
		&hooktest.Recorder{Respond: func(*hook.Request) (*hook.Result, error) {
			return &hook.Result{ControlVersionsDigest: "sha256:0f1e2d"}, nil
		}},
		hook.Noop{}, // Wants false: the envelope is still written, digest empty
	} {
		client, up, _ := startRoute(t, ev)
		got, err := client.PlanResourceChange(context.Background(), &tfplugin5.PlanResourceChange_Request{TypeName: "fake_thing", PriorState: thing(t, "prior"), Config: thing(t, "cfg")})
		if err != nil {
			t.Fatal(err)
		}
		h, tail, err := Unwrap(got.PlannedPrivate)
		if err != nil || h == nil || !bytes.Equal(tail, up.plan.PlannedPrivate) || h.CTF.Op != hook.OpReplace {
			t.Fatalf("planned_private = %q (%+v, %v), want a replace envelope around upstream's", got.PlannedPrivate, h, err)
		}
		if rec, ok := ev.(*hooktest.Recorder); ok {
			if h.CTF.ControlVersionsDigest != "sha256:0f1e2d" || rec.Requests()[0].Op != hook.OpReplace {
				t.Errorf("digest %q, hook op %q", h.CTF.ControlVersionsDigest, rec.Requests()[0].Op)
			}
		} else if h.CTF.ControlVersionsDigest != "" {
			t.Errorf("digest without hook = %q", h.CTF.ControlVersionsDigest)
		}
	}
}

func TestEnvelopePlanOversize(t *testing.T) {
	rec := &hooktest.Recorder{Respond: func(*hook.Request) (*hook.Result, error) {
		return &hook.Result{ControlVersionsDigest: strings.Repeat("a", maxHeader)}, nil
	}}
	client, _, _ := startRoute(t, rec)
	got, err := client.PlanResourceChange(context.Background(), &tfplugin5.PlanResourceChange_Request{TypeName: "fake_thing", PriorState: thing(t, "prior"), Config: thing(t, "cfg")})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(summaries(got.Diagnostics), "ERROR:Invalid compliance plan envelope") {
		t.Errorf("diagnostics = %v, want a plan error", summaries(got.Diagnostics))
	}
}

func TestEnvelopeApplyUnwraps(t *testing.T) {
	rec := &hooktest.Recorder{}
	client, up, _ := startRoute(t, rec)
	_, err := client.ApplyResourceChange(context.Background(), &tfplugin5.ApplyResourceChange_Request{
		TypeName: "fake_thing", PriorState: thing(t, ""), PlannedState: thing(t, "planned"), Config: thing(t, "cfg"),
		PlannedPrivate: wrapped(t, header(hook.OpReplace, "sha256:0f1e2d", "", "none", false), "pp"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(up.applyReq.PlannedPrivate) != "pp" {
		t.Errorf("upstream planned_private = %q, want pp", up.applyReq.PlannedPrivate)
	}
	pre := rec.Requests()[0]
	if pre.Envelope == nil || pre.Envelope.CTF.ControlVersionsDigest != "sha256:0f1e2d" || pre.Op != hook.OpReplace {
		t.Errorf("apply_pre envelope %+v op %q, want digest and replace", pre.Envelope, pre.Op)
	}
}

// TestEnvelopeApplyBlocks covers every proxy-side block: upstream is never
// reached and the hook only records the block from the type and
// the request-shape op, with no value or envelope; an apply that passes the
// check reaches the hook with no block.
func TestEnvelopeApplyBlocks(t *testing.T) {
	bob := header(hook.OpUpdate, "", bobIdentity, "identity", false)
	same := identityMsgpack(t, map[string]any{"account_id": "123456789012", "bucket": "bobthecorp-logs"})
	other := identityMsgpack(t, map[string]any{"account_id": "123456789012", "bucket": "bobthecorp-other"})
	const invalid, disagrees = "ERROR:Invalid compliance plan envelope", "ERROR:Envelope disagrees with prior state"
	for _, tc := range []struct {
		name           string
		pp             []byte
		prior, planned *tfplugin5.DynamicValue
		identity       *tfplugin5.ResourceIdentityData
		want           string // "" = reaches the hook
	}{
		{"invalid", rawEnv(`{"v":1,"ctf":{"op":"update","x":1}}`, ""), thing(t, "p"), thing(t, "q"), nil, invalid},
		{"truncated", []byte("\x00CTF"), thing(t, "p"), thing(t, "q"), nil, invalid},
		{"create with id kind", wrapped(t, header(hook.OpUpdate, "", "", "id", false), ""), thing(t, ""), thing(t, "q"), nil, disagrees},
		{"replace create half", wrapped(t, header(hook.OpReplace, "", "", "id", false), ""), thing(t, ""), thing(t, "q"), nil, ""},
		{"update identity equal", wrapped(t, bob, ""), thing(t, "p"), thing(t, "q"), same, ""},
		{"update identity differs", wrapped(t, bob, ""), thing(t, "p"), thing(t, "q"), other, disagrees},
		{"update identity missing", wrapped(t, bob, ""), thing(t, "p"), thing(t, "q"), nil, disagrees},
		// A destroy RPC's planned_identity is the prior identity (Core sends
		// BeforeIdentity): kind identity must equal it, so an edited envelope
		// cannot pick another object's delete key.
		{"delete identity equal", wrapped(t, header(hook.OpDelete, "", bobIdentity, "identity", false), ""), thing(t, "p"), thing(t, ""), same, ""},
		{"delete identity differs", wrapped(t, header(hook.OpDelete, "", bobIdentity, "identity", false), ""), thing(t, "p"), thing(t, ""), other, disagrees},
		{"delete identity no identity schema", wrapped(t, header(hook.OpDelete, "", `{"id":"bobthecorp-other"}`, "identity", false), ""), thing(t, "p"), thing(t, ""), nil, disagrees},
		{"delete identity all null", rawEnv(`{"v":1,"ctf":{"op":"delete","prior_identity_kind":"identity","prior_identity":{"bucket":null}}}`, ""), thing(t, "p"), thing(t, ""),
			identityMsgpack(t, map[string]any{"bucket": nil}), disagrees},
		{"replace destroy identity equal", wrapped(t, header(hook.OpReplace, "", bobIdentity, "identity", false), ""), thing(t, "p"), thing(t, ""), same, ""},
		{"replace destroy identity differs", wrapped(t, header(hook.OpReplace, "", bobIdentity, "identity", false), ""), thing(t, "p"), thing(t, ""), other, disagrees},
		{"replace destroy identity no identity schema", wrapped(t, header(hook.OpReplace, "", bobIdentity, "identity", false), ""), thing(t, "p"), thing(t, ""), nil, disagrees},
		// A destroy whose request carries an identity keys by it: an edited
		// envelope cannot switch to kind id, whose {id} key may match a
		// same-type object with the same id elsewhere in the verdict.
		{"delete id with identity sent", wrapped(t, header(hook.OpDelete, "", "", "id", false), ""), thing(t, "p"), thing(t, ""), same, disagrees},
		{"replace destroy id with identity sent", wrapped(t, header(hook.OpReplace, "", "", "id", false), ""), thing(t, "p"), thing(t, ""), same, disagrees},
		{"delete id all null identity", wrapped(t, header(hook.OpDelete, "", "", "id", false), ""), thing(t, "p"), thing(t, ""), identityMsgpack(t, map[string]any{"bucket": nil}), ""},
		{"delete id no identity", wrapped(t, header(hook.OpDelete, "", "", "id", false), ""), thing(t, "p"), thing(t, ""), nil, ""},
		{"update id with identity sent", wrapped(t, header(hook.OpUpdate, "", "", "id", false), ""), thing(t, "p"), thing(t, "q"), same, ""},
		{"delete identity undecodable prior", wrapped(t, header(hook.OpDelete, "", bobIdentity, "identity", false), ""), notMsgpack, thing(t, ""), same, disagrees},
		{"id present", wrapped(t, header(hook.OpUpdate, "", "", "id", false), ""), thing(t, "p"), thing(t, "q"), nil, ""},
		{"id missing", wrapped(t, header(hook.OpUpdate, "", "", "id", false), ""), thingNoID(t), thing(t, "q"), nil, disagrees},
		{"none with id", wrapped(t, header(hook.OpDelete, "", "", "none", false), ""), thing(t, "p"), thing(t, ""), nil, disagrees},
		{"none without id", wrapped(t, header(hook.OpUpdate, "", "", "none", false), ""), thingNoID(t), thing(t, "q"), nil, ""},
		{"empty kind", wrapped(t, header(hook.OpUpdate, "", "", "", false), ""), thing(t, "p"), thing(t, "q"), nil, disagrees},
		{"create empty kind", wrapped(t, header(hook.OpCreate, "", "", "", false), ""), thing(t, ""), thing(t, "q"), nil, disagrees},
		{"delete empty kind", wrapped(t, header(hook.OpDelete, "", "", "", false), ""), thing(t, "p"), thing(t, ""), nil, disagrees},
		// The destroy RPC of a destroy-before-create replace carries the create
		// half's envelope (rpcseq goldens): it makes no claim about the prior.
		{"destroy with create half envelope", wrapped(t, header(hook.OpCreate, "", "", "none", false), ""), thing(t, "p"), thing(t, ""), nil, ""},
		// The tainted path keys kind id by FORMAT.md v1 rule 1 even when
		// Terraform sends the identity.
		{"destroy with create half envelope identity sent", wrapped(t, header(hook.OpCreate, "", "", "none", false), ""), thing(t, "p"), thing(t, ""), same, ""},
		{"update with create envelope", wrapped(t, header(hook.OpCreate, "", "", "none", false), ""), thing(t, "p"), thing(t, "q"), nil, disagrees},
		// A create envelope claiming a prior on a destroy: Unwrap
		// rejects it, so the block records envelope_invalid.
		{"destroy with create envelope kind id", rawEnv(`{"v":1,"ctf":{"op":"create","prior_identity_kind":"id"}}`, ""), thing(t, "p"), thing(t, ""), nil, invalid},
	} {
		rec := &hooktest.Recorder{}
		client, up, _ := startRoute(t, rec)
		got, err := client.ApplyResourceChange(context.Background(), &tfplugin5.ApplyResourceChange_Request{
			TypeName: "fake_thing", PriorState: tc.prior, PlannedState: tc.planned, Config: thing(t, "cfg"), PlannedPrivate: tc.pp, PlannedIdentity: tc.identity,
		})
		if err != nil {
			t.Fatal(err)
		}
		reqs := rec.Requests()
		reached := len(reqs) > 0 && reqs[0].Blocked == ""
		switch {
		case tc.want == "" && (!reached || slices.ContainsFunc(reqs, func(r *hook.Request) bool { return r.Blocked != "" })):
			t.Errorf("%s: blocked with %v, want the hook", tc.name, summaries(got.Diagnostics))
		case tc.want != "" && (reached || slices.Contains(up.calls, "ApplyResourceChange") || got.NewState != nil || !slices.Equal(summaries(got.Diagnostics), []string{tc.want})):
			t.Errorf("%s: diagnostics %v, hook reached %v, want only %s", tc.name, summaries(got.Diagnostics), reached, tc.want)
		case tc.want != "":
			block := hook.BlockEnvelopeInvalid
			if tc.want == disagrees {
				block = hook.BlockEnvelopeDisagrees
			}
			if len(reqs) != 1 || fmt.Sprintf("%+v", *reqs[0]) != fmt.Sprintf("%+v", hook.Request{Stage: hook.StageApplyPre, Kind: hook.KindResource,
				TypeName: "fake_thing", Op: planOp(tc.prior, tc.planned, 0), Blocked: block}) {
				t.Errorf("%s: hook requests %+v, want only the %s block record request", tc.name, reqs, block)
			}
		}
	}
}

// TestEnvelopeKeyFromRequest: once the envelope passes the
// cross-check, apply_pre gets the request's identity bytes in the form the
// plan stamps, never the envelope's, on the update and destroy RPC.
func TestEnvelopeKeyFromRequest(t *testing.T) {
	reordered := `{"v":1,"ctf":{"op":"%s","prior_identity_kind":"identity","prior_identity":{"bucket":"bobthecorp-logs", "account_id":"123456789012"}}}`
	ident := identityMsgpack(t, map[string]any{"account_id": "123456789012", "bucket": "bobthecorp-logs"})
	for _, tc := range []struct {
		op      hook.Op
		planned *tfplugin5.DynamicValue
	}{{hook.OpUpdate, thing(t, "q")}, {hook.OpDelete, thing(t, "")}, {hook.OpReplace, thing(t, "")}} {
		rec := &hooktest.Recorder{}
		client, _, _ := startRoute(t, rec)
		if _, err := client.ApplyResourceChange(context.Background(), &tfplugin5.ApplyResourceChange_Request{
			TypeName: "fake_thing", PriorState: thing(t, "p"), PlannedState: tc.planned, Config: thing(t, "cfg"),
			PlannedPrivate: rawEnv(fmt.Sprintf(reordered, tc.op), ""), PlannedIdentity: ident,
		}); err != nil {
			t.Fatal(err)
		}
		var got string
		if reqs := rec.Requests(); len(reqs) > 0 && reqs[0].Envelope != nil {
			got = string(reqs[0].Envelope.CTF.PriorIdentity)
		}
		if got != bobIdentity {
			t.Errorf("%s: apply_pre prior identity %s, want the request's %s", tc.op, got, bobIdentity)
		}
	}
}

// TestEnvelopeDestroyIdentityNotSent: a destroy RPC without an identity
// for a kind identity envelope tells the user to upgrade Terraform (1.12 to
// 1.16.5 send none on the destroy half of a replace), naming no value; an
// update without one keeps the generic text.
func TestEnvelopeDestroyIdentityNotSent(t *testing.T) {
	allNull := identityMsgpack(t, map[string]any{"account_id": nil, "bucket": nil})
	for _, tc := range []struct {
		planned  *tfplugin5.DynamicValue
		identity *tfplugin5.ResourceIdentityData
		upgrade  bool
	}{
		{thing(t, ""), nil, true},
		{thing(t, ""), &tfplugin5.ResourceIdentityData{IdentityData: &tfplugin5.DynamicValue{}}, true},
		{thing(t, ""), allNull, false}, // Terraform sent an identity: no upgrade advice
		{thing(t, "q"), nil, false},
	} {
		rec := &hooktest.Recorder{}
		client, _, _ := startRoute(t, rec)
		got, err := client.ApplyResourceChange(context.Background(), &tfplugin5.ApplyResourceChange_Request{
			TypeName: "fake_thing", PriorState: thing(t, "p"), PlannedState: tc.planned, Config: thing(t, "cfg"),
			PlannedPrivate: wrapped(t, header(hook.OpReplace, "", bobIdentity, "identity", false), ""), PlannedIdentity: tc.identity,
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Diagnostics) != 1 {
			t.Fatalf("diagnostics %v, want one", summaries(got.Diagnostics))
		}
		d := got.Diagnostics[0].Detail
		if strings.Contains(d, "use Terraform 1.16.6 or later") != tc.upgrade || strings.Contains(d, "bobthecorp") || strings.Contains(d, "123456789012") {
			t.Errorf("detail %q, want upgrade advice %t and no value", d, tc.upgrade)
		}
		// Either text, the hook records only the disagreement block.
		if reqs := rec.Requests(); len(reqs) != 1 || fmt.Sprintf("%+v", *reqs[0]) != fmt.Sprintf("%+v", hook.Request{Stage: hook.StageApplyPre, Kind: hook.KindResource,
			TypeName: "fake_thing", Op: planOp(thing(t, "p"), tc.planned, 0), Blocked: hook.BlockEnvelopeDisagrees}) {
			t.Errorf("hook requests %+v, want only the envelope_disagrees block record request", reqs)
		}
	}
}

// TestEnvelopeCreateOnDestroy: an op create envelope on a destroy RPC
// makes no claim only with kind none; Unwrap rejects any other kind, and
// envelopeDisagrees does too should a header reach it.
func TestEnvelopeCreateOnDestroy(t *testing.T) {
	for kind, want := range map[string]string{"none": "", "id": "prior identity on create", "identity": "prior identity on create"} {
		h := header(hook.OpCreate, "", "", "none", false)
		h.CTF.PriorIdentityKind = kind
		if kind == "identity" {
			h.CTF.PriorIdentity = []byte(bobIdentity)
		}
		got := (&server5{}).envelopeDisagrees(context.Background(), &h, &tfplugin5.ApplyResourceChange_Request{
			TypeName: "fake_thing", PriorState: thing(t, "p"), PlannedState: thing(t, ""),
		})
		if got != want {
			t.Errorf("kind %s: %q, want %q", kind, got, want)
		}
	}
}

// TestEnvelopeMutation rewrites every field of a recorded envelope under a
// blocking hook and asserts no mutation lets the apply through.
func TestEnvelopeMutation(t *testing.T) {
	base := header(hook.OpUpdate, "sha256:0f1e2d", bobIdentity, "identity", false)
	var muts []hook.EnvelopeHeader
	for _, op := range []hook.Op{hook.OpCreate, hook.OpUpdate, hook.OpReplace, hook.OpDelete, hook.OpImport} {
		m := base
		m.CTF.Op = op
		muts = append(muts, m)
	}
	for _, f := range []func(*hook.EnvelopeHeader){
		func(h *hook.EnvelopeHeader) { h.CTF.ControlVersionsDigest = "" },
		func(h *hook.EnvelopeHeader) { h.CTF.ControlVersionsDigest = "sha256:other" },
		func(h *hook.EnvelopeHeader) { h.CTF.PriorIdentity, h.CTF.PriorIdentityKind = nil, "" },
		func(h *hook.EnvelopeHeader) { h.CTF.PriorIdentity, h.CTF.PriorIdentityKind = nil, "id" },
		func(h *hook.EnvelopeHeader) { h.CTF.PriorIdentity, h.CTF.PriorIdentityKind = nil, "none" },
		func(h *hook.EnvelopeHeader) { h.CTF.PriorIdentity = []byte(`{"account_id":"123456789012"}`) },
		func(h *hook.EnvelopeHeader) { h.CTF.Imported = true },
	} {
		m := base
		f(&m)
		muts = append(muts, m)
	}
	ident := identityMsgpack(t, map[string]any{"account_id": "123456789012", "bucket": "bobthecorp-logs"})
	pps := [][]byte{wrapped(t, base, "pp"), []byte("pp"), nil} // last two: envelope stripped
	for _, m := range muts {                                   // framed raw: a tamperer is not bound by Wrap's checks
		hj, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		pps = append(pps, rawEnv(string(hj), "pp"))
	}
	for i, pp := range pps {
		client, up, _ := startRoute(t, &hooktest.Recorder{Respond: hooktest.Deny("blocked")})
		got, err := client.ApplyResourceChange(context.Background(), &tfplugin5.ApplyResourceChange_Request{
			TypeName: "fake_thing", PriorState: thing(t, "p"), PlannedState: thing(t, "q"), Config: thing(t, "cfg"), PlannedPrivate: pp, PlannedIdentity: ident,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !hasErrorDiag(got.Diagnostics) || slices.Contains(up.calls, "ApplyResourceChange") {
			t.Errorf("mutation %d: apply went through: %v", i, summaries(got.Diagnostics))
		}
	}
}

// stateUpstream echoes request private bytes back, so an envelope the proxy
// let through would land in a state-bound field.
type stateUpstream struct{ *resUpstream }

func (u stateUpstream) ApplyResourceChange(ctx context.Context, req *tfplugin5.ApplyResourceChange_Request) (*tfplugin5.ApplyResourceChange_Response, error) {
	resp, err := u.resUpstream.ApplyResourceChange(ctx, req)
	return &tfplugin5.ApplyResourceChange_Response{NewState: resp.NewState, Private: req.PlannedPrivate}, err
}

func (u stateUpstream) ReadResource(_ context.Context, req *tfplugin5.ReadResource_Request) (*tfplugin5.ReadResource_Response, error) {
	return &tfplugin5.ReadResource_Response{NewState: req.CurrentState, Private: req.Private}, nil
}

func (u stateUpstream) ImportResourceState(context.Context, *tfplugin5.ImportResourceState_Request) (*tfplugin5.ImportResourceState_Response, error) {
	return &tfplugin5.ImportResourceState_Response{ImportedResources: []*tfplugin5.ImportResourceState_ImportedResource{{TypeName: "fake_thing", Private: []byte("imp")}}}, nil
}

func (u stateUpstream) MoveResourceState(_ context.Context, req *tfplugin5.MoveResourceState_Request) (*tfplugin5.MoveResourceState_Response, error) {
	return &tfplugin5.MoveResourceState_Response{TargetPrivate: req.SourcePrivate}, nil
}

func TestNoEnvelopeInStateFields(t *testing.T) {
	_, res, _ := startRoute(t, hook.Noop{})
	client, _ := startProxy(t, stateUpstream{res}, Backends{Evaluator: &hooktest.Recorder{}})
	ctx := context.Background()
	plan, err := client.PlanResourceChange(ctx, &tfplugin5.PlanResourceChange_Request{TypeName: "fake_thing", PriorState: thing(t, ""), Config: thing(t, "cfg")})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(plan.PlannedPrivate, envelopeMagic) {
		t.Fatal("plan did not wrap planned_private")
	}
	apply, err := client.ApplyResourceChange(ctx, &tfplugin5.ApplyResourceChange_Request{TypeName: "fake_thing", PriorState: thing(t, ""), PlannedState: plan.PlannedState, Config: thing(t, "cfg"), PlannedPrivate: plan.PlannedPrivate})
	if err != nil {
		t.Fatal(err)
	}
	read, err := client.ReadResource(ctx, &tfplugin5.ReadResource_Request{TypeName: "fake_thing", CurrentState: apply.NewState, Private: apply.Private})
	if err != nil {
		t.Fatal(err)
	}
	imp, err := client.ImportResourceState(ctx, &tfplugin5.ImportResourceState_Request{TypeName: "fake_thing", Id: "i-1"})
	if err != nil {
		t.Fatal(err)
	}
	move, err := client.MoveResourceState(ctx, &tfplugin5.MoveResourceState_Request{TargetTypeName: "fake_thing", SourcePrivate: read.Private})
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{
		"apply new_state": apply.NewState.GetMsgpack(), "apply private": apply.Private,
		"read new_state": read.NewState.GetMsgpack(), "read private": read.Private,
		"import private": imp.ImportedResources[0].Private, "move private": move.TargetPrivate,
	} {
		if bytes.Contains(b, envelopeMagic) {
			t.Errorf("%s carries envelope bytes: %q", name, b)
		}
	}
	if string(apply.Private) != string(res.plan.PlannedPrivate) {
		t.Errorf("apply private = %q, want upstream's planned private", apply.Private)
	}
}

// TestEnvelopePlanIdentityKind: plan stamps prior_identity and
// prior_identity_kind by the 0A rules, and the stamped identity passes the
// apply-time IdentityEqual check against the same identity.
func TestEnvelopePlanIdentityKind(t *testing.T) {
	bob := map[string]any{"account_id": "123456789012", "bucket": "bobthecorp-logs", "n": int64(5), "f": 1.5, "g": 2.0}
	js := func(s string) *tfplugin5.ResourceIdentityData {
		return &tfplugin5.ResourceIdentityData{IdentityData: &tfplugin5.DynamicValue{Json: []byte(s)}}
	}
	both := identityMsgpack(t, bob)
	both.IdentityData.Json = []byte(`{}`)
	nullID := &tfplugin5.ResourceIdentityData{IdentityData: &tfplugin5.DynamicValue{Msgpack: []byte{0xc0}}}
	for _, tc := range []struct {
		name     string
		prior    *tfplugin5.DynamicValue
		identity *tfplugin5.ResourceIdentityData
		kind     string // "" = plan error
		wantID   string // prior_identity JSON
	}{
		{"create", thing(t, ""), nil, "none", ""},
		{"id", thing(t, "p"), nil, "id", ""},
		{"no id", thingNoID(t), nil, "none", ""},
		{"null identity", thing(t, "p"), nullID, "id", ""},
		{"all-null identity", thing(t, "p"), js(`{"bucket":null,"n":null}`), "id", ""},
		{"empty identity", thing(t, "p"), js(`{}`), "id", ""},
		{"all-null identity no id", thingNoID(t), js(`{"bucket":null}`), "none", ""},
		{"one leaf identity", thing(t, "p"), js(`{"bucket":"bobthecorp-logs","n":null}`), "identity", `{"bucket":"bobthecorp-logs","n":null}`},
		{"msgpack identity", thing(t, "p"), identityMsgpack(t, bob), "identity", `{"account_id":"123456789012","bucket":"bobthecorp-logs","f":1.5,"g":2.0,"n":5}`},
		{"json identity", thing(t, "p"), js(`{"bucket":"bobthecorp-logs","n":5}`), "identity", `{"bucket":"bobthecorp-logs","n":5}`},
		{"both codecs", thing(t, "p"), both, "", ""},
		{"not an object", thing(t, "p"), js(`[1]`), "", ""},
		{"prior unreadable", notMsgpack, nil, "", ""},
	} {
		client, _, _ := startRoute(t, hook.Noop{})
		got, err := client.PlanResourceChange(context.Background(), &tfplugin5.PlanResourceChange_Request{
			TypeName: "fake_thing", PriorState: tc.prior, PriorIdentity: tc.identity, Config: thing(t, "cfg"),
		})
		if err != nil {
			t.Fatal(err)
		}
		h, _, err := Unwrap(got.PlannedPrivate)
		if tc.kind == "" {
			if !slices.Contains(summaries(got.Diagnostics), "ERROR:Invalid compliance plan envelope") || h != nil {
				t.Errorf("%s: diagnostics %v, envelope %+v, want a plan error", tc.name, summaries(got.Diagnostics), h)
			}
			continue
		}
		if err != nil || h == nil || h.CTF.PriorIdentityKind != tc.kind || string(h.CTF.PriorIdentity) != tc.wantID {
			t.Errorf("%s: envelope %+v (%v), want kind %q identity %s", tc.name, h, err, tc.kind, tc.wantID)
			continue
		}
		if tc.kind == "identity" && !IdentityEqual(h.CTF.PriorIdentity, tc.identity) {
			t.Errorf("%s: stamped identity %s does not round-trip through IdentityEqual", tc.name, h.CTF.PriorIdentity)
		}
	}
}

// TestEnvelopeReplanCarriesPrior: Core re-plans the create half of
// a destroy-before-create replace (and -replace) with a null prior and
// PriorPrivate = the first plan's planned_private, and the destroy RPC gets
// that re-plan's envelope. The re-plan envelope therefore carries the first
// plan's prior identity and kind under op replace, never the re-plan's own
// PriorIdentity (the new object's), so the destroy RPC recomputes the
// delete key of the destroyed object.
func TestEnvelopeReplanCarriesPrior(t *testing.T) {
	newObj := &tfplugin5.ResourceIdentityData{IdentityData: &tfplugin5.DynamicValue{Json: []byte(`{"bucket":"bobthecorp-new"}`)}}
	for _, tc := range []struct {
		name         string
		priorPrivate []byte
		op           hook.Op
		kind, id     string
	}{
		{"replace identity", wrapped(t, header(hook.OpReplace, "", bobIdentity, "identity", false), "up"), hook.OpReplace, "identity", bobIdentity},
		{"replace id", wrapped(t, header(hook.OpReplace, "", "", "id", false), "up"), hook.OpReplace, "id", ""},
		{"-replace update", wrapped(t, header(hook.OpUpdate, "", bobIdentity, "identity", false), "up"), hook.OpReplace, "identity", bobIdentity},
		{"first plan kind none", wrapped(t, header(hook.OpReplace, "", "", "none", false), "up"), hook.OpCreate, "none", ""},
		{"create envelope", wrapped(t, header(hook.OpCreate, "", "", "none", false), "up"), hook.OpCreate, "none", ""},
		{"state private", []byte(`{"schema_version":"1"}`), hook.OpCreate, "none", ""},
		{"no private", nil, hook.OpCreate, "none", ""},
		{"malformed envelope", envelopeMagic, hook.OpCreate, "none", ""},
	} {
		rec := &hooktest.Recorder{}
		client, _, _ := startRoute(t, rec)
		got, err := client.PlanResourceChange(context.Background(), &tfplugin5.PlanResourceChange_Request{
			TypeName: "fake_thing", PriorState: thing(t, ""), PriorPrivate: tc.priorPrivate, PriorIdentity: newObj, Config: thing(t, "cfg"),
		})
		if err != nil {
			t.Fatal(err)
		}
		h, _, err := Unwrap(got.PlannedPrivate)
		if err != nil || h == nil || h.CTF.Op != tc.op || h.CTF.PriorIdentityKind != tc.kind || string(h.CTF.PriorIdentity) != tc.id {
			t.Errorf("%s: envelope %+v (%v), want op %s kind %s identity %s", tc.name, h, err, tc.op, tc.kind, tc.id)
			continue
		}
		if op := rec.Requests()[0].Op; op != hook.OpCreate {
			t.Errorf("%s: plan hook op %q, want create (only the envelope carries replace)", tc.name, op)
		}
		// The destroy RPC Core sends with that envelope, planned_identity the
		// destroyed object's (Core sends BeforeIdentity): the envelope passes
		// the prior-state cross-check and reaches apply_pre with the carried
		// identity, or (kind none) stays the classified change it was. A
		// first plan of kind id saw no usable identity, so its destroy carries
		// none.
		destroyed := identityMsgpack(t, map[string]any{"account_id": "123456789012", "bucket": "bobthecorp-logs"})
		if tc.kind == "id" {
			destroyed = nil
		}
		_, err = client.ApplyResourceChange(context.Background(), &tfplugin5.ApplyResourceChange_Request{
			TypeName: "fake_thing", PriorState: thing(t, "old"), PlannedState: thing(t, ""), Config: thing(t, ""), PlannedPrivate: got.PlannedPrivate,
			PlannedIdentity: destroyed,
		})
		if err != nil {
			t.Fatal(err)
		}
		var pre *hook.Request
		for _, r := range rec.Requests() {
			if r.Stage == hook.StageApplyPre {
				pre = r
			}
		}
		wantOp := hook.OpChange
		if tc.op == hook.OpReplace {
			wantOp = hook.OpReplace
		}
		if pre == nil {
			t.Errorf("%s: the destroy RPC never reached apply_pre", tc.name)
			continue
		}
		if pre.Op != wantOp || pre.Envelope == nil || pre.Envelope.CTF.PriorIdentityKind != tc.kind || string(pre.Envelope.CTF.PriorIdentity) != tc.id {
			t.Errorf("%s: destroy RPC apply_pre op %q envelope %+v, want %s kind %s", tc.name, pre.Op, pre.Envelope, wantOp, tc.kind)
		}
	}
}

// TestEnvelopeReplanStripsPriorPrivate: the create re-plan's
// PriorPrivate is the first plan's envelope; upstream gets only the bytes it
// produced itself (hashicorp/aws SDKv2 json-decodes PriorPrivate and fails
// on our header). Anything that is not a readable envelope passes untouched.
func TestEnvelopeReplanStripsPriorPrivate(t *testing.T) {
	for _, tc := range []struct {
		name               string
		priorPrivate, want []byte
	}{
		{"envelope", wrapped(t, header(hook.OpReplace, "", bobIdentity, "identity", false), `{"up":1}`), []byte(`{"up":1}`)},
		{"envelope empty tail", wrapped(t, header(hook.OpCreate, "", "", "none", false), ""), nil},
		{"state private", []byte(`{"schema_version":"1"}`), []byte(`{"schema_version":"1"}`)},
		{"no private", nil, nil},
		{"malformed envelope", envelopeMagic, envelopeMagic},
	} {
		client, up, _ := startRoute(t, &hooktest.Recorder{})
		if _, err := client.PlanResourceChange(context.Background(), &tfplugin5.PlanResourceChange_Request{
			TypeName: "fake_thing", PriorState: thing(t, ""), PriorPrivate: tc.priorPrivate, Config: thing(t, "cfg"),
		}); err != nil {
			t.Fatal(err)
		}
		if got := up.planReq.GetPriorPrivate(); !bytes.Equal(got, tc.want) {
			t.Errorf("%s: upstream prior_private = %q, want %q", tc.name, got, tc.want)
		}
	}
}
