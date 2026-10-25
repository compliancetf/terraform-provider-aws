package proxy

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/hook/hooktest"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

// importUpstream imports one fake_thing with id i-1 (and identity, when set).
type importUpstream struct {
	*resUpstream
	identity *tfplugin5.ResourceIdentityData
	state    *tfplugin5.DynamicValue
}

func (u importUpstream) ImportResourceState(context.Context, *tfplugin5.ImportResourceState_Request) (*tfplugin5.ImportResourceState_Response, error) {
	return &tfplugin5.ImportResourceState_Response{ImportedResources: []*tfplugin5.ImportResourceState_ImportedResource{
		{TypeName: "fake_thing", State: u.state, Private: []byte("imp"), Identity: u.identity},
	}}, nil
}

// thingWithID is a fake_thing with the given id.
func thingWithID(t *testing.T, id, name string) *tfplugin5.DynamicValue {
	t.Helper()
	dv, err := tfprotov5.NewDynamicValue(thingType, tftypes.NewValue(thingType, map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, id), "name": tftypes.NewValue(tftypes.String, name)}))
	if err != nil {
		t.Fatal(err)
	}
	return &tfplugin5.DynamicValue{Msgpack: dv.MsgPack}
}

func startImport(t *testing.T, identity *tfplugin5.ResourceIdentityData, requiresReplace bool) (tfplugin5.ProviderClient, *hooktest.Recorder) {
	t.Helper()
	_, res, _ := startRoute(t, hook.Noop{})
	res.plan.Deferred = nil
	if !requiresReplace {
		res.plan.RequiresReplace = nil
	}
	rec := &hooktest.Recorder{}
	client, _ := startProxy(t, importUpstream{res, identity, thingWithID(t, "i-1", "imp")}, Backends{Evaluator: rec})
	return client, rec
}

// planEnvelope plans an update of prior and returns the envelope header and
// the op the hook saw.
func planEnvelope(t *testing.T, client tfplugin5.ProviderClient, rec *hooktest.Recorder, prior *tfplugin5.DynamicValue, identity *tfplugin5.ResourceIdentityData) (*hook.EnvelopeHeader, hook.Op) {
	t.Helper()
	got, err := client.PlanResourceChange(context.Background(), &tfplugin5.PlanResourceChange_Request{
		TypeName: "fake_thing", PriorState: prior, PriorIdentity: identity, Config: thing(t, "cfg")})
	if err != nil {
		t.Fatal(err)
	}
	h, _, err := Unwrap(got.PlannedPrivate)
	if err != nil || h == nil {
		t.Fatalf("planned_private %q: %v", got.PlannedPrivate, err)
	}
	reqs := rec.Requests()
	return h, reqs[len(reqs)-1].Op
}

func importOnce(t *testing.T, client tfplugin5.ProviderClient) {
	t.Helper()
	if _, err := client.ImportResourceState(context.Background(), &tfplugin5.ImportResourceState_Request{TypeName: "fake_thing", Id: "i-1"}); err != nil {
		t.Fatal(err)
	}
}

// TestImportedPlanStamp: the plan of an object this process imported is op
// import with imported true, for the hook and in the envelope, once.
func TestImportedPlanStamp(t *testing.T) {
	ident := identityMsgpack(t, map[string]any{"account_id": "111111111111", "id": "i-1"})
	for _, tc := range []struct {
		name                   string
		importIdent, planIdent *tfplugin5.ResourceIdentityData
		prior                  *tfplugin5.DynamicValue
		imported               bool
	}{
		{"id match", nil, nil, thingWithID(t, "i-1", "p"), true},
		{"identity match", ident, ident, thingWithID(t, "i-1", "p"), true},
		{"import without identity, plan with identity: id", nil, ident, thingWithID(t, "i-1", "p"), true},
		{"import with identity, plan without identity (Terraform before identity): id", ident, nil, thingWithID(t, "i-1", "p"), true},
		{"other id", nil, nil, thingWithID(t, "i-2", "p"), false},
		{"other identity, same id", ident, identityMsgpack(t, map[string]any{"account_id": "222222222222", "id": "i-1"}), thingWithID(t, "i-1", "p"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, rec := startImport(t, tc.importIdent, false)
			importOnce(t, client)
			h, op := planEnvelope(t, client, rec, tc.prior, tc.planIdent)
			wantOp := hook.OpUpdate
			if tc.imported {
				wantOp = hook.OpImport
			}
			if h.CTF.Op != wantOp || h.CTF.Imported != tc.imported || op != wantOp {
				t.Errorf("envelope op %q imported %v, hook op %q; want %q %v", h.CTF.Op, h.CTF.Imported, op, wantOp, tc.imported)
			}
			// The entry is taken by the first matching plan.
			h, op = planEnvelope(t, client, rec, tc.prior, tc.planIdent)
			if h.CTF.Op != hook.OpUpdate || h.CTF.Imported || op != hook.OpUpdate {
				t.Errorf("second plan: envelope op %q imported %v, hook op %q; want a plain update", h.CTF.Op, h.CTF.Imported, op)
			}
		})
	}
}

// TestImportedPlanOtherProcess: a CLI import runs in its own provider
// process, so the later plan (a fresh process) is a plain update.
func TestImportedPlanOtherProcess(t *testing.T) {
	importer, _ := startImport(t, nil, false)
	importOnce(t, importer)
	client, rec := startImport(t, nil, false)
	if h, op := planEnvelope(t, client, rec, thingWithID(t, "i-1", "p"), nil); h.CTF.Op != hook.OpUpdate || h.CTF.Imported || op != hook.OpUpdate {
		t.Errorf("envelope op %q imported %v, hook op %q; want a plain update", h.CTF.Op, h.CTF.Imported, op)
	}
}

// TestImportedPlanReplaceStaysReplace: import never narrows a replace; the
// envelope still marks the object imported.
func TestImportedPlanReplaceStaysReplace(t *testing.T) {
	client, rec := startImport(t, nil, true)
	importOnce(t, client)
	if h, op := planEnvelope(t, client, rec, thingWithID(t, "i-1", "p"), nil); h.CTF.Op != hook.OpReplace || !h.CTF.Imported || op != hook.OpReplace {
		t.Errorf("envelope op %q imported %v, hook op %q; want replace, imported", h.CTF.Op, h.CTF.Imported, op)
	}
}

// TestImportedApplyOp: at apply an import envelope combines as the update it
// is, so the hook sees the op an unstamped plan gives (never change).
func TestImportedApplyOp(t *testing.T) {
	for _, env := range []hook.EnvelopeHeader{
		header(hook.OpImport, "", "", "id", true),
		header(hook.OpUpdate, "", "", "id", true),
		header(hook.OpUpdate, "", "", "id", false),
	} {
		rec := &hooktest.Recorder{}
		client, _, _ := startRoute(t, rec)
		_, err := client.ApplyResourceChange(context.Background(), &tfplugin5.ApplyResourceChange_Request{
			TypeName: "fake_thing", PriorState: thing(t, "p"), PlannedState: thing(t, "q"), Config: thing(t, "cfg"),
			PlannedPrivate: wrapped(t, env, "pp"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if pre := rec.Requests()[0]; pre.Op != hook.OpUpdate {
			t.Errorf("envelope %+v: apply_pre op %q, want update", env.CTF, pre.Op)
		}
	}
}

// TestImportedSetObjects: objects are taken whole and only once; two objects
// sharing an id stay apart by identity.
func TestImportedSetObjects(t *testing.T) {
	var s importedSet
	a := importedKeys{byIdentity: "t\x00identity\x00A", byID: "t\x00id\x00X"}
	b := importedKeys{byIdentity: "t\x00identity\x00B", byID: "t\x00id\x00X"}
	s.add(a)
	s.add(a) // imported twice: still one object
	s.add(b)
	if !s.take(importedKeys{byIdentity: a.byIdentity, byID: a.byID}) || s.take(importedKeys{byIdentity: a.byIdentity}) {
		t.Fatal("A must be taken exactly once")
	}
	if s.take(importedKeys{byIdentity: "t\x00identity\x00C", byID: "t\x00id\x00X"}) {
		t.Fatal("an identity-keyed object matched another identity by id")
	}
	if !s.take(importedKeys{byID: b.byID}) || !s.empty() {
		t.Fatal("B must still be taken by id when the plan carries no identity")
	}
}
