package proxy

import (
	"context"
	"reflect"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/hook/hooktest"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

func idJSON(s string) *tfplugin5.ResourceIdentityData {
	return &tfplugin5.ResourceIdentityData{IdentityData: &tfplugin5.DynamicValue{Json: []byte(s)}}
}

// TestRouteIdentity: every resource stage hands the hook the identity of the
// object it evaluates: planned at plan and apply_pre, prior for a
// planned delete, new at apply_post, read and import; nil when absent or
// unreadable.
func TestRouteIdentity(t *testing.T) {
	want := map[string]any{"id": "i-1"}
	identities := func(rec *hooktest.Recorder) map[hook.Stage]map[string]any {
		out := map[hook.Stage]map[string]any{}
		for _, r := range rec.Requests() {
			out[r.Stage] = r.Identity
		}
		return out
	}
	ctx := context.Background()

	t.Run("plan and apply", func(t *testing.T) {
		rec := &hooktest.Recorder{}
		client, up, _ := startRoute(t, rec)
		up.plan.PlannedIdentity = idJSON(`{"id":"i-1"}`)
		up.apply.NewIdentity = idJSON(`{"id":"i-1"}`)
		if _, err := client.PlanResourceChange(ctx, &tfplugin5.PlanResourceChange_Request{TypeName: "fake_thing", PriorState: thing(t, "prior"),
			PriorIdentity: idJSON(`{"id":"other"}`), Config: thing(t, "cfg")}); err != nil {
			t.Fatal(err)
		}
		if _, err := client.ApplyResourceChange(ctx, &tfplugin5.ApplyResourceChange_Request{TypeName: "fake_thing", PriorState: thing(t, "prior"),
			PlannedState: thing(t, "planned"), PlannedIdentity: idJSON(`{"id":"i-1"}`), Config: thing(t, "cfg")}); err != nil {
			t.Fatal(err)
		}
		got := identities(rec)
		for _, s := range []hook.Stage{hook.StagePlan, hook.StageApplyPre, hook.StageApplyPost} {
			if !reflect.DeepEqual(got[s], want) {
				t.Errorf("%s identity = %v, want %v", s, got[s], want)
			}
		}
	})

	t.Run("delete", func(t *testing.T) {
		rec := &hooktest.Recorder{}
		client, up, _ := startRoute(t, rec)
		up.plan.PlannedState, up.plan.RequiresReplace = thing(t, ""), nil
		if _, err := client.PlanResourceChange(ctx, &tfplugin5.PlanResourceChange_Request{TypeName: "fake_thing", PriorState: thing(t, "prior"),
			PriorIdentity: idJSON(`{"id":"i-1"}`), ProposedNewState: thing(t, "")}); err != nil {
			t.Fatal(err)
		}
		if _, err := client.ApplyResourceChange(ctx, &tfplugin5.ApplyResourceChange_Request{TypeName: "fake_thing", PriorState: thing(t, "prior"),
			PlannedState: thing(t, ""), PlannedIdentity: idJSON(`{"id":"i-1"}`)}); err != nil {
			t.Fatal(err)
		}
		got := identities(rec)
		if !reflect.DeepEqual(got[hook.StagePlan], want) || got[hook.StageApplyPre] != nil {
			t.Errorf("plan identity = %v, want prior %v; apply_pre identity = %v, want nil", got[hook.StagePlan], want, got[hook.StageApplyPre])
		}
	})

	t.Run("read and import", func(t *testing.T) {
		rec := &hooktest.Recorder{}
		client, _ := startRead(t, rec)
		if _, err := client.ReadResource(ctx, &tfplugin5.ReadResource_Request{TypeName: "fake_thing", CurrentState: thing(t, "prior")}); err != nil {
			t.Fatal(err)
		}
		if _, err := client.ImportResourceState(ctx, &tfplugin5.ImportResourceState_Request{TypeName: "fake_thing", Id: "i-1"}); err != nil {
			t.Fatal(err)
		}
		got := identities(rec)
		if !reflect.DeepEqual(got[hook.StageRead], want) || !reflect.DeepEqual(rec.Requests()[1].Identity, want) {
			t.Errorf("read identity = %v, import identity = %v, want %v", got[hook.StageRead], rec.Requests()[1].Identity, want)
		}
	})
}

func TestIdentityObject(t *testing.T) {
	for name, c := range map[string]struct {
		in   *tfplugin5.ResourceIdentityData
		want map[string]any
	}{
		"absent":      {nil, nil},
		"no data":     {&tfplugin5.ResourceIdentityData{}, nil},
		"json":        {idJSON(`{"id":"i-1"}`), map[string]any{"id": "i-1"}},
		"msgpack":     {&tfplugin5.ResourceIdentityData{IdentityData: &tfplugin5.DynamicValue{Msgpack: []byte{0x81, 0xa2, 'i', 'd', 0xa3, 'i', '-', '1'}}}, map[string]any{"id": "i-1"}},
		"both codecs": {&tfplugin5.ResourceIdentityData{IdentityData: &tfplugin5.DynamicValue{Json: []byte(`{"id":"i-1"}`), Msgpack: []byte{0x80}}}, nil},
		"not object":  {idJSON(`"i-1"`), nil},
		"duplicate":   {idJSON(`{"id":"a","id":"b"}`), nil},
		"unknown":     {&tfplugin5.ResourceIdentityData{IdentityData: &tfplugin5.DynamicValue{Msgpack: []byte{0x81, 0xa2, 'i', 'd', 0xd4, 0x00, 0x00}}}, nil},
	} {
		if got := identityObject(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: identityObject = %v, want %v", name, got, c.want)
		}
	}
}
