package proxy

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/hook/hooktest"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

// resUpstream answers the resource RPCs with canned responses.
type resUpstream struct {
	*fakeUpstream5
	validate *tfplugin5.ValidateResourceTypeConfig_Response
	plan     *tfplugin5.PlanResourceChange_Response
	planReq  *tfplugin5.PlanResourceChange_Request
	apply    *tfplugin5.ApplyResourceChange_Response
	applyReq *tfplugin5.ApplyResourceChange_Request
}

func (u *resUpstream) ValidateResourceTypeConfig(context.Context, *tfplugin5.ValidateResourceTypeConfig_Request) (*tfplugin5.ValidateResourceTypeConfig_Response, error) {
	u.record("ValidateResourceTypeConfig")
	return u.validate, nil
}

func (u *resUpstream) PlanResourceChange(_ context.Context, req *tfplugin5.PlanResourceChange_Request) (*tfplugin5.PlanResourceChange_Response, error) {
	u.record("PlanResourceChange")
	u.planReq = req
	return u.plan, nil
}

func (u *resUpstream) ApplyResourceChange(_ context.Context, req *tfplugin5.ApplyResourceChange_Request) (*tfplugin5.ApplyResourceChange_Response, error) {
	u.record("ApplyResourceChange")
	u.applyReq = req
	return u.apply, nil
}

var thingType = tftypes.Object{AttributeTypes: map[string]tftypes.Type{"id": tftypes.String, "name": tftypes.String}}

func thingSchema() *tfplugin5.GetProviderSchema_Response {
	return &tfplugin5.GetProviderSchema_Response{ResourceSchemas: map[string]*tfplugin5.Schema{"fake_thing": {Block: &tfplugin5.Schema_Block{Attributes: []*tfplugin5.Schema_Attribute{
		{Name: "id", Type: []byte(`"string"`), Computed: true},
		{Name: "name", Type: []byte(`"string"`), Optional: true},
	}}}}}
}

// thing is a fake_thing value; name "" is a null object.
func thing(t *testing.T, name string) *tfplugin5.DynamicValue {
	t.Helper()
	v := tftypes.NewValue(thingType, nil)
	if name != "" {
		v = tftypes.NewValue(thingType, map[string]tftypes.Value{"id": tftypes.NewValue(tftypes.String, "i-1"), "name": tftypes.NewValue(tftypes.String, name)})
	}
	dv, err := tfprotov5.NewDynamicValue(thingType, v)
	if err != nil {
		t.Fatal(err)
	}
	return &tfplugin5.DynamicValue{Msgpack: dv.MsgPack}
}

func nameOf(t *testing.T, v *hook.Value) string {
	t.Helper()
	if v == nil {
		return "<absent>"
	}
	got, err := v.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got.IsNull() {
		return "<null>"
	}
	var m map[string]tftypes.Value
	var s string
	if err := got.As(&m); err != nil {
		t.Fatal(err)
	}
	if err := m["name"].As(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func diag(sev tfplugin5.Diagnostic_Severity, summary string) *tfplugin5.Diagnostic {
	return &tfplugin5.Diagnostic{Severity: sev, Summary: summary}
}

func summaries(diags []*tfplugin5.Diagnostic) []string {
	var out []string
	for _, d := range diags {
		out = append(out, d.Severity.String()+":"+d.Summary)
	}
	return out
}

func startRoute(t *testing.T, ev hook.Evaluator) (tfplugin5.ProviderClient, *resUpstream, *server5) {
	t.Helper()
	up := &resUpstream{
		fakeUpstream5: &fakeUpstream5{schema: thingSchema()},
		validate:      &tfplugin5.ValidateResourceTypeConfig_Response{Diagnostics: []*tfplugin5.Diagnostic{diag(tfplugin5.Diagnostic_WARNING, "upstream")}},
		apply:         &tfplugin5.ApplyResourceChange_Response{NewState: thing(t, "new"), Private: []byte("upstream-private"), Diagnostics: []*tfplugin5.Diagnostic{diag(tfplugin5.Diagnostic_WARNING, "upstream")}},
	}
	up.plan = &tfplugin5.PlanResourceChange_Response{
		PlannedState:    thing(t, "planned"),
		PlannedPrivate:  []byte("upstream-planned-private"),
		RequiresReplace: []*tfplugin5.AttributePath{{Steps: []*tfplugin5.AttributePath_Step{{Selector: &tfplugin5.AttributePath_Step_AttributeName{AttributeName: "name"}}}}},
		Deferred:        &tfplugin5.Deferred{Reason: tfplugin5.Deferred_RESOURCE_CONFIG_UNKNOWN},
		Diagnostics:     []*tfplugin5.Diagnostic{diag(tfplugin5.Diagnostic_WARNING, "upstream")},
	}
	client, p := startProxy(t, up, Backends{Evaluator: ev})
	return client, up, p
}

// warmSchema calls GetSchema as Terraform does first. A value whose type
// needs a schema fetch decodes only while its RPC runs, so tests that read
// recorded values after the RPC warm the cache.
func warmSchema(t *testing.T, client tfplugin5.ProviderClient) {
	t.Helper()
	if _, err := client.GetSchema(context.Background(), &tfplugin5.GetProviderSchema_Request{}); err != nil {
		t.Fatal(err)
	}
}

func warnAt(stage hook.Stage) func(*hook.Request) (*hook.Result, error) {
	return func(r *hook.Request) (*hook.Result, error) {
		return &hook.Result{Diagnostics: []hook.Diagnostic{{Severity: hook.SeverityWarning, Summary: string(r.Stage), Attribute: tftypes.NewAttributePath().WithAttributeName("name")}}}, nil
	}
}

func TestRouteValidate(t *testing.T) {
	rec := &hooktest.Recorder{Respond: hooktest.Deny("proxy")}
	client, up, _ := startRoute(t, rec)
	warmSchema(t, client)
	got, err := client.ValidateResourceTypeConfig(context.Background(), &tfplugin5.ValidateResourceTypeConfig_Request{TypeName: "fake_thing", Config: thing(t, "cfg")})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(up.calls, "ValidateResourceTypeConfig") {
		t.Errorf("upstream calls = %v, want validate forwarded despite the error", up.calls)
	}
	if want := []string{"WARNING:upstream", "ERROR:proxy"}; !slices.Equal(summaries(got.Diagnostics), want) {
		t.Errorf("diagnostics = %v, want %v", summaries(got.Diagnostics), want)
	}
	reqs := rec.Requests()
	if len(reqs) != 1 || reqs[0].Stage != hook.StageValidate || reqs[0].Kind != hook.KindResource || reqs[0].TypeName != "fake_thing" {
		t.Fatalf("requests = %+v, want one validate for fake_thing", reqs)
	}
	if n := nameOf(t, reqs[0].Config); n != "cfg" || reqs[0].Prior != nil || reqs[0].Planned != nil {
		t.Errorf("config = %s, prior %v, planned %v; want cfg and nothing else", n, reqs[0].Prior, reqs[0].Planned)
	}
}

func TestRoutePlan(t *testing.T) {
	rec := &hooktest.Recorder{}
	client, up, _ := startRoute(t, rec)
	warmSchema(t, client)
	rec.Respond = func(r *hook.Request) (*hook.Result, error) {
		if !slices.Contains(up.calls, "PlanResourceChange") {
			t.Error("hook ran before the plan was forwarded")
		}
		return warnAt(hook.StagePlan)(r)
	}
	got, err := client.PlanResourceChange(context.Background(), &tfplugin5.PlanResourceChange_Request{TypeName: "fake_thing", PriorState: thing(t, "prior"), Config: thing(t, "cfg")})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"WARNING:upstream", "WARNING:plan"}; !slices.Equal(summaries(got.Diagnostics), want) {
		t.Errorf("diagnostics = %v, want %v", summaries(got.Diagnostics), want)
	}
	if a := got.Diagnostics[1].Attribute; len(a.GetSteps()) != 1 || a.Steps[0].GetAttributeName() != "name" {
		t.Errorf("hook diagnostic attribute = %v, want name", a)
	}
	if !bytes.Equal(got.PlannedState.Msgpack, up.plan.PlannedState.Msgpack) {
		t.Error("planned_state changed")
	}
	reqs := rec.Requests()
	if len(reqs) != 1 || reqs[0].Stage != hook.StagePlan || !reqs[0].Deferred {
		t.Fatalf("requests = %+v, want one deferred plan", reqs)
	}
	r := reqs[0]
	if nameOf(t, r.Config) != "cfg" || nameOf(t, r.Prior) != "prior" || nameOf(t, r.Planned) != "planned" || r.New != nil {
		t.Errorf("inputs = %s/%s/%s, want cfg/prior/planned", nameOf(t, r.Config), nameOf(t, r.Prior), nameOf(t, r.Planned))
	}
	if len(r.RequiresReplace) != 1 || !r.RequiresReplace[0].Equal(tftypes.NewAttributePath().WithAttributeName("name")) {
		t.Errorf("requires_replace = %v, want [name]", r.RequiresReplace)
	}
}

func TestRoutePlanUpstreamErrorSkipsHook(t *testing.T) {
	rec := &hooktest.Recorder{Respond: hooktest.Deny("proxy")}
	client, up, _ := startRoute(t, rec)
	up.plan.Diagnostics = []*tfplugin5.Diagnostic{diag(tfplugin5.Diagnostic_ERROR, "upstream")}
	got, err := client.PlanResourceChange(context.Background(), &tfplugin5.PlanResourceChange_Request{TypeName: "fake_thing", Config: thing(t, "cfg")})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"ERROR:upstream"}; !slices.Equal(summaries(got.Diagnostics), want) || len(rec.Requests()) != 0 {
		t.Errorf("diagnostics = %v, hook calls %d; want upstream only and no hook", summaries(got.Diagnostics), len(rec.Requests()))
	}
}

func TestRouteApply(t *testing.T) {
	rec := &hooktest.Recorder{Respond: func(r *hook.Request) (*hook.Result, error) {
		res, err := warnAt(r.Stage)(r)
		if res != nil && r.Stage == hook.StageApplyPre {
			res.Carry = "pre-carry"
		}
		return res, err
	}}
	client, up, _ := startRoute(t, rec)
	warmSchema(t, client)
	got, err := client.ApplyResourceChange(context.Background(), &tfplugin5.ApplyResourceChange_Request{
		TypeName: "fake_thing", PriorState: thing(t, "prior"), PlannedState: thing(t, "planned"), Config: thing(t, "cfg"), PlannedPrivate: []byte("pp"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"WARNING:upstream", "WARNING:apply_pre", "WARNING:apply_post"}; !slices.Equal(summaries(got.Diagnostics), want) {
		t.Errorf("diagnostics = %v, want %v", summaries(got.Diagnostics), want)
	}
	if !bytes.Equal(got.NewState.Msgpack, up.apply.NewState.Msgpack) || !bytes.Equal(got.Private, up.apply.Private) {
		t.Error("new_state or private changed")
	}
	reqs := rec.Requests()
	if want := []hook.Stage{hook.StageApplyPre, hook.StageApplyPost}; !slices.Equal(rec.Stages(), want) {
		t.Fatalf("stages = %v, want %v", rec.Stages(), want)
	}
	pre, post := reqs[0], reqs[1]
	if nameOf(t, pre.Config) != "cfg" || nameOf(t, pre.Prior) != "prior" || nameOf(t, pre.Planned) != "planned" || pre.New != nil || pre.Envelope != nil {
		t.Errorf("apply_pre inputs wrong: %+v", pre)
	}
	if nameOf(t, post.New) != "new" {
		t.Errorf("apply_post new = %s, want new", nameOf(t, post.New))
	}
	// apply_post gets back exactly what apply_pre returned.
	if pre.Carry != nil || post.Carry != "pre-carry" {
		t.Errorf("carry: apply_pre %v, apply_post %v; want none, then pre-carry", pre.Carry, post.Carry)
	}
}

func TestRouteApplyBlocked(t *testing.T) {
	rec := &hooktest.Recorder{Respond: hooktest.Deny("blocked")}
	client, up, _ := startRoute(t, rec)
	got, err := client.ApplyResourceChange(context.Background(), &tfplugin5.ApplyResourceChange_Request{TypeName: "fake_thing", PriorState: thing(t, ""), PlannedState: thing(t, "planned"), Config: thing(t, "cfg")})
	if err != nil {
		t.Fatal(err)
	}
	if got.NewState != nil || got.Private != nil || !slices.Equal(summaries(got.Diagnostics), []string{"ERROR:blocked"}) {
		t.Errorf("response = %v, want diagnostics only", got)
	}
	if slices.Contains(up.calls, "ApplyResourceChange") {
		t.Error("blocked apply reached upstream")
	}
}

func TestRouteEvaluateError(t *testing.T) {
	rec := &hooktest.Recorder{Respond: func(*hook.Request) (*hook.Result, error) { return nil, errors.New("secret value leaked?") }}
	client, up, _ := startRoute(t, rec)
	ctx := context.Background()

	v, err := client.ValidateResourceTypeConfig(ctx, &tfplugin5.ValidateResourceTypeConfig_Request{TypeName: "fake_thing", Config: thing(t, "cfg")})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"WARNING:upstream", "ERROR:Compliance evaluation failed"}; !slices.Equal(summaries(v.Diagnostics), want) {
		t.Errorf("validate diagnostics = %v, want %v", summaries(v.Diagnostics), want)
	}
	if d := v.Diagnostics[1].Detail; d != "validate for fake_thing: evaluator error" {
		t.Errorf("detail = %q", d)
	}

	a, err := client.ApplyResourceChange(ctx, &tfplugin5.ApplyResourceChange_Request{TypeName: "fake_thing", PriorState: thing(t, "prior"), PlannedState: thing(t, "planned")})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(summaries(a.Diagnostics), []string{"ERROR:Compliance evaluation failed"}) || slices.Contains(up.calls, "ApplyResourceChange") {
		t.Errorf("apply_pre error: diagnostics %v, upstream calls %v; want blocked", summaries(a.Diagnostics), up.calls)
	}

	rec.Respond = func(r *hook.Request) (*hook.Result, error) {
		if r.Stage == hook.StageApplyPost {
			return nil, errors.New("boom")
		}
		return &hook.Result{}, nil
	}
	a, err = client.ApplyResourceChange(ctx, &tfplugin5.ApplyResourceChange_Request{TypeName: "fake_thing", PriorState: thing(t, "prior"), PlannedState: thing(t, "planned")})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"WARNING:upstream", "WARNING:Compliance evaluation failed"}; !slices.Equal(summaries(a.Diagnostics), want) || a.NewState == nil {
		t.Errorf("apply_post error: diagnostics %v, want %v and new_state kept", summaries(a.Diagnostics), want)
	}
}

func TestRouteApplyCancelledByStop(t *testing.T) {
	rec := &hooktest.Recorder{}
	client, up, p := startRoute(t, rec)
	rec.Respond = func(*hook.Request) (*hook.Result, error) {
		p.stopProxy()
		return &hook.Result{}, nil
	}
	got, err := client.ApplyResourceChange(context.Background(), &tfplugin5.ApplyResourceChange_Request{TypeName: "fake_thing", PriorState: thing(t, "prior"), PlannedState: thing(t, "planned")})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(summaries(got.Diagnostics), []string{"ERROR:Compliance evaluation cancelled"}) || //nolint:misspell // fixed diagnostic text
		slices.Contains(up.calls, "ApplyResourceChange") {
		t.Errorf("diagnostics %v, upstream calls %v; want blocked as canceled", summaries(got.Diagnostics), up.calls)
	}
}

// TestApplyPreIgnoresWants: an evaluator that wants nothing still sees every
// apply at apply_pre, and its blocking diagnostic stops the forward.
func TestApplyPreIgnoresWants(t *testing.T) {
	for name, tc := range map[string]struct{ prior, planned string }{
		"create": {"", "planned"},
		"update": {"prior", "planned"},
		"delete": {"prior", ""},
	} {
		t.Run(name, func(t *testing.T) {
			rec := &hooktest.Recorder{Wanted: []string{}, Respond: hooktest.Deny("verdict required")}
			client, up, _ := startRoute(t, rec)
			ctx := context.Background()
			if _, err := client.ValidateResourceTypeConfig(ctx, &tfplugin5.ValidateResourceTypeConfig_Request{TypeName: "fake_thing", Config: thing(t, "cfg")}); err != nil {
				t.Fatal(err)
			}
			if _, err := client.PlanResourceChange(ctx, &tfplugin5.PlanResourceChange_Request{TypeName: "fake_thing", Config: thing(t, "cfg")}); err != nil {
				t.Fatal(err)
			}
			got, err := client.ApplyResourceChange(ctx, &tfplugin5.ApplyResourceChange_Request{TypeName: "fake_thing", PriorState: thing(t, tc.prior), PlannedState: thing(t, tc.planned)})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(rec.Stages(), []hook.Stage{hook.StageApplyPre}) {
				t.Errorf("stages = %v, want apply_pre only", rec.Stages())
			}
			if !slices.Equal(summaries(got.Diagnostics), []string{"ERROR:verdict required"}) || slices.Contains(up.calls, "ApplyResourceChange") {
				t.Errorf("diagnostics %v, upstream calls %v; want the forward stopped", summaries(got.Diagnostics), up.calls)
			}
			if slices.Contains(up.calls, "GetSchema") {
				t.Error("an unwanted type fetched the schema; Value must stay lazy")
			}
		})
	}
}

func TestRouteConfigureHook(t *testing.T) {
	rec := &hooktest.Recorder{OnConfigure: func(*hook.ConfigureRequest) ([]hook.Diagnostic, error) {
		return []hook.Diagnostic{{Severity: hook.SeverityWarning, Summary: "proxy"}}, nil
	}}
	client, up, _ := startRoute(t, rec)
	got, err := client.Configure(context.Background(), &tfplugin5.Configure_Request{TerraformVersion: "1.14.0", Config: combinedConfig(t, "advisory")})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"WARNING:upstream", "WARNING:proxy"}; !slices.Equal(summaries(got.Diagnostics), want) {
		t.Errorf("diagnostics = %v, want %v", summaries(got.Diagnostics), want)
	}
	cr := rec.Configures()
	if len(cr) != 1 || cr[0].TerraformVersion != "1.14.0" {
		t.Fatalf("configure requests = %+v", cr)
	}
	var m map[string]tftypes.Value
	var mode string
	if err := cr[0].Compliance.As(&m); err != nil {
		t.Fatal(err)
	}
	if err := m["enforcement_mode"].As(&mode); err != nil || mode != "advisory" {
		t.Errorf("enforcement_mode = %q (%v), want advisory", mode, err)
	}
	if s, ok := cr[0].Schemas.Resource("fake_thing"); !ok || !s.ValueType().Equal(thingType) {
		t.Errorf("schema source fake_thing = %v, %v", s, ok)
	}
	if !bytes.Equal(up.configure.Config.Msgpack, upstreamConfig(t)) {
		t.Error("upstream config still carries compliance")
	}
}

// TestRouteEvaluatePanic: a panicking evaluator follows the Go error rule
// instead of crashing the provider (at apply_post upstream already applied).
func TestRouteEvaluatePanic(t *testing.T) {
	rec := &hooktest.Recorder{Respond: func(*hook.Request) (*hook.Result, error) { panic("evaluator bug") }}
	client, up, _ := startRoute(t, rec)
	ctx := context.Background()
	applyReq := &tfplugin5.ApplyResourceChange_Request{TypeName: "fake_thing", PriorState: thing(t, "prior"), PlannedState: thing(t, "planned")}

	a, err := client.ApplyResourceChange(ctx, applyReq)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(summaries(a.Diagnostics), []string{"ERROR:Compliance evaluation failed"}) || slices.Contains(up.calls, "ApplyResourceChange") {
		t.Errorf("apply_pre panic: diagnostics %v, upstream calls %v; want blocked", summaries(a.Diagnostics), up.calls)
	}

	p, err := client.PlanResourceChange(ctx, &tfplugin5.PlanResourceChange_Request{TypeName: "fake_thing", PriorState: thing(t, "prior"), Config: thing(t, "cfg")})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(summaries(p.Diagnostics), "ERROR:Compliance evaluation failed") {
		t.Errorf("plan panic: diagnostics %v, want an error", summaries(p.Diagnostics))
	}

	rec.Respond = func(r *hook.Request) (*hook.Result, error) {
		if r.Stage == hook.StageApplyPost {
			panic("evaluator bug")
		}
		return &hook.Result{}, nil
	}
	a, err = client.ApplyResourceChange(ctx, applyReq)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"WARNING:upstream", "WARNING:Compliance evaluation failed"}; !slices.Equal(summaries(a.Diagnostics), want) || a.NewState == nil {
		t.Errorf("apply_post panic: diagnostics %v, want %v and new_state kept", summaries(a.Diagnostics), want)
	}

	rec.OnConfigure = func(*hook.ConfigureRequest) ([]hook.Diagnostic, error) { panic("evaluator bug") }
	c, err := client.Configure(ctx, &tfplugin5.Configure_Request{Config: combinedConfig(t, "advisory")})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(summaries(c.Diagnostics), []string{"ERROR:Compliance evaluation failed"}) {
		t.Errorf("configure panic: diagnostics %v", summaries(c.Diagnostics))
	}
}

// panicWants panics in Wants; Evaluate answers from Recorder.
type panicWants struct{ *hooktest.Recorder }

func (panicWants) Wants(hook.Kind, string) bool { panic("evaluator bug") }

// TestRouteWantsPanic: a panic in Wants counts as wanted, so the hook still
// runs, and never crashes the provider after upstream applied.
func TestRouteWantsPanic(t *testing.T) {
	rec := &hooktest.Recorder{}
	client, up, _ := startRoute(t, panicWants{rec})
	a, err := client.ApplyResourceChange(context.Background(), &tfplugin5.ApplyResourceChange_Request{TypeName: "fake_thing", PriorState: thing(t, "prior"), PlannedState: thing(t, "planned")})
	if err != nil {
		t.Fatal(err)
	}
	if a.NewState == nil || !slices.Contains(up.calls, "ApplyResourceChange") {
		t.Errorf("new_state %v, upstream calls %v; want applied", a.NewState, up.calls)
	}
	if !slices.Equal(rec.Stages(), []hook.Stage{hook.StageApplyPre, hook.StageApplyPost}) {
		t.Errorf("stages = %v, want apply_pre and apply_post", rec.Stages())
	}

	p, err := client.PlanResourceChange(context.Background(), &tfplugin5.PlanResourceChange_Request{TypeName: "fake_thing", PriorState: thing(t, "prior"), Config: thing(t, "cfg")})
	if err != nil {
		t.Fatal(err)
	}
	if h, _, err := Unwrap(p.PlannedPrivate); err != nil || h == nil || !slices.Contains(rec.Stages(), hook.StagePlan) {
		t.Errorf("plan with Wants panic: envelope %+v (%v), stages %v; want hook run and envelope written", h, err, rec.Stages())
	}
}

// TestRouteWantsPanicDiagnoses: a Wants panic is never lost when Evaluate
// then succeeds. It adds "Compliance evaluation failed" at the stage
// severity, so ephemeral open does not reach upstream.
func TestRouteWantsPanicDiagnoses(t *testing.T) {
	const failed = "Compliance evaluation failed"
	ctx := context.Background()
	rc, _, _ := startRoute(t, panicWants{&hooktest.Recorder{}})
	v, err := rc.ValidateResourceTypeConfig(ctx, &tfplugin5.ValidateResourceTypeConfig_Request{TypeName: "fake_thing", Config: thing(t, "cfg")})
	if err != nil {
		t.Fatal(err)
	}
	p, err := rc.PlanResourceChange(ctx, &tfplugin5.PlanResourceChange_Request{TypeName: "fake_thing", PriorState: thing(t, "prior"), Config: thing(t, "cfg")})
	if err != nil {
		t.Fatal(err)
	}
	a, err := rc.ApplyResourceChange(ctx, &tfplugin5.ApplyResourceChange_Request{TypeName: "fake_thing", PriorState: thing(t, "prior"), PlannedState: thing(t, "planned")})
	if err != nil {
		t.Fatal(err)
	}
	dc, up := startRead(t, panicWants{&hooktest.Recorder{}})
	r, err := dc.ReadResource(ctx, &tfplugin5.ReadResource_Request{TypeName: "fake_thing", CurrentState: thing(t, "prior")})
	if err != nil {
		t.Fatal(err)
	}
	d, err := dc.ReadDataSource(ctx, &tfplugin5.ReadDataSource_Request{TypeName: "fake_data", Config: thing(t, "cfg")})
	if err != nil {
		t.Fatal(err)
	}
	im, err := dc.ImportResourceState(ctx, &tfplugin5.ImportResourceState_Request{TypeName: "fake_thing", Id: "i-1"})
	if err != nil {
		t.Fatal(err)
	}
	o, err := dc.OpenEphemeralResource(ctx, &tfplugin5.OpenEphemeralResource_Request{TypeName: "fake_secret", Config: thing(t, "cfg")})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		rpc   string
		diags []*tfplugin5.Diagnostic
		want  []string
	}{
		{"validate", v.Diagnostics, []string{"WARNING:upstream", "ERROR:" + failed}},
		{"plan", p.Diagnostics, []string{"WARNING:upstream", "ERROR:" + failed}},
		{"apply", a.Diagnostics, []string{"WARNING:upstream", "WARNING:" + failed}},
		{"read", r.Diagnostics, []string{"WARNING:upstream", "WARNING:" + failed}},
		{"data", d.Diagnostics, []string{"WARNING:upstream", "WARNING:" + failed}},
		{"import", im.Diagnostics, []string{"WARNING:upstream", "WARNING:" + failed, "WARNING:" + failed}},
		{"open", o.Diagnostics, []string{"ERROR:" + failed}},
	} {
		if !slices.Equal(summaries(c.diags), c.want) {
			t.Errorf("%s: diagnostics = %v, want %v", c.rpc, summaries(c.diags), c.want)
		}
	}
	if slices.Contains(up.calls, "OpenEphemeralResource") {
		t.Error("ephemeral open forwarded after a Wants panic")
	}
}

// TestRouteConfigureSchemaFollowsRequestContext: a schema lookup the
// evaluator makes during Configure ends with the Configure RPC.
func TestRouteConfigureSchemaFollowsRequestContext(t *testing.T) {
	_, up, _ := startRoute(t, &hooktest.Recorder{})
	done := make(chan bool, 1)
	rec := &hooktest.Recorder{OnConfigure: func(r *hook.ConfigureRequest) ([]hook.Diagnostic, error) {
		_, ok1 := r.Schemas.Resource("fake_thing")
		_, ok2 := r.Schemas.Resource("fake_thing") // after the deadline, Configure still running
		done <- ok1 || ok2
		return nil, nil
	}}
	client, p := startProxy(t, hangSchema{up}, Backends{Evaluator: rec})
	t.Cleanup(p.stopProxy)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, _ = client.Configure(ctx, &tfplugin5.Configure_Request{Config: combinedConfig(t, "advisory")})
	select {
	case ok := <-done:
		if ok {
			t.Error("schema found without a GetSchema answer")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("schema lookup during Configure still blocked after the RPC context ended")
	}
}

// hangSchema never answers GetSchema until the caller gives up.
type hangSchema struct{ *resUpstream }

func (h hangSchema) GetSchema(ctx context.Context, _ *tfplugin5.GetProviderSchema_Request) (*tfplugin5.GetProviderSchema_Response, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestRouteValueTypeFollowsRequestContext: resolving a value type fetches the
// upstream schema under the RPC context, so a hung upstream GetSchema cannot
// hold the hook past Terraform's cancellation.
func TestRouteValueTypeFollowsRequestContext(t *testing.T) {
	_, up, _ := startRoute(t, &hooktest.Recorder{})
	got := make(chan error, 1)
	rec := &hooktest.Recorder{Respond: func(r *hook.Request) (*hook.Result, error) {
		_, err := r.Planned.Get()
		got <- err
		return nil, err
	}}
	client, p := startProxy(t, hangSchema{up}, Backends{Evaluator: rec})
	t.Cleanup(p.stopProxy)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, _ = client.ApplyResourceChange(ctx, &tfplugin5.ApplyResourceChange_Request{TypeName: "fake_thing", PlannedState: thing(t, "planned")})
	select {
	case err := <-got:
		if err == nil {
			t.Error("Get succeeded without a schema")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("value type resolution still blocked after the RPC context ended")
	}
}

// readUpstream answers the read-side RPCs with canned responses and keeps
// the open request it received.
type readUpstream struct {
	*fakeUpstream5
	read    *tfplugin5.ReadResource_Response
	data    *tfplugin5.ReadDataSource_Response
	open    *tfplugin5.OpenEphemeralResource_Response
	imp     *tfplugin5.ImportResourceState_Response
	openReq *tfplugin5.OpenEphemeralResource_Request
}

func (u *readUpstream) ReadResource(context.Context, *tfplugin5.ReadResource_Request) (*tfplugin5.ReadResource_Response, error) {
	u.record("ReadResource")
	return u.read, nil
}

func (u *readUpstream) ReadDataSource(context.Context, *tfplugin5.ReadDataSource_Request) (*tfplugin5.ReadDataSource_Response, error) {
	u.record("ReadDataSource")
	return u.data, nil
}

func (u *readUpstream) OpenEphemeralResource(_ context.Context, req *tfplugin5.OpenEphemeralResource_Request) (*tfplugin5.OpenEphemeralResource_Response, error) {
	u.record("OpenEphemeralResource")
	u.openReq = req
	return u.open, nil
}

func (u *readUpstream) ImportResourceState(context.Context, *tfplugin5.ImportResourceState_Request) (*tfplugin5.ImportResourceState_Response, error) {
	u.record("ImportResourceState")
	return u.imp, nil
}

var (
	upstreamWarn = []*tfplugin5.Diagnostic{diag(tfplugin5.Diagnostic_WARNING, "upstream")}
	identity     = &tfplugin5.ResourceIdentityData{IdentityData: &tfplugin5.DynamicValue{Json: []byte(`{"id":"i-1"}`)}}
	notMsgpack   = &tfplugin5.DynamicValue{Msgpack: []byte{0xc1}} // 0xc1 is never valid msgpack
)

// startRead serves fake_thing and fake_other as resources, fake_data as a
// data source and fake_secret as an ephemeral resource, all with the
// fake_thing block, so a lookup in the wrong schema table fails. The schema
// is warm, so recorded values decode after their RPC.
func startRead(t *testing.T, ev hook.Evaluator) (tfplugin5.ProviderClient, *readUpstream) {
	t.Helper()
	sch := thingSchema()
	blk := sch.ResourceSchemas["fake_thing"]
	sch.ResourceSchemas["fake_other"] = blk
	sch.DataSourceSchemas = map[string]*tfplugin5.Schema{"fake_data": blk}
	sch.EphemeralResourceSchemas = map[string]*tfplugin5.Schema{"fake_secret": blk}
	up := &readUpstream{
		fakeUpstream5: &fakeUpstream5{schema: sch},
		read:          &tfplugin5.ReadResource_Response{NewState: thing(t, "refreshed"), Private: []byte("p"), NewIdentity: identity, Diagnostics: upstreamWarn},
		data:          &tfplugin5.ReadDataSource_Response{State: thing(t, "result"), Diagnostics: upstreamWarn},
		open:          &tfplugin5.OpenEphemeralResource_Response{Result: notMsgpack, Private: []byte("p"), Diagnostics: upstreamWarn},
		imp: &tfplugin5.ImportResourceState_Response{Diagnostics: upstreamWarn, ImportedResources: []*tfplugin5.ImportResourceState_ImportedResource{
			{TypeName: "fake_thing", State: thing(t, "one"), Private: []byte("p1"), Identity: identity},
			{TypeName: "fake_other", State: thing(t, "two"), Private: []byte("p2")},
		}},
	}
	client, _ := startProxy(t, up, Backends{Evaluator: ev})
	warmSchema(t, client)
	return client, up
}

func TestRouteRead(t *testing.T) {
	rec := &hooktest.Recorder{Respond: warnAt(hook.StageRead)}
	client, up := startRead(t, rec)
	got, err := client.ReadResource(context.Background(), &tfplugin5.ReadResource_Request{TypeName: "fake_thing", CurrentState: thing(t, "prior")})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"WARNING:upstream", "WARNING:read"}; !slices.Equal(summaries(got.Diagnostics), want) {
		t.Errorf("diagnostics = %v, want %v", summaries(got.Diagnostics), want)
	}
	if !bytes.Equal(got.NewState.Msgpack, up.read.NewState.Msgpack) || string(got.Private) != "p" || string(got.NewIdentity.GetIdentityData().GetJson()) != `{"id":"i-1"}` {
		t.Errorf("response = %v, want new_state, private and new_identity untouched", got)
	}
	reqs := rec.Requests()
	if len(reqs) != 1 || reqs[0].Stage != hook.StageRead || reqs[0].Kind != hook.KindResource || reqs[0].TypeName != "fake_thing" {
		t.Fatalf("requests = %+v, want one read for fake_thing", reqs)
	}
	if p, n := nameOf(t, reqs[0].Prior), nameOf(t, reqs[0].New); p != "prior" || n != "refreshed" || reqs[0].Config != nil || reqs[0].Planned != nil {
		t.Errorf("prior, new = %s, %s, want prior, refreshed and no config or planned", p, n)
	}
}

func TestRouteReadUpstreamErrorSkipsHook(t *testing.T) {
	rec := &hooktest.Recorder{}
	client, up := startRead(t, rec)
	up.read = &tfplugin5.ReadResource_Response{Diagnostics: []*tfplugin5.Diagnostic{diag(tfplugin5.Diagnostic_ERROR, "upstream")}}
	got, err := client.ReadResource(context.Background(), &tfplugin5.ReadResource_Request{TypeName: "fake_thing", CurrentState: thing(t, "prior")})
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Requests()) != 0 || len(got.Diagnostics) != 1 {
		t.Errorf("hook requests = %d, diagnostics = %v, want no hook call and the upstream error only", len(rec.Requests()), summaries(got.Diagnostics))
	}
}

func TestRouteReadDataSource(t *testing.T) {
	rec := &hooktest.Recorder{Respond: warnAt(hook.StageDataSource)}
	client, up := startRead(t, rec)
	got, err := client.ReadDataSource(context.Background(), &tfplugin5.ReadDataSource_Request{TypeName: "fake_data", Config: thing(t, "cfg")})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"WARNING:upstream", "WARNING:data_source"}; !slices.Equal(summaries(got.Diagnostics), want) {
		t.Errorf("diagnostics = %v, want %v", summaries(got.Diagnostics), want)
	}
	if !bytes.Equal(got.State.Msgpack, up.data.State.Msgpack) {
		t.Error("state changed")
	}
	reqs := rec.Requests()
	if len(reqs) != 1 || reqs[0].Stage != hook.StageDataSource || reqs[0].Kind != hook.KindDataSource || reqs[0].TypeName != "fake_data" {
		t.Fatalf("requests = %+v, want one data_source for fake_data", reqs)
	}
	if c, n := nameOf(t, reqs[0].Config), nameOf(t, reqs[0].New); c != "cfg" || n != "result" || reqs[0].Prior != nil {
		t.Errorf("config, new = %s, %s, want cfg, result and no prior", c, n)
	}
}

func TestRouteImport(t *testing.T) {
	rec := &hooktest.Recorder{Respond: warnAt(hook.StageImport)}
	client, _ := startRead(t, rec)
	got, err := client.ImportResourceState(context.Background(), &tfplugin5.ImportResourceState_Request{TypeName: "fake_thing", Id: "i-1"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"WARNING:upstream", "WARNING:import", "WARNING:import"}; !slices.Equal(summaries(got.Diagnostics), want) {
		t.Errorf("diagnostics = %v, want %v", summaries(got.Diagnostics), want)
	}
	if len(got.ImportedResources) != 2 || string(got.ImportedResources[0].Private) != "p1" || got.ImportedResources[0].Identity == nil {
		t.Errorf("imported = %v, want both objects with private and identity untouched", got.ImportedResources)
	}
	var seen []string
	for _, r := range rec.Requests() {
		if r.Stage != hook.StageImport || r.Kind != hook.KindResource || r.Op != hook.OpImport {
			t.Errorf("request = %+v, want import of a resource with Op import", r)
		}
		seen = append(seen, r.TypeName+"="+nameOf(t, r.New))
	}
	if want := []string{"fake_thing=one", "fake_other=two"}; !slices.Equal(seen, want) {
		t.Errorf("hooked objects = %v, want %v", seen, want)
	}
}

func TestRouteImportWantsPerObject(t *testing.T) {
	rec := &hooktest.Recorder{Wanted: []string{"fake_other"}}
	client, _ := startRead(t, rec)
	if _, err := client.ImportResourceState(context.Background(), &tfplugin5.ImportResourceState_Request{TypeName: "fake_thing", Id: "i-1"}); err != nil {
		t.Fatal(err)
	}
	if reqs := rec.Requests(); len(reqs) != 1 || reqs[0].TypeName != "fake_other" {
		t.Errorf("requests = %+v, want only the wanted imported type", reqs)
	}
}

func TestRouteEphemeralOpen(t *testing.T) {
	rec := &hooktest.Recorder{Respond: warnAt(hook.StageEphemeralOpen)}
	client, up := startRead(t, rec)
	cfg := thing(t, "cfg")
	got, err := client.OpenEphemeralResource(context.Background(), &tfplugin5.OpenEphemeralResource_Request{TypeName: "fake_secret", Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"WARNING:upstream", "WARNING:ephemeral_open"}; !slices.Equal(summaries(got.Diagnostics), want) {
		t.Errorf("diagnostics = %v, want %v", summaries(got.Diagnostics), want)
	}
	if up.openReq == nil || !bytes.Equal(up.openReq.Config.GetMsgpack(), cfg.Msgpack) {
		t.Error("config not forwarded as sent")
	}
	reqs := rec.Requests()
	if len(reqs) != 1 || reqs[0].Stage != hook.StageEphemeralOpen || reqs[0].Kind != hook.KindEphemeral || reqs[0].TypeName != "fake_secret" || nameOf(t, reqs[0].Config) != "cfg" {
		t.Fatalf("requests = %+v, want one ephemeral_open for fake_secret with its config", reqs)
	}
}

func TestRouteEphemeralOpenBlocks(t *testing.T) {
	for name, respond := range map[string]func(*hook.Request) (*hook.Result, error){
		"deny":  hooktest.Deny("proxy"),
		"error": func(*hook.Request) (*hook.Result, error) { return nil, errors.New("boom") },
	} {
		t.Run(name, func(t *testing.T) {
			client, up := startRead(t, &hooktest.Recorder{Respond: respond})
			got, err := client.OpenEphemeralResource(context.Background(), &tfplugin5.OpenEphemeralResource_Request{TypeName: "fake_secret", Config: thing(t, "cfg")})
			if err != nil {
				t.Fatal(err)
			}
			if slices.Contains(up.calls, "OpenEphemeralResource") {
				t.Error("open forwarded despite an error diagnostic")
			}
			if len(got.Diagnostics) != 1 || got.Diagnostics[0].Severity != tfplugin5.Diagnostic_ERROR || got.Result != nil || got.Private != nil {
				t.Errorf("response = %v, want one error diagnostic only", got)
			}
		})
	}
}

// TestEphemeralResultNeverDecoded: the hook sees only the request config, and
// result and private pass through as bytes (0xc1 fails any decode).
func TestEphemeralResultNeverDecoded(t *testing.T) {
	rec := &hooktest.Recorder{}
	client, up := startRead(t, rec)
	got, err := client.OpenEphemeralResource(context.Background(), &tfplugin5.OpenEphemeralResource_Request{TypeName: "fake_secret", Config: thing(t, "cfg")})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Result.GetMsgpack(), notMsgpack.Msgpack) || string(got.Private) != "p" || !slices.Equal(summaries(got.Diagnostics), summaries(up.open.Diagnostics)) {
		t.Errorf("response = %v, want result and private as upstream sent them and no proxy diagnostics", got)
	}
	reqs := rec.Requests()
	if len(reqs) != 1 || reqs[0].Config == nil || reqs[0].New != nil || reqs[0].Prior != nil || reqs[0].Planned != nil {
		t.Errorf("requests = %+v, want one with Config only", reqs)
	}
}

func TestRouteEvalErrorIsWarningAfterForward(t *testing.T) {
	rec := &hooktest.Recorder{Respond: func(*hook.Request) (*hook.Result, error) { return nil, errors.New("boom") }}
	client, _ := startRead(t, rec)
	ctx := context.Background()
	read, err1 := client.ReadResource(ctx, &tfplugin5.ReadResource_Request{TypeName: "fake_thing", CurrentState: thing(t, "prior")})
	data, err2 := client.ReadDataSource(ctx, &tfplugin5.ReadDataSource_Request{TypeName: "fake_data", Config: thing(t, "cfg")})
	imp, err3 := client.ImportResourceState(ctx, &tfplugin5.ImportResourceState_Request{TypeName: "fake_thing", Id: "i-1"})
	if err := errors.Join(err1, err2, err3); err != nil {
		t.Fatal(err)
	}
	for name, d := range map[string][]*tfplugin5.Diagnostic{"read": read.Diagnostics, "data_source": data.Diagnostics, "import": imp.Diagnostics} {
		if len(d) < 2 || summaries(d)[1] != "WARNING:Compliance evaluation failed" {
			t.Errorf("%s diagnostics = %v, want the upstream warning then an evaluation warning", name, summaries(d))
		}
	}
}

func TestRouteReadSideSkipsUnwanted(t *testing.T) {
	rec := &hooktest.Recorder{Wanted: []string{}}
	client, up := startRead(t, rec)
	ctx := context.Background()
	_, err1 := client.ReadResource(ctx, &tfplugin5.ReadResource_Request{TypeName: "fake_thing", CurrentState: thing(t, "prior")})
	_, err2 := client.ReadDataSource(ctx, &tfplugin5.ReadDataSource_Request{TypeName: "fake_data", Config: thing(t, "cfg")})
	_, err3 := client.OpenEphemeralResource(ctx, &tfplugin5.OpenEphemeralResource_Request{TypeName: "fake_secret", Config: thing(t, "cfg")})
	_, err4 := client.ImportResourceState(ctx, &tfplugin5.ImportResourceState_Request{TypeName: "fake_thing", Id: "i-1"})
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		t.Fatal(err)
	}
	if n := len(rec.Requests()); n != 0 || len(up.calls) < 4 {
		t.Errorf("hook calls = %d, upstream calls = %v, want none and all four forwarded", n, up.calls)
	}
}

// TestRouteReadEvaluatePanic: on the read-side routes a panicking evaluator
// follows the Go error rule too: a warning after upstream acted, an error
// (upstream not called) at ephemeral open.
func TestRouteReadEvaluatePanic(t *testing.T) {
	rec := &hooktest.Recorder{Respond: func(*hook.Request) (*hook.Result, error) { panic("evaluator bug") }}
	client, up := startRead(t, rec)
	ctx := context.Background()
	failed := []string{"WARNING:upstream", "WARNING:Compliance evaluation failed"}

	r, err := client.ReadResource(ctx, &tfplugin5.ReadResource_Request{TypeName: "fake_thing", CurrentState: thing(t, "prior")})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(summaries(r.Diagnostics), failed) || r.NewState == nil {
		t.Errorf("read panic: diagnostics %v, want %v and new_state kept", summaries(r.Diagnostics), failed)
	}
	d, err := client.ReadDataSource(ctx, &tfplugin5.ReadDataSource_Request{TypeName: "fake_data", Config: thing(t, "cfg")})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(summaries(d.Diagnostics), failed) {
		t.Errorf("data source panic: diagnostics %v, want %v", summaries(d.Diagnostics), failed)
	}
	o, err := client.OpenEphemeralResource(ctx, &tfplugin5.OpenEphemeralResource_Request{TypeName: "fake_secret", Config: thing(t, "cfg")})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(summaries(o.Diagnostics), []string{"ERROR:Compliance evaluation failed"}) || slices.Contains(up.calls, "OpenEphemeralResource") {
		t.Errorf("ephemeral open panic: diagnostics %v, upstream calls %v; want blocked", summaries(o.Diagnostics), up.calls)
	}
}
