//go:build ctftest

package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/lifecycle"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
	"github.com/compliancetf/terraform-provider-aws/test/scrub/scrubtest"
)

// scrubUpstream answers the resource RPCs as hashicorp/aws would for the
// fields it has and records each call.
type scrubUpstream struct{ *fakeUpstream5 }

func (u *scrubUpstream) ValidateResourceTypeConfig(context.Context, *tfplugin5.ValidateResourceTypeConfig_Request) (*tfplugin5.ValidateResourceTypeConfig_Response, error) {
	u.record("ValidateResourceTypeConfig")
	return &tfplugin5.ValidateResourceTypeConfig_Response{}, nil
}

func (u *scrubUpstream) PlanResourceChange(_ context.Context, req *tfplugin5.PlanResourceChange_Request) (*tfplugin5.PlanResourceChange_Response, error) {
	u.record("PlanResourceChange")
	return &tfplugin5.PlanResourceChange_Response{PlannedState: req.ProposedNewState}, nil
}

func (u *scrubUpstream) ApplyResourceChange(_ context.Context, req *tfplugin5.ApplyResourceChange_Request) (*tfplugin5.ApplyResourceChange_Response, error) {
	u.record("ApplyResourceChange")
	return &tfplugin5.ApplyResourceChange_Response{NewState: req.Config}, nil
}

func (u *scrubUpstream) ReadResource(_ context.Context, req *tfplugin5.ReadResource_Request) (*tfplugin5.ReadResource_Response, error) {
	u.record("ReadResource")
	return &tfplugin5.ReadResource_Response{NewState: req.CurrentState}, nil
}

func (u *scrubUpstream) called(name string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	n := 0
	for _, c := range u.calls {
		if c == name {
			n++
		}
	}
	return n
}

// panicHook is the lifecycle hook, except that Evaluate panics with a
// marker while armed.
type panicHook struct {
	lifecycle.Hook
	armed atomic.Bool
}

func (h *panicHook) Evaluate(ctx context.Context, req *hook.Request) (*hook.Result, error) {
	if h.armed.Load() {
		panic("evaluate: " + scrubtest.Marker(70))
	}
	return h.Hook.Evaluate(ctx, req)
}

var scrubEBSType = tftypes.Object{AttributeTypes: map[string]tftypes.Type{
	"id": tftypes.String, "encrypted": tftypes.Bool, "kms_key_id": tftypes.String, "tags": tftypes.Map{ElementType: tftypes.String},
}}

// scrubEBS is a marked aws_ebs_volume: the sensitive kms_key_id and a tags
// map with marker keys and values carry markers; id is recorded by design
// and carries none.
func scrubEBS(t *testing.T, encrypted, id any, n int) *tfplugin5.DynamicValue {
	t.Helper()
	dv, err := tfprotov5.NewDynamicValue(scrubEBSType, tftypes.NewValue(scrubEBSType, map[string]tftypes.Value{
		"id":         tftypes.NewValue(tftypes.String, id),
		"encrypted":  tftypes.NewValue(tftypes.Bool, encrypted),
		"kms_key_id": tftypes.NewValue(tftypes.String, scrubtest.Marker(n)),
		"tags": tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, map[string]tftypes.Value{
			scrubtest.Marker(n + 1): tftypes.NewValue(tftypes.String, scrubtest.Marker(n+2)),
		}),
	}))
	if err != nil {
		t.Fatal(err)
	}
	return &tfplugin5.DynamicValue{Msgpack: dv.MsgPack}
}

// markedConfig is combinedConfig with a marker as the provider region.
func markedConfig(t *testing.T) *tfplugin5.DynamicValue {
	t.Helper()
	compType := ComplianceBlockType().(tftypes.Object)
	comp := map[string]tftypes.Value{}
	for name, typ := range compType.AttributeTypes {
		comp[name] = tftypes.NewValue(typ, nil)
	}
	comp["enforcement_mode"] = tftypes.NewValue(tftypes.String, "hard_fail")
	typ := CombinedProviderType(upstreamProviderSchema)
	dv, err := tfprotov5.NewDynamicValue(typ, tftypes.NewValue(typ, map[string]tftypes.Value{
		"region":     tftypes.NewValue(tftypes.String, scrubtest.Marker(60)),
		"compliance": tftypes.NewValue(compType, comp),
	}))
	if err != nil {
		t.Fatal(err)
	}
	return &tfplugin5.DynamicValue{Msgpack: dv.MsgPack}
}

// TestScrubProxy: marked config, plan, apply and refresh values
// sent through the proxy RPCs that reach the lifecycle (embedded CIS
// bundle, hard_fail, free tier) give proto diagnostics, errors, hclog, std
// log and stderr output without a marker. Each RPC must reach upstream and
// give its expected diagnostic; an invalid envelope takes the hclog
// blockApply path; an evaluator panic with a marker takes the recover path.
// Upstream errors and the upstream stderr relay carry upstream text and are
// passed through unchanged by design.
func TestScrubProxy(t *testing.T) {
	logs := scrubtest.CaptureLogs(t)
	dir := t.TempDir()
	for _, k := range []string{"COMPLIANCETF_ENFORCEMENT_MODE", "COMPLIANCETF_ORG_ID", "COMPLIANCETF_GOVERNED", "COMPLIANCETF_TOKEN",
		"COMPLIANCETF_PROFILE_PATH", "COMPLIANCETF_FLOOR_PATH", "COMPLIANCETF_ENVIRONMENT", "COMPLIANCETF_BUNDLE_PATH",
		"COMPLIANCETF_EXCEPTIONS_FILE", "COMPLIANCETF_EXCEPTION_GRANTS", "COMPLIANCETF_MIN_BUNDLE_VERSION",
		"COMPLIANCETF_MIN_PROFILE_VERSION", "COMPLIANCETF_BREAK_GLASS"} {
		t.Setenv(k, "")
	}
	os.Unsetenv("COMPLIANCETF_BREAK_GLASS") //nolint:errcheck,usetesting // set, even empty, fails Configure; t.Setenv above restores it
	t.Setenv("COMPLIANCETF_OFFLINE", "true")
	t.Setenv("COMPLIANCETF_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("COMPLIANCETF_CACHE_DIR", filepath.Join(dir, "cache"))
	t.Setenv("COMPLIANCETF_EVIDENCE_DIR", filepath.Join(dir, "evidence"))

	schema := &tfplugin5.GetProviderSchema_Response{
		Provider: &tfplugin5.Schema{Block: &tfplugin5.Schema_Block{Attributes: []*tfplugin5.Schema_Attribute{{Name: "region", Type: []byte(`"string"`), Optional: true}}}},
		ResourceSchemas: map[string]*tfplugin5.Schema{"aws_ebs_volume": {Block: &tfplugin5.Schema_Block{Attributes: []*tfplugin5.Schema_Attribute{
			{Name: "id", Type: []byte(`"string"`), Computed: true},
			{Name: "encrypted", Type: []byte(`"bool"`), Optional: true},
			{Name: "kms_key_id", Type: []byte(`"string"`), Optional: true, Sensitive: true},
			{Name: "tags", Type: []byte(`["map","string"]`), Optional: true},
		}}}},
	}
	l := lifecycle.New(lifecycle.Options{ProviderVersion: "6.40.0"})
	t.Cleanup(func() { _ = l.Close() })
	up := &scrubUpstream{&fakeUpstream5{schema: schema}}
	ev := &panicHook{Hook: lifecycle.Hook{Lifecycle: l}}
	client, _ := startProxy(t, up, Backends{Evaluator: ev})
	ctx := context.Background()
	warmSchema(t, client)

	var all []*tfplugin5.Diagnostic
	scan := func(rpc string, diags []*tfplugin5.Diagnostic) []string {
		t.Helper()
		all = append(all, diags...)
		scrubtest.NoMarker(t, rpc+" diagnostics", fmt.Sprintf("%v", diags))
		var out []string
		for _, d := range diags {
			out = append(out, d.Severity.String()+" "+d.Summary+": "+d.Detail)
		}
		return out
	}
	has := func(rpc string, got []string, want string) {
		t.Helper()
		if !slices.ContainsFunc(got, func(s string) bool { return strings.Contains(s, want) }) {
			t.Errorf("%s: no %q diagnostic in %q", rpc, want, scrubtest.Mask(strings.Join(got, "; ")))
		}
	}
	const ctl = "[ebs_attached_volume_encryption_enabled]"

	cr, err := client.Configure(ctx, &tfplugin5.Configure_Request{TerraformVersion: "1.14.0", Config: markedConfig(t)})
	scrubtest.Must(t, "Configure error", err)
	scan("Configure", cr.Diagnostics)
	if l.Configured() == nil || up.called("Configure") != 1 {
		t.Fatalf("Configure: lifecycle configured %v, upstream calls %d", l.Configured() != nil, up.called("Configure"))
	}

	vr, err := client.ValidateResourceTypeConfig(ctx, &tfplugin5.ValidateResourceTypeConfig_Request{TypeName: "aws_ebs_volume", Config: scrubEBS(t, false, nil, 1)})
	scrubtest.Must(t, "ValidateResourceTypeConfig error", err)
	scan("ValidateResourceTypeConfig", vr.Diagnostics)
	if up.called("ValidateResourceTypeConfig") != 1 {
		t.Error("ValidateResourceTypeConfig did not reach upstream")
	}

	plan := func(encrypted any, n int) *tfplugin5.PlanResourceChange_Response {
		t.Helper()
		resp, err := client.PlanResourceChange(ctx, &tfplugin5.PlanResourceChange_Request{TypeName: "aws_ebs_volume",
			PriorState: &tfplugin5.DynamicValue{Msgpack: []byte{0xc0}}, // null: create
			Config:     scrubEBS(t, encrypted, nil, n), ProposedNewState: scrubEBS(t, encrypted, tftypes.UnknownValue, n)})
		scrubtest.Must(t, "PlanResourceChange error", err)
		return resp
	}
	has("plan non-compliant", scan("plan", plan(false, 4).Diagnostics), "ERROR "+ctl)
	has("plan unknown", scan("plan", plan(tftypes.UnknownValue, 7).Diagnostics), ctl)
	good := plan(true, 10)
	if d := scan("plan", good.Diagnostics); slices.ContainsFunc(d, func(s string) bool { return strings.HasPrefix(s, "ERROR") }) {
		t.Errorf("compliant plan: %q", scrubtest.Mask(strings.Join(d, "; ")))
	}
	if up.called("PlanResourceChange") != 3 {
		t.Errorf("upstream PlanResourceChange calls %d, want 3", up.called("PlanResourceChange"))
	}

	apply := func(planned *tfplugin5.DynamicValue, private []byte, n int) []string {
		t.Helper()
		resp, err := client.ApplyResourceChange(ctx, &tfplugin5.ApplyResourceChange_Request{TypeName: "aws_ebs_volume",
			PriorState: &tfplugin5.DynamicValue{Msgpack: []byte{0xc0}}, PlannedState: planned,
			Config: scrubEBS(t, true, "vol-scrub", n), PlannedPrivate: private})
		scrubtest.Must(t, "ApplyResourceChange error", err)
		return scan("apply", resp.Diagnostics)
	}
	if d := apply(good.PlannedState, good.PlannedPrivate, 10); slices.ContainsFunc(d, func(s string) bool { return strings.HasPrefix(s, "ERROR") }) {
		t.Errorf("compliant apply: %q", scrubtest.Mask(strings.Join(d, "; ")))
	}
	if up.called("ApplyResourceChange") != 1 {
		t.Errorf("upstream ApplyResourceChange calls %d, want 1", up.called("ApplyResourceChange"))
	}
	// A framed header whose op is a marker: Unwrap rejects it by name only.
	hdr := `{"v":1,"ctf":{"op":"` + scrubtest.Marker(13) + `"}}`
	bad := binary.BigEndian.AppendUint32(append(slices.Clone(envelopeMagic), envelopeVersion), uint32(len(hdr)))
	has("apply invalid envelope", apply(good.PlannedState, append(bad, hdr...), 10), "ERROR Invalid compliance plan envelope")
	// A readable envelope whose prior identity is a marker, on a create RPC:
	// the envelope disagrees with the (null) prior state.
	var dh hook.EnvelopeHeader
	dh.V, dh.CTF.Op, dh.CTF.PriorIdentityKind = 1, hook.OpUpdate, "identity"
	dh.CTF.PriorIdentity = []byte(`{"id":"` + scrubtest.Marker(15) + `"}`)
	_, tail, err := Unwrap(good.PlannedPrivate)
	scrubtest.Must(t, "Unwrap", err)
	disagrees, err := Wrap(dh, tail)
	scrubtest.Must(t, "Wrap", err)
	has("apply envelope disagrees", apply(good.PlannedState, disagrees, 10), "ERROR Envelope disagrees with prior state")
	if up.called("ApplyResourceChange") != 1 {
		t.Error("an apply with an invalid or disagreeing envelope reached upstream")
	}

	rr, err := client.ReadResource(ctx, &tfplugin5.ReadResource_Request{TypeName: "aws_ebs_volume", CurrentState: scrubEBS(t, false, "vol-scrub", 14)})
	scrubtest.Must(t, "ReadResource error", err)
	scan("ReadResource", rr.Diagnostics)
	if up.called("ReadResource") != 1 {
		t.Error("ReadResource did not reach upstream")
	}

	ev.armed.Store(true)
	has("evaluator panic", scan("plan", plan(false, 17).Diagnostics), "Compliance evaluation failed")
	ev.armed.Store(false)

	out := logs()
	scrubtest.NoMarker(t, "log", out)
	for _, want := range []string{"apply blocked by the proxy", "compliance evaluator panicked (string)"} {
		if !strings.Contains(out, want) {
			t.Errorf("log has no %q line", want)
		}
	}
	if len(all) == 0 {
		t.Fatal("no diagnostics scanned")
	}
	// Each stage ran: the evidence chain has its record (read is refresh). Every
	// evidence, state and cache file is scanned.
	if err := l.Close(); err != nil {
		scrubtest.Must(t, "Close", err)
	}
	var chain strings.Builder
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !d.Type().IsRegular() {
			t.Errorf("%s is a %s, want a regular file", p, d.Type())
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		scrubtest.NoMarker(t, p, string(raw))
		chain.Write(raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"plan", "apply_pre", "apply_post", "refresh"} {
		if !strings.Contains(chain.String(), `"stage":"`+stage+`"`) {
			t.Errorf("no %s eval record", stage)
		}
	}
	// One apply_pre record per apply: the compliant one and one per proxy
	// block, whose result is the block token.
	if n := strings.Count(chain.String(), `"stage":"apply_pre"`); n != 3 {
		t.Errorf("%d apply_pre records, want 3", n)
	}
	for _, c := range []string{hook.BlockEnvelopeInvalid, hook.BlockEnvelopeDisagrees} {
		if n := strings.Count(chain.String(), `"control":"`+c+`","decision":"blocked"`); n != 1 {
			t.Errorf("%d %s block records, want 1", n, c)
		}
	}
}
