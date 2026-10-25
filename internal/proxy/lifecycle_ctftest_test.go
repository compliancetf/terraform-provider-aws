//go:build ctftest

package proxy

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/lifecycle"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

// ebsUpstream plans as hashicorp/aws would for the fields it has: the
// proposed new state with id unknown.
type ebsUpstream struct{ *fakeUpstream5 }

var ebsType = tftypes.Object{AttributeTypes: map[string]tftypes.Type{"id": tftypes.String, "encrypted": tftypes.Bool}}

func (u *ebsUpstream) PlanResourceChange(_ context.Context, req *tfplugin5.PlanResourceChange_Request) (*tfplugin5.PlanResourceChange_Response, error) {
	u.record("PlanResourceChange")
	return &tfplugin5.PlanResourceChange_Response{PlannedState: req.ProposedNewState}, nil
}

func ebsVolume(t *testing.T, encrypted bool, id any) *tfplugin5.DynamicValue {
	t.Helper()
	dv, err := tfprotov5.NewDynamicValue(ebsType, tftypes.NewValue(ebsType, map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, id), "encrypted": tftypes.NewValue(tftypes.Bool, encrypted),
	}))
	if err != nil {
		t.Fatal(err)
	}
	return &tfplugin5.DynamicValue{Msgpack: dv.MsgPack}
}

// TestLifecycleThroughProxy: the proxy serving the 0B lifecycle
// as main.go wires it, on the ctftest keyring and the embedded CIS bundle,
// free tier (no org). Under hard_fail a plan that violates a deny control is
// blocked and a compliant plan passes.
func TestLifecycleThroughProxy(t *testing.T) {
	if got := SchemaBlockToType(ComplianceBlockSchema().Block); !got.Equal(lifecycle.BlockType()) {
		t.Fatalf("proxy advertises compliance %s, lifecycle parses %s", got, lifecycle.BlockType())
	}
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
		}}}},
	}
	l := lifecycle.New(lifecycle.Options{ProviderVersion: "6.40.0"})
	t.Cleanup(func() { _ = l.Close() })
	up := &ebsUpstream{&fakeUpstream5{schema: schema}}
	client, _ := startProxy(t, up, Backends{Evaluator: lifecycle.Hook{Lifecycle: l}})
	ctx := context.Background()
	warmSchema(t, client)

	cr, err := client.Configure(ctx, &tfplugin5.Configure_Request{TerraformVersion: "1.14.0", Config: combinedConfig(t, "hard_fail")})
	if err != nil {
		t.Fatal(err)
	}
	if hasErrorDiag(cr.Diagnostics) || l.Configured() == nil {
		t.Fatalf("Configure: %v", cr.Diagnostics)
	}
	// the region and partition come from the provider
	// config region; the account stays unknown.
	if got := l.Configured().Provider; got != (engine.ProviderInfo{Region: "eu-west-1", RegionKnown: true, Partition: "aws", PartitionKnown: true}) {
		t.Errorf("provider binding %+v, want region eu-west-1 and partition aws only", got)
	}

	plan := func(encrypted bool) []*tfplugin5.Diagnostic {
		t.Helper()
		resp, err := client.PlanResourceChange(ctx, &tfplugin5.PlanResourceChange_Request{
			TypeName:         "aws_ebs_volume",
			PriorState:       &tfplugin5.DynamicValue{Msgpack: []byte{0xc0}}, // null: create
			Config:           ebsVolume(t, encrypted, nil),
			ProposedNewState: ebsVolume(t, encrypted, tftypes.UnknownValue),
		})
		if err != nil {
			t.Fatal(err)
		}
		return resp.Diagnostics
	}
	diags := plan(false)
	if !slices.ContainsFunc(diags, func(d *tfplugin5.Diagnostic) bool {
		return d.Severity == tfplugin5.Diagnostic_ERROR && strings.Contains(d.Summary, "[ebs_volume_encryption_at_rest_enabled]")
	}) {
		t.Errorf("non-compliant plan under hard_fail: %v, want the encryption control error", diags)
	}
	if diags := plan(true); hasErrorDiag(diags) {
		t.Errorf("compliant plan blocked: %v", diags)
	}

	// A Configure error reaches Terraform as an error diagnostic and upstream
	// is not configured.
	t.Setenv("COMPLIANCETF_BREAK_GLASS", "1")
	upCalls := func() int {
		up.mu.Lock()
		defer up.mu.Unlock()
		return strings.Count(strings.Join(up.calls, " "), "Configure")
	}
	before := upCalls()
	cr, err = client.Configure(ctx, &tfplugin5.Configure_Request{TerraformVersion: "1.14.0", Config: combinedConfig(t, "hard_fail")})
	if err != nil {
		t.Fatal(err)
	}
	if len(cr.Diagnostics) != 1 || cr.Diagnostics[0].Severity != tfplugin5.Diagnostic_ERROR || !strings.Contains(cr.Diagnostics[0].Detail, "COMPLIANCETF_BREAK_GLASS") {
		t.Errorf("Configure with break-glass set: %v", cr.Diagnostics)
	}
	if upCalls() != before {
		t.Error("upstream Configure ran after the compliance Configure failed")
	}
}
