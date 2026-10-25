//go:build ctftest

package proxy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/bundle/bundletest"
	"github.com/compliancetf/terraform-provider-aws/internal/lifecycle"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
	"github.com/compliancetf/terraform-provider-aws/test/scrub/scrubtest"
)

// lookupUpstream serves the fake_lookup data source of test/fakeupstream:
// name required, id computed as "lookup-<name>".
type lookupUpstream struct{ *fakeUpstream5 }

var lookupType = tftypes.Object{AttributeTypes: map[string]tftypes.Type{"name": tftypes.String, "id": tftypes.String}}

func lookupValue(t *testing.T, name, id any) *tfplugin5.DynamicValue {
	t.Helper()
	dv, err := tfprotov5.NewDynamicValue(lookupType, tftypes.NewValue(lookupType, map[string]tftypes.Value{
		"name": tftypes.NewValue(tftypes.String, name), "id": tftypes.NewValue(tftypes.String, id)}))
	if err != nil {
		t.Fatal(err)
	}
	return &tfplugin5.DynamicValue{Msgpack: dv.MsgPack}
}

func (u *lookupUpstream) ReadDataSource(_ context.Context, req *tfplugin5.ReadDataSource_Request) (*tfplugin5.ReadDataSource_Response, error) {
	u.record("ReadDataSource")
	v, err := (&tfprotov5.DynamicValue{MsgPack: req.Config.Msgpack}).Unmarshal(lookupType)
	if err != nil {
		return nil, err
	}
	var attrs map[string]tftypes.Value
	if err := v.As(&attrs); err != nil {
		return nil, err
	}
	var name string
	if !attrs["name"].IsKnown() || attrs["name"].As(&name) != nil {
		return &tfplugin5.ReadDataSource_Response{State: req.Config}, nil
	}
	dv, err := tfprotov5.NewDynamicValue(lookupType, tftypes.NewValue(lookupType, map[string]tftypes.Value{
		"name": attrs["name"], "id": tftypes.NewValue(tftypes.String, "lookup-"+name)}))
	if err != nil {
		return nil, err
	}
	return &tfplugin5.ReadDataSource_Response{State: &tfplugin5.DynamicValue{Msgpack: dv.MsgPack}}, nil
}

// lookupControls are the data source controls of the test bundle: a deny
// configured control on the query name and a warn effective control on the
// result id.
const lookupControls = `[
  {"id": "lookup_name_bobthecorp", "version": "1.0.0", "kind": "data_source", "resource_type": "fake_lookup",
   "reads": ["name"], "presence_mode": "configured", "expr": "config.name == \"bobthecorp-db\"",
   "action": "deny", "severity": "high", "message": "Look up bobthecorp-db only.", "fix": "Set name = \"bobthecorp-db\".",
   "exemption_coverable": []},
  {"id": "lookup_id_prefixed", "version": "1.0.0", "kind": "data_source", "resource_type": "fake_lookup",
   "reads": ["id"], "presence_mode": "effective", "expr": "resource.id == \"lookup-bobthecorp-db\"",
   "action": "warn", "severity": "low", "message": "The lookup should resolve bobthecorp-db.",
   "exemption_coverable": []}
]`

func dataSourceConfig(t *testing.T, mode, dataSources string) *tfplugin5.DynamicValue {
	t.Helper()
	compType := ComplianceBlockType().(tftypes.Object)
	comp := map[string]tftypes.Value{}
	for name, typ := range compType.AttributeTypes {
		comp[name] = tftypes.NewValue(typ, nil)
	}
	comp["enforcement_mode"] = tftypes.NewValue(tftypes.String, mode)
	if dataSources != "" {
		comp["data_sources"] = tftypes.NewValue(tftypes.String, dataSources)
	}
	typ := CombinedProviderType(upstreamProviderSchema)
	dv, err := tfprotov5.NewDynamicValue(typ, tftypes.NewValue(typ, map[string]tftypes.Value{
		"region": tftypes.NewValue(tftypes.String, "eu-west-1"), "compliance": tftypes.NewValue(compType, comp)}))
	if err != nil {
		t.Fatal(err)
	}
	return &tfplugin5.DynamicValue{Msgpack: dv.MsgPack}
}

// TestDataSourceThroughProxy: the lifecycle
// behind the proxy, on a ctftest-signed bundle of fake_lookup data source
// controls, under hard_fail. Data source enforcement is advisory by default
// (a failing deny control warns), deny is opt-in from HCL or env and raise
// only, and an unknown query argument is pending, never an error.
func TestDataSourceThroughProxy(t *testing.T) {
	archive, err := os.ReadFile("../../testdata/bundles/release-iam.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := bundletest.WithFile(archive, bundle.ControlsFile, []byte(lookupControls), testkeys.Bundle())
	if err != nil {
		t.Fatal(err)
	}
	schema := &tfplugin5.GetProviderSchema_Response{
		Provider: &tfplugin5.Schema{Block: &tfplugin5.Schema_Block{Attributes: []*tfplugin5.Schema_Attribute{{Name: "region", Type: []byte(`"string"`), Optional: true}}}},
		DataSourceSchemas: map[string]*tfplugin5.Schema{"fake_lookup": {Block: &tfplugin5.Schema_Block{Attributes: []*tfplugin5.Schema_Attribute{
			{Name: "name", Type: []byte(`"string"`), Required: true},
			{Name: "id", Type: []byte(`"string"`), Computed: true},
		}}}},
	}
	for _, tc := range []struct {
		name          string
		hcl, env      string
		queryName     any
		wantSeverity  tfplugin5.Diagnostic_Severity
		wantSummary   string
		wantNoErrDiag bool
		scrub         bool // the query value is a marker: no diagnostic, log or evidence line may carry it
	}{
		{name: "advisory default", queryName: "other-db", wantSeverity: tfplugin5.Diagnostic_WARNING,
			wantSummary: "[lookup_name_bobthecorp] Look up bobthecorp-db only.", wantNoErrDiag: true},
		{name: "hcl deny opt-in", hcl: "deny", queryName: "other-db", wantSeverity: tfplugin5.Diagnostic_ERROR,
			wantSummary: "[lookup_name_bobthecorp] Look up bobthecorp-db only."},
		{name: "env raises over hcl advisory", hcl: "advisory", env: "deny", queryName: "other-db", wantSeverity: tfplugin5.Diagnostic_ERROR,
			wantSummary: "[lookup_name_bobthecorp] Look up bobthecorp-db only."},
		{name: "unknown pending", hcl: "deny", queryName: tftypes.UnknownValue, wantSeverity: tfplugin5.Diagnostic_WARNING,
			wantSummary: "[lookup_name_bobthecorp] pending: re-checked when known", wantNoErrDiag: true},
		{name: "compliant", hcl: "deny", queryName: "bobthecorp-db", wantNoErrDiag: true},
		{name: "value-free", hcl: "deny", queryName: scrubtest.Marker(91), wantSeverity: tfplugin5.Diagnostic_ERROR,
			wantSummary: "[lookup_name_bobthecorp] Look up bobthecorp-db only.", scrub: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, k := range []string{"COMPLIANCETF_ENFORCEMENT_MODE", "COMPLIANCETF_GOVERNED", "COMPLIANCETF_TOKEN",
				"COMPLIANCETF_PROFILE_PATH", "COMPLIANCETF_FLOOR_PATH", "COMPLIANCETF_ENVIRONMENT", "COMPLIANCETF_WORKSPACE",
				"COMPLIANCETF_EXCEPTIONS_FILE", "COMPLIANCETF_EXCEPTION_GRANTS", "COMPLIANCETF_MIN_BUNDLE_VERSION",
				"COMPLIANCETF_MIN_PROFILE_VERSION", "COMPLIANCETF_BREAK_GLASS"} {
				t.Setenv(k, "")
			}
			os.Unsetenv("COMPLIANCETF_BREAK_GLASS") //nolint:errcheck,usetesting // set, even empty, fails Configure; t.Setenv above restores it
			t.Setenv("COMPLIANCETF_DATA_SOURCES", tc.env)
			t.Setenv("COMPLIANCETF_OFFLINE", "true")
			t.Setenv("COMPLIANCETF_ORG_ID", "bobthecorp")
			t.Setenv("COMPLIANCETF_STATE_DIR", filepath.Join(dir, "state"))
			t.Setenv("COMPLIANCETF_CACHE_DIR", filepath.Join(dir, "cache"))
			t.Setenv("COMPLIANCETF_EVIDENCE_DIR", filepath.Join(dir, "evidence"))
			path := filepath.Join(dir, "bundle.tar.gz")
			if err := os.WriteFile(path, signed, 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("COMPLIANCETF_BUNDLE_PATH", path)

			var logs func() string
			if tc.scrub {
				logs = scrubtest.CaptureLogs(t)
			}
			l := lifecycle.New(lifecycle.Options{ProviderVersion: "6.40.0",
				Now: func() time.Time { return time.Date(2026, 10, 6, 6, 0, 0, 0, time.UTC) }})
			t.Cleanup(func() { _ = l.Close() })
			up := &lookupUpstream{&fakeUpstream5{schema: schema}}
			client, _ := startProxy(t, up, Backends{Evaluator: lifecycle.Hook{Lifecycle: l}})
			ctx := context.Background()
			warmSchema(t, client)
			cr, err := client.Configure(ctx, &tfplugin5.Configure_Request{TerraformVersion: "1.14.0", Config: dataSourceConfig(t, "hard_fail", tc.hcl)})
			if err != nil {
				t.Fatal(err)
			}
			if hasErrorDiag(cr.Diagnostics) {
				t.Fatalf("Configure: %v", cr.Diagnostics)
			}
			resp, err := client.ReadDataSource(ctx, &tfplugin5.ReadDataSource_Request{TypeName: "fake_lookup", Config: lookupValue(t, tc.queryName, nil)})
			if err != nil {
				t.Fatal(err)
			}
			if resp.State == nil {
				t.Fatal("ReadDataSource dropped the upstream state")
			}
			if tc.scrub {
				for _, d := range resp.Diagnostics {
					scrubtest.NoMarker(t, "diagnostic", d.Summary+"\n"+d.Detail)
				}
				_ = l.Close() // flush the evidence chain
				_ = filepath.WalkDir(filepath.Join(dir, "evidence"), func(p string, e os.DirEntry, err error) error {
					if err == nil && !e.IsDir() {
						b, rerr := os.ReadFile(p)
						scrubtest.Must(t, "evidence read", rerr)
						scrubtest.NoMarker(t, "evidence "+e.Name(), string(b))
					}
					return nil
				})
				scrubtest.NoMarker(t, "logs", logs())
			}
			if tc.wantNoErrDiag && hasErrorDiag(resp.Diagnostics) {
				t.Fatalf("diagnostics %v, want no error", resp.Diagnostics)
			}
			if tc.wantSummary == "" {
				if len(resp.Diagnostics) != 0 {
					t.Fatalf("diagnostics %v, want none", resp.Diagnostics)
				}
				return
			}
			found := false
			for _, d := range resp.Diagnostics {
				if d.Summary == tc.wantSummary {
					found = d.Severity == tc.wantSeverity
					if d.Severity != tfplugin5.Diagnostic_ERROR && d.Severity != tfplugin5.Diagnostic_WARNING {
						t.Errorf("severity %v", d.Severity)
					}
					if strings.Contains(tc.wantSummary, "] Look up") && !strings.Contains(d.Detail, "Stage: data_source\nType: fake_lookup") {
						t.Errorf("detail %q, want Stage: data_source then Type: fake_lookup", d.Detail)
					}
				}
			}
			if !found {
				t.Fatalf("diagnostics %v, want %v %q", resp.Diagnostics, tc.wantSeverity, tc.wantSummary)
			}
		})
	}
}
