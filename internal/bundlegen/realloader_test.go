package bundlegen

import (
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
)

// realLoaderInputs are the test inputs with the rds id authored for three
// targets: a resource, a configured second resource type (clusterExpr) and
// an effective data source whose deny expr reads a Computed-only attribute
// of its read result.
func realLoaderInputs(t *testing.T, clusterExpr string) Inputs {
	t.Helper()
	in := loadInputs(t, inputs, true)
	str, b := tftypes.String, tftypes.Bool
	resp := in.Schemas.ProviderSchema()
	resp.ResourceSchemas["aws_rds_cluster"] = &tfprotov5.Schema{Block: &tfprotov5.SchemaBlock{Attributes: []*tfprotov5.SchemaAttribute{
		{Name: "storage_encrypted", Type: b, Optional: true, Computed: true},
	}}}
	resp.DataSourceSchemas["aws_db_instance"] = &tfprotov5.Schema{Block: &tfprotov5.SchemaBlock{Attributes: []*tfprotov5.SchemaAttribute{
		{Name: "db_instance_identifier", Type: str, Required: true},
		{Name: "storage_encrypted", Type: b, Computed: true},
	}}}

	const id = "rds_bobthecorp_storage_encrypted"
	d := in.Catalog.Dispositions.Controls[id]
	d.Targets = []Target{{"resource", "aws_db_instance"}, {"resource", "aws_rds_cluster"}, {"data_source", "aws_db_instance"}}
	in.Catalog.Dispositions.Controls[id] = d
	base := in.Authored[id][0]
	cluster, ds := base, base
	dsExpr := "resource.storage_encrypted == true"
	cluster.ResourceType, cluster.PresenceMode, cluster.Expr = "aws_rds_cluster", bundle.PresenceConfigured, &clusterExpr
	ds.Kind, ds.On, ds.Expr = bundle.KindDataSource, nil, &dsExpr
	in.Authored[id] = []bundle.Control{base, cluster, ds}
	// Generate replays authored fixtures through verify: a pass and a fail
	// case for each added target.
	fx := func(kind bundle.Kind, typ, name, obj string, v bool, want engine.State) Fixture {
		x := Fixture{Kind: kind, Type: typ, Name: name, Bindings: FixtureBindings{Op: bundle.OnCreate}, Expect: FixtureExpect{State: want}}
		m := map[string]any{"storage_encrypted": v}
		if obj == "config" {
			x.Bindings.Config = m
		} else {
			x.Bindings.Resource = m
		}
		return x
	}
	in.AuthoredFixtures[id] = append(slices.Clone(in.AuthoredFixtures[id]),
		fx(bundle.KindResource, "aws_rds_cluster", "pass", "config", true, engine.Pass),
		fx(bundle.KindResource, "aws_rds_cluster", "fail", "config", false, engine.Fail),
		fx(bundle.KindDataSource, "aws_db_instance", "pass", "resource", true, engine.Pass),
		fx(bundle.KindDataSource, "aws_db_instance", "fail", "resource", false, engine.Fail))
	return in
}

// TestRealLoader: generated configured, multi-target and
// data-source controls load through the provider's own decoder
// (bundle.ParseControls) and celeng.Load; a configured control that reads
// resource.* is rejected control_vars by the same loader.
func TestRealLoader(t *testing.T) {
	in := realLoaderInputs(t, "config.storage_encrypted == true")
	out, err := Generate(in, testOpts)
	if err != nil {
		t.Fatal(err)
	}
	targets := map[string]int{}
	var configured, dataSource bool
	for _, p := range slices.Sorted(maps.Keys(out.Files)) {
		if !strings.HasSuffix(p, "/"+bundle.ControlsFile) {
			continue
		}
		cs, err := bundle.ParseControls(out.Files[p])
		if err != nil {
			t.Fatalf("%s: ParseControls: %v", p, err)
		}
		if _, diags, err := celeng.Load(cs, in.Schemas.ProviderSchema()); err != nil || len(diags) > 0 {
			t.Fatalf("%s: celeng.Load: %v, diagnostics %v", p, err, diags)
		}
		for _, c := range cs {
			targets[c.ID]++
			configured = configured || c.PresenceMode == bundle.PresenceConfigured
			dataSource = dataSource || c.Kind == bundle.KindDataSource
		}
	}
	if !configured || !dataSource || slices.Max(slices.Collect(maps.Values(targets))) < 3 {
		t.Fatalf("want configured, data-source and multi-target controls; got targets %v configured %v data source %v", targets, configured, dataSource)
	}

	// A configured resource control reading resource.*: Generate's verify
	// (celeng's loader) refuses the bundle, and the provider load path
	// rejects the decoded control control_vars.
	bad := realLoaderInputs(t, "resource.storage_encrypted == true")
	if _, err := Generate(bad, testOpts); err == nil || !strings.Contains(err.Error(), "control_vars") {
		t.Fatalf("Generate: want a control_vars refusal, got %v", err)
	}
	data, err := EmitControls(bad.Authored["rds_bobthecorp_storage_encrypted"])
	if err != nil {
		t.Fatal(err)
	}
	cs, err := bundle.ParseControls(data)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = celeng.Load(cs, bad.Schemas.ProviderSchema())
	var d *celeng.LoadDiag
	if !errors.As(err, &d) || d.Code != "control_vars" {
		t.Fatalf("configured control reading resource.*: want control_vars, got %v", err)
	}
}
