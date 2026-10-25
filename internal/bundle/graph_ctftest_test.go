//go:build ctftest

package bundle_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/bundle/bundletest"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

// TestArchiveGraphControls: a signed bundle with a kind graph
// control loads only when the manifest also binds a graph.json; without one
// the archive is rejected, value-free, never loaded as a silent pass.
func TestArchiveGraphControls(t *testing.T) {
	controls, err := os.ReadFile("testdata/controls/valid/kind_graph.json")
	if err != nil {
		t.Fatal(err)
	}
	for name, src := range map[string]string{
		"with graph.json":    "../../testdata/bundles/swap-graph/a.tar.gz",
		"without graph.json": "../../testdata/bundles/bobthecorp-soc2-sim/good.tar.gz",
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(src)
			if err != nil {
				t.Fatal(err)
			}
			signed, err := bundletest.WithFile(raw, bundle.ControlsFile, controls, testkeys.Bundle())
			if err != nil {
				t.Fatal(err)
			}
			b, err := bundle.ReadArchive(signed, bundle.TestVerify)
			if name == "without graph.json" {
				if err == nil || err.Error() != "controls.json: control[0]: control_graph_file_missing" {
					t.Fatalf("err = %v, want control_graph_file_missing", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			set, _, err := bundle.NewControlSet(b.Manifest.OrgID, time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC), trust.NoRevocations(), b)
			if err != nil {
				t.Fatal(err)
			}
			all := set.All()
			if len(all) != 2 || all[0].Kind != bundle.KindGraph || all[0].Expr != nil || all[0].Reads != nil ||
				all[0].Graph == nil || all[0].Graph.Rule != bundle.GraphCompanionPresent ||
				strings.Join(all[0].Graph.TargetAttrs, ",") != "id,bucket" || all[0].Graph.CompanionExpr != nil ||
				all[1].Graph.Rule != bundle.GraphCompanionAbsentForbidden || all[1].Graph.CompanionExpr == nil {
				t.Fatalf("controls %+v", all)
			}
			for _, op := range []bundle.On{bundle.OnCreate, bundle.OnUpdate, bundle.OnDelete} {
				if len(set.For("aws_s3_bucket", op)) != 0 {
					t.Fatalf("graph control indexed for single-resource %s evaluation", op)
				}
			}
		})
	}
}
