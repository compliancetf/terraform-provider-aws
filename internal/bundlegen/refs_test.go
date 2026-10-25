package bundlegen

import (
	"errors"
	"maps"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

func loadRefsCatalog(t *testing.T) map[string]CatalogControl {
	t.Helper()
	var cat map[string]CatalogControl
	if err := readJSON(filepath.Join("testdata", "refs", "controls.json"), &cat); err != nil {
		t.Fatal(err)
	}
	return cat
}

// TestRefs: framework_refs take a first token with a digit as the clause id
// and keep other titles whole; supporting clause titles and frameworks
// without a clause title give no ref. tool_refs map catalog export keys to the
// loader's tool slugs, drop empty lists, sort and dedupe values. Every
// generated ref passes the bundle loader.
func TestRefs(t *testing.T) {
	cat := loadRefsCatalog(t)
	type refs struct {
		fw    []string
		tools map[string][]string
	}
	want := map[string]refs{
		"bobthecorp_cis_soc2": {
			[]string{"cis_v500:2.3.1", "cis_v600:3.2", "soc_2:CC6.1"},
			map[string][]string{"checkov": {"CKV_AWS_16", "CKV_AWS_17"}, "trivy": {"AVD-AWS-0080"}},
		},
		"bobthecorp_hipaa_omnibus": {
			[]string{"hipaa_final_omnibus_2013:164.312(a)(2)(iv)"},
			map[string][]string{"powerpipe": {"control.bobthecorp_a", "control.bobthecorp_b"}, "security_hub": {"RDS.3"}},
		},
		"bobthecorp_hipaa_security": {
			[]string{"hipaa_security_2003:164.308(a)(1)(ii)(D)"},
			map[string][]string{"control_tower": {"CT.BOBTHECORP.PR.1"}, "kics": {"00000000-0000-0000-0000-000000000001"}, "prowler": {"bobthecorp_check"}},
		},
		"bobthecorp_cis_v500_only": {[]string{"cis_v500:4"}, nil},
		"bobthecorp_prose_titles": {
			[]string{"aws_well_architected_v10:Data protection", "cisa_cyber_essentials:Your Data-1", "cisa_cyber_essentials:Your Surroundings-1"},
			nil,
		},
		"bobthecorp_no_framework": {nil, nil},
	}
	if got := slices.Sorted(maps.Keys(cat)); !slices.Equal(got, slices.Sorted(maps.Keys(want))) {
		t.Fatalf("catalog ids %v", got)
	}
	expr := "resource.storage_encrypted != null"
	for _, id := range slices.Sorted(maps.Keys(want)) {
		w := want[id]
		fw := FrameworkRefs(cat[id])
		if !slices.Equal(fw, w.fw) {
			t.Errorf("%s framework_refs = %q, want %q", id, fw, w.fw)
		}
		tools, err := ToolRefs(cat[id])
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if !reflect.DeepEqual(tools, w.tools) {
			t.Errorf("%s tool_refs = %v, want %v", id, tools, w.tools)
		}
		c := bundle.Control{
			ID: id, Version: "1.0.0", Kind: bundle.KindResource, ResourceType: "aws_db_instance",
			Reads: []string{"storage_encrypted"}, PresenceMode: bundle.PresenceEffective,
			On:     []bundle.On{bundle.OnCreate, bundle.OnUpdate},
			Expr:   &expr,
			Action: bundle.ActionDeny, Severity: bundle.SeverityMedium, Message: "m",
			FrameworkRefs: fw, ToolRefs: tools, ExemptionCoverable: []bundle.ExemptionKind{},
		}
		data, err := EmitControls([]bundle.Control{c})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := bundle.ParseControls(data); err != nil {
			t.Errorf("%s: loader rejects generated refs: %v", id, err)
		}
	}
}

func TestToolRefsFailClosed(t *testing.T) {
	for name, tools := range map[string]map[string][]string{
		"unknown export key": {"SNYK": {"SNYK-1"}},
		"slug as key":        {"checkov": {"CKV_AWS_16"}},
		"empty ref":          {"CKV": {""}},
	} {
		_, err := ToolRefs(CatalogControl{Tools: tools})
		var e *Error
		if !errors.As(err, &e) || e.Code != "E_TOOL_KEY" {
			t.Errorf("%s: err %v, want E_TOOL_KEY", name, err)
		}
	}
}

// TestSelect: cis-aws takes cis_v600 only, hipaa-aws either HIPAA id,
// pci-dss-aws matches metadata.frameworks without a clause title, all takes
// every control, and a bundle with no control is not returned.
func TestSelect(t *testing.T) {
	cat := loadRefsCatalog(t)
	var cs []bundle.Control
	for _, id := range slices.Sorted(maps.Keys(cat)) {
		cs = append(cs, bundle.Control{ID: id})
	}
	got := map[string][]string{}
	var order []string
	for _, b := range Select(cs, cat) {
		order = append(order, b.ID)
		for _, c := range b.Controls {
			got[b.ID] = append(got[b.ID], c.ID)
		}
	}
	want := map[string][]string{
		"cis-aws":     {"bobthecorp_cis_soc2"},
		"soc2-aws":    {"bobthecorp_cis_soc2"},
		"pci-dss-aws": {"bobthecorp_hipaa_omnibus"},
		"hipaa-aws":   {"bobthecorp_hipaa_omnibus", "bobthecorp_hipaa_security"},
		"all":         slices.Sorted(maps.Keys(cat)),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Select = %v, want %v", got, want)
	}
	if wantOrder := []string{"cis-aws", "soc2-aws", "pci-dss-aws", "hipaa-aws", "all"}; !slices.Equal(order, wantOrder) {
		t.Errorf("bundle order %v, want %v", order, wantOrder)
	}
}

func TestCloneToolRefs(t *testing.T) {
	src := map[string][]string{"checkov": {"CKV_AWS_16"}}
	c := cloneToolRefs(src)
	c["checkov"][0] = "changed"
	if src["checkov"][0] != "CKV_AWS_16" {
		t.Error("cloneToolRefs shares a slice with its source")
	}
	if cloneToolRefs(nil) != nil {
		t.Error("nil tool refs must stay nil (omitempty)")
	}
}
