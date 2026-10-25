package bundlegen

import (
	"slices"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

// selectors are the bundles in emit order and the catalog frameworks each
// selects (the bundle selectors); nil selects every
// generated control. cis-aws tracks cis_v600 only: earlier CIS versions stay
// visible through framework_refs.
var selectors = []struct {
	id         string
	frameworks []string
}{
	{"cis-aws", []string{"cis_v600"}},
	{"soc2-aws", []string{"soc_2"}},
	{"pci-dss-aws", []string{"pci_dss_v40"}},
	{"hipaa-aws", []string{"hipaa_security_2003", "hipaa_final_omnibus_2013"}},
	{"all", nil},
}

// Selected is one bundle and its controls, in input order.
type Selected struct {
	ID       string
	Controls []bundle.Control
}

// Select assigns controls to bundles by the catalog metadata.frameworks of their
// id, which also covers a framework that has no clause title. A bundle with
// no control is left out: an empty controls.json does not load.
func Select(cs []bundle.Control, catalog map[string]CatalogControl) []Selected {
	var out []Selected
	for _, s := range selectors {
		var sel []bundle.Control
		for _, c := range cs {
			if selects(s.frameworks, catalog[c.ID].Metadata.Frameworks) {
				sel = append(sel, c)
			}
		}
		if len(sel) > 0 {
			out = append(out, Selected{s.id, sel})
		}
	}
	return out
}

// selects reports whether a selector with frameworks (nil: every control)
// selects a control in the catalog frameworks fws.
func selects(frameworks, fws []string) bool {
	return frameworks == nil || slices.ContainsFunc(frameworks, func(f string) bool { return slices.Contains(fws, f) })
}
