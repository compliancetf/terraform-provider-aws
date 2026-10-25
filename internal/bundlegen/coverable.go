package bundlegen

import (
	"encoding/json"
	"slices"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

// coverableKinds is a disposition's exemption_coverable: a JSON
// list of exemption kind strings. Any other JSON value (a boolean, null, a
// number, an object, a non-string element) fails E_COVERABLE_KIND at decode,
// so no boolean form reaches the generator. An absent field stays nil, the
// default empty list. Kinds and uniqueness are checked by checkCoverable.
type coverableKinds []bundle.ExemptionKind

func (k *coverableKinds) UnmarshalJSON(data []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil || raw == nil {
		return errf("E_COVERABLE_KIND", "exemption_coverable must be a list of exemption kinds")
	}
	out := make(coverableKinds, 0, len(raw))
	for _, r := range raw {
		var s string
		if len(r) == 0 || r[0] != '"' || json.Unmarshal(r, &s) != nil {
			return errf("E_COVERABLE_KIND", "exemption_coverable must be a list of exemption kinds")
		}
		out = append(out, bundle.ExemptionKind(s))
	}
	*k = out
	return nil
}

// checkCoverable fails closed on a disposition whose exemption_coverable
// holds an unknown or duplicate kind. Order is free: Generate emits the
// list sorted into every control of the id (P1 normative control schema).
func checkCoverable(id string, d Disposition) error {
	var seen []bundle.ExemptionKind
	for _, k := range d.ExemptionCoverable {
		switch k {
		case bundle.CoverBaseline, bundle.CoverBreakGlass, bundle.CoverGrant, bundle.CoverSelfService:
		default:
			return errf("E_COVERABLE_KIND", "%s: exemption kind %q: want grant, baseline, break_glass or self_service", id, k)
		}
		if slices.Contains(seen, k) {
			return errf("E_COVERABLE_KIND", "%s: duplicate exemption kind %q", id, k)
		}
		seen = append(seen, k)
	}
	return nil
}
