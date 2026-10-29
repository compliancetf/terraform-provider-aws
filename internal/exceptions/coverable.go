package exceptions

import (
	"fmt"
	"slices"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

// Coverability is the effective per-kind coverable map. Coverable is the only resolver:
// a signed grant needs grant, a sidecar entry self_service; the verdict gate
// asks for baseline and break_glass. The zero value covers nothing.
type Coverability struct {
	m        map[string][]string // control id -> sorted unique kinds
	declared map[string][]string // the bundle-declared lists alone: the Kinds
}

// NewCoverability builds the map once per Configure from compliance.tf-signed
// content only: declared is bundle.ControlSet.Coverable (verified bundles)
// and ex the verified org profile's exceptions (nil without a signed
// profile). Per id it is the bundle-declared list, emptied when
// forbid_controls lists the id (case-insensitive, deliberately wider). The
// profile's exceptions.coverable is never read: only the bundle declares
// coverability, as the verdict tool does. Grants, sidecar entries, verdicts
// and baselines are never inputs.
//
// modes are the resolved profile floor_mode and the mode the floor was
// obtained in (as for NewClock). break_glass is kept only when every mode is
// "" or online; under airgap, or an invalid mode, it is dropped from every
// list with one warning per id. Profile validation and the floor
// path already reject an invalid mode; the drop is defense in depth. The
// post-drop Coverable(id, break_glass) is the only break-glass gate: the verdict gate
// must not read the signed lists directly. The content digest is over the
// bundle-declared lists only (Kinds): forbid_controls and floor_mode are
// never digest inputs; profile_digest binds the profile.
func NewCoverability(declared map[string][]bundle.ExemptionKind, ex *profile.Exceptions, modes ...string) (Coverability, []string) {
	m := map[string][]string{}
	bundleOnly := make(map[string][]string, len(declared))
	for id, kinds := range declared {
		bundleOnly[id] = []string{}
		for _, k := range kinds {
			m[id] = append(m[id], string(k))
			bundleOnly[id] = append(bundleOnly[id], string(k))
		}
		slices.Sort(bundleOnly[id])
		bundleOnly[id] = slices.Compact(bundleOnly[id])
	}
	airgap, invalid := floorModes(modes...)
	why := "floor_mode airgap has no break-glass"
	if invalid != "" {
		why = fmt.Sprintf("floor_mode %q is not online or airgap", invalid)
	}
	var warns []string
	for id, kinds := range m {
		slices.Sort(kinds)
		kinds = slices.Compact(kinds)
		if ex.Forbidden(id) {
			kinds = nil
		}
		if (airgap || invalid != "") && slices.Contains(kinds, string(bundle.CoverBreakGlass)) {
			kinds = slices.DeleteFunc(kinds, func(k string) bool { return k == string(bundle.CoverBreakGlass) })
			warns = append(warns, fmt.Sprintf("break_glass coverability ignored for %s: %s", id, why))
		}
		m[id] = kinds
	}
	slices.Sort(warns)
	return Coverability{m: m, declared: bundleOnly}, warns
}

// Coverable reports whether control id is exemption-coverable for kind;
// false for an unknown id or kind.
func (c Coverability) Coverable(id, kind string) bool {
	return slices.Contains(c.m[id], kind)
}

// Kinds is a copy of the bundle-declared map (every declared id, sorted
// unique kinds, [] when none), the coverable input of
// bundle.ControlSet.ContentDigest. forbid_controls is not in it: it
// changes Coverable, never the digest.
// Never resolve with it: Coverable is the only resolver. Kinds and the
// digest are profile and floor_mode invariant while Coverable is not, so
// nothing cached under the digest may hold a coverability or break_glass
// decision: ask Coverable at use time.
func (c Coverability) Kinds() map[string][]string {
	out := make(map[string][]string, len(c.declared))
	for id, kinds := range c.declared {
		out[id] = slices.Clone(kinds)
	}
	return out
}

// GrantCoverable decides grant coverability for a verified grant: ok only
// when it names at least one control, every reference resolves and every
// resolved id is coverable for grant; otherwise the whole grant is not
// applied. notCovered is the sorted unique list of unresolvable references
// and ids lacking grant, one exception_not_coverable warning each.
func (c Coverability) GrantCoverable(g Grant, resolve func(string) []string) (ok bool, notCovered []string) {
	for _, ref := range g.Controls {
		ids := resolve(ref)
		if len(ids) == 0 {
			notCovered = append(notCovered, ref)
		}
		for _, id := range ids {
			if !c.Coverable(id, string(bundle.CoverGrant)) {
				notCovered = append(notCovered, id)
			}
		}
	}
	slices.Sort(notCovered)
	notCovered = slices.Compact(notCovered)
	return len(g.Controls) > 0 && len(notCovered) == 0, notCovered
}
