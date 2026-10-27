package verdict

// Plan-time provisional exemptions.

// Exemption kinds of a control's coverable list, in PendingKinds order.
var exemptionKinds = []string{"baseline", "break_glass", "grant", "self_service"}

// Eligibility is what plan knows about one blocking control: the
// compliance.tf-signed bundle and profile, and whether the run configures
// exception grants; never an exemption artifact.
type Eligibility struct {
	// Coverable is the effective signed coverability of the control for an
	// exemption kind after the airgap break_glass drop
	// (exceptions.Coverability.Coverable); nil covers nothing. A coverable
	// list in a grant, sidecar, verdict or baseline is never an input.
	Coverable func(kind string) bool
	// Grandfather: the control's mode is grandfather and the control is
	// grandfatherable (no schema-sensitive or unresolvable read).
	Grandfather bool
	// BreakGlass: the signed profile enables break_glass under floor_mode
	// online.
	BreakGlass bool
	// Grants: the run configures exception grants (exception_grants_dir).
	// Without it no grant can exist at plan or apply, so grant is not
	// eligible and the failure errors at plan.
	Grants bool
	// SelfService: the signed profile lists the control in
	// exceptions.self_service, the only way a sidecar entry can cover it.
	SelfService bool
}

// PendingKinds are the exemption kinds eligible at plan for a blocking
// failure of the control, sorted; empty means the failure errors at plan.
// Each kind needs its kind in the list and its own signal: grant Grants,
// self_service SelfService, baseline Grandfather, break_glass BreakGlass.
func PendingKinds(e Eligibility) []string {
	var out []string
	for _, k := range exemptionKinds {
		ok := e.Coverable != nil && e.Coverable(k)
		switch k {
		case "baseline":
			ok = ok && e.Grandfather
		case "break_glass":
			ok = ok && e.BreakGlass
		case "grant":
			ok = ok && e.Grants
		case "self_service":
			ok = ok && e.SelfService
		}
		if ok {
			out = append(out, k)
		}
	}
	return out
}

// PendingSummary is the plan warning of one eligible kind (spec text).
func PendingSummary(kind, control string) string {
	return "pending exemption: " + kind + " " + control
}
