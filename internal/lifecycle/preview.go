package lifecycle

import "github.com/compliancetf/terraform-provider-aws/internal/profile"

// verdictRequiredGA is the GA flag of verdict_required: it stays
// false, so verdict_required is preview, until the key custody gate (9.1)
// and the break-glass drill pass (GA checklist); the owner sets it
// to true in the GA release.
const verdictRequiredGA = false

// PreviewVerdictRequired is the Configure warning of a profile that sets
// verdict_required before GA.
const PreviewVerdictRequired = "Profile sets verdict_required, which is in preview: the key custody and break-glass drills for GA have not passed. Every mutating apply still needs a verdict."

// previewWarnings warns that verdict_required is preview while the GA flag
// is off. Preview never relaxes it: every mutating apply still needs a
// verdict entry.
func previewWarnings(p *profile.Profile, ga bool) []string {
	if p == nil || !p.VerdictRequired || ga {
		return nil
	}
	return []string{PreviewVerdictRequired}
}
