package exceptions

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

// Grants are the signed grants of exception_grants_dir honored this run;
// a nil Grants applies nothing. A grant applies to a control
// only when it verified (signature, key window, org, expiry and scope at
// the exceptions clock) and every target is coverable for grant.
type Grants struct {
	clock   Clock // the Verifier's: the honor-time re-check resolves through it
	digests []string
	rules   map[string][]rule // control id -> grants naming it
}

// GrantsInput: Dir is exception_grants_dir ("": no grants), Verifier the
// run's grant verifier (built with the run's exceptions Clock), Coverable
// the effective coverable map, Resolve the control reference resolver and
// Table the run's mode table (the trusted workspace recorded in evidence).
// Binding: ContentDigest is the loaded content digest, FloorEpoch
// the accepted floor epoch high-water (0 without a floor) and Revoked
// reports a loaded control id whose version a merged revocation names (nil
// fails closed: every grant naming a control is stale).
type GrantsInput struct {
	Dir           string
	Verifier      *Verifier
	Coverable     Coverability
	Resolve       func(ref string) []string
	ResolveFold   func(ref string) []string // as SidecarInput.ResolveFold (nil fails closed)
	Table         profile.ModeTable
	ContentDigest string
	FloorEpoch    int64
	Revoked       func(id string) bool
}

// LoadGrants verifies the grant files once per run and decides grant
// coverability. A dir fault is an error; each rejected file warns. A
// verified grant that is not coverable applies to none of its controls:
// one warning per unresolved reference (exception_unresolved_id) and one
// per id lacking grant (exception_not_coverable); its resolved controls
// record status not_coverable.
func LoadGrants(in GrantsInput) (*Grants, Notices, error) {
	if in.Dir == "" {
		return nil, Notices{}, nil
	}
	grants, rej, err := in.Verifier.LoadGrants(in.Dir)
	if err != nil {
		return nil, Notices{}, err
	}
	var n Notices
	for _, r := range rej {
		n.Warnings = append(n.Warnings, r.String()+"; not applied")
		if r.Code == CodeScopeUntrusted {
			n.event(CodeScopeUntrusted)
		}
	}
	gs := &Grants{clock: in.Verifier.in.Clock, rules: map[string][]rule{}}
	forbid := newForbidSet(in.Table, in.ResolveFold)
	for _, g := range grants {
		ok, notCovered := in.Coverable.GrantCoverable(g, in.Resolve)
		status := StatusApplied
		if !ok {
			status = StatusNotCoverable
			for _, ref := range notCovered {
				if len(in.Resolve(ref)) == 0 {
					n.Warnings = append(n.Warnings, fmt.Sprintf("exception %s: %s is not a known control id or alias; grant not applied", g.GrantID, ref))
					n.event("exception_unresolved_id")
				}
			}
			for _, id := range notCovered {
				if len(in.Resolve(id)) > 0 {
					n.Warnings = append(n.Warnings, fmt.Sprintf("exception %s: %s is not exemption-coverable for %s; enforced", g.GrantID, id, bundle.CoverGrant))
					n.event("exception_not_coverable")
				}
			}
		}
		ws := ""
		if len(g.Workspaces) > 0 {
			ws = in.Table.Workspace.Value // verified: the grant lists the trusted workspace
		}
		var ids []string
		for _, ref := range g.Controls {
			for _, id := range in.Resolve(ref) {
				if !slices.Contains(ids, id) {
					ids = append(ids, id)
				}
			}
		}
		if why := grantScopeFault(g, ids, ws, in.Table, forbid); why != "" { // also for a non-coverable grant: its rules still record ws
			status, ws = StatusRejected, ""
			n.Warnings = append(n.Warnings, fmt.Sprintf("exception %s: %s; grant not applied", g.GrantID, why))
		} else if why := staleBinding(g, ids, in); status == StatusApplied && why != "" {
			status = StatusStaleBinding
			n.Warnings = append(n.Warnings, fmt.Sprintf("exception %s: %s; re-approve", g.GrantID, why))
			n.event("exception_stale_binding")
		} else if status == StatusApplied {
			gs.digests = append(gs.digests, g.Digest)
		}
		for _, id := range ids {
			gs.rules[id] = append(gs.rules[id], rule{label: g.GrantID, workspace: ws, source: "grant", digest: g.Digest,
				sel: g.sel, expires: g.ExpiresAt, status: status})
		}
	}
	slices.Sort(gs.digests)
	return gs, n, nil
}

// staleBinding: a grant binds the content it was
// approved against (exact content_digest) and stays valid across floor raises
// while its floor_epoch is at or below the high-water and no revocation names
// a listed control. A revoked signing key already fails verification.
// shortcut: revocations/v1 has no grant-id entries and no per-entry epoch, so
// every merged revocation counts; grant-id revocation needs a format change.
// The warning is the spec text for every stale cause.
func staleBinding(g Grant, ids []string, in GrantsInput) string {
	stale := g.ContentDigest != in.ContentDigest || g.FloorEpoch > in.FloorEpoch ||
		slices.ContainsFunc(ids, func(id string) bool { return in.Revoked == nil || in.Revoked(id) })
	if !stale {
		return ""
	}
	return fmt.Sprintf("approved for content %s at floor epoch %d, provider loaded %s at %d",
		g.ContentDigest, g.FloorEpoch, in.ContentDigest, in.FloorEpoch)
}

// grantScopeFault re-checks scope on the resolved control ids: the
// Verifier sees only the raw references, so an alias must not reach a
// forbid_environment_scoped control, and the recorded workspace must fit
// the evidence scope grammar.
func grantScopeFault(g Grant, ids []string, ws string, t profile.ModeTable, forbid forbidSet) string {
	if ws != "" && !scopeRE.MatchString(ws) {
		return "workspace " + ws + " is outside the evidence scope grammar"
	}
	if len(g.Environments) == 0 || t.Exceptions == nil {
		return ""
	}
	for _, id := range ids {
		if forbid.has(id) {
			return "control " + id + " may not be excepted per environment"
		}
	}
	return ""
}

// forbidSet is forbid_environment_scoped resolved once per load: each
// entry as written plus every control id it resolves to.
type forbidSet struct {
	all   bool     // no resolver: fail closed, every id is forbidden
	names []string // matched under case folding
}

// newForbidSet resolves each forbid_environment_scoped entry once. An id
// is forbidden when an entry names it as written (any case) or through an
// alias or catalog id that resolves to it, so an alias in the profile list
// forbids its canonical control (fail closed: an entry forbids every id it
// resolves to). resolveFold must fold case (bundle.ControlSet.ResolveFold);
// a nil resolveFold with a non-empty list forbids every id, since an exact
// resolver would miss a differently cased alias and fail open.
func newForbidSet(t profile.ModeTable, resolveFold func(string) []string) forbidSet {
	if t.Exceptions == nil || len(t.Exceptions.ForbidEnvironmentScoped) == 0 {
		return forbidSet{}
	}
	if resolveFold == nil {
		return forbidSet{all: true}
	}
	var fs forbidSet
	for _, f := range t.Exceptions.ForbidEnvironmentScoped {
		fs.names = append(append(fs.names, f), resolveFold(f)...)
	}
	return fs
}

// has reports whether control id may not be excepted per environment.
func (fs forbidSet) has(id string) bool {
	return fs.all || slices.ContainsFunc(fs.names, func(n string) bool { return strings.EqualFold(n, id) })
}

// ForbidUnmatched warns, once per forbid_environment_scoped entry that
// resolves to no loaded control id or tool_refs alias, by list position
// only (value-free): such an entry forbids nothing this run. A nil
// resolveFold forbids every id (newForbidSet), so it gets one warning saying so.
func ForbidUnmatched(t profile.ModeTable, resolveFold func(string) []string) []string {
	if t.Exceptions == nil {
		return nil
	}
	if resolveFold == nil {
		if len(t.Exceptions.ForbidEnvironmentScoped) == 0 {
			return nil
		}
		return []string{"forbid_environment_scoped: control resolver unavailable; every environment-scoped exception is rejected"}
	}
	var out []string
	for i, f := range t.Exceptions.ForbidEnvironmentScoped {
		if len(resolveFold(f)) == 0 {
			out = append(out, fmt.Sprintf("forbid_environment_scoped entry %d matches no loaded control id or tool_ref; it forbids nothing", i+1))
		}
	}
	return out
}

// Lookup decides the grants for control ctl, as Sidecar.Lookup.
func (gs *Grants) Lookup(ctx context.Context, ctl *bundle.Control, schemas celeng.SchemaSource, a *engine.Activation, now time.Time) Decision {
	if gs == nil {
		return Decision{}
	}
	return lookup(ctx, gs.rules[ctl.ID], gs.clock, ctl, schemas, a, now)
}

// Digests are the envelope digests of the grants that apply, sorted (nil
// for a nil Grants).
func (gs *Grants) Digests() []string {
	if gs == nil {
		return nil
	}
	return gs.digests
}
