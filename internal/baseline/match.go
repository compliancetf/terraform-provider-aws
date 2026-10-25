package baseline

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

// Instance is what a match needs about one apply, from the verified verdict
// entry, the request and the provider binding. The zero value has
// no verdict entry, so it never matches: plan and any apply without a
// matched verdict entry treat every violation as new.
type Instance struct {
	// From the verified verdict.
	OrgID, Workspace         string
	Address, PreviousAddress string   // instances[].address and .previous_address
	Action                   string   // instances[].action
	Refreshed                string   // instances[].refreshed, exactly "true" to match
	Listed                   []string // instances[].baselines[]
	Matched                  []string // top-level baselines[].digest

	// From the provider binding and the request.
	AccountID, Region string
	Type              string
	IdentityKind      string          // the instance key's prior_identity_kind
	PriorIdentity     json.RawMessage // the instance key's prior identity (kind identity)
	Prior, Planned    tftypes.Value
	Schema            *tfprotov5.Schema // the upstream schema of Type
	Now               time.Time
}

// Decision is a match outcome. Reason is set when no entry matched and the
// spec names a diagnostic for why (major bump, revocation); value-free.
type Decision struct {
	Grandfathered bool
	Entry         string // digest of the matching entry
	Reason        string
}

// Grandfathered reports whether an entry covers ctl's violation on in. All
// grandfather requirements hold: the control is
// baseline-coverable and no read is schema-sensitive; the verdict marks the
// instance refreshed and lists the entry digest for it and at the top
// level; org, workspace, scope, type, identity, control, control major and
// control manifest digest equal; read_digest equals on the prior reads and
// the planned reads equal the prior reads; not expired, not revoked; the
// address equals, or the verdict attests the entry address as
// previous_address. An import or forget never matches. Whether
// grandfathering applies at all (mode grandfather) stays with Classify.
func (s *Set) Grandfathered(ctl *bundle.Control, in Instance) Decision {
	switch {
	case s == nil || ctl == nil || s.coverable == nil || !s.coverable(ctl.ID):
		return Decision{}
	case in.Refreshed != "true" || in.Action == "import" || in.Action == "forget" || in.OrgID != s.org:
		return Decision{}
	}
	if !Grandfatherable(ctl, in.Schema) {
		return Decision{}
	}
	manifest, err := digestJSON(ctl)
	if err != nil {
		return Decision{}
	}
	identity, ok := instanceIdentity(in)
	if !ok {
		return Decision{}
	}
	var prior, planned string
	var d Decision
	for i := range s.entries {
		e, digest := &s.entries[i], s.digests[i]
		switch {
		case !slices.Contains(in.Listed, digest) || !slices.Contains(in.Matched, digest):
			continue
		case e.Workspace != in.Workspace || e.Scope != (Scope{in.AccountID, in.Region}) || e.Type != in.Type || e.Control != ctl.ID:
			continue
		case e.IdentityKind != in.IdentityKind || !maps.Equal(e.Identity, identity):
			continue
		case e.Address != in.Address && (in.PreviousAddress == "" || e.Address != in.PreviousAddress):
			continue // a moved instance matches only through the verdict's previous_address
		case e.ControlMajor != fmt.Sprint(major(ctl.Version)):
			d.Reason = fmt.Sprintf("baseline entry for %s approved at major %s, bundle has %d: re-baseline", ctl.ID, e.ControlMajor, major(ctl.Version))
			continue
		case e.ControlManifestDigest != manifest:
			continue
		case s.revs.KeyRevoked(s.kid) || s.revs.ControlRevoked(e.Control, major(ctl.Version)):
			d.Reason = fmt.Sprintf("baseline entry %s revoked at epoch %d", digest, s.revs.Epoch())
			continue
		}
		if exp, err := parseUTC(e.Expires); err != nil || in.Now.After(exp) {
			continue
		}
		if prior == "" {
			p, ok1 := ReadDigest(s.key, ctl.Reads, in.Prior)
			q, ok2 := ReadDigest(s.key, ctl.Reads, in.Planned)
			if !ok1 || !ok2 || p != q {
				return Decision{} // an unknown or a changed read is never grandfathered
			}
			prior, planned = p, q
		}
		if e.ReadDigest == prior && planned == prior {
			return Decision{Grandfathered: true, Entry: digest}
		}
	}
	return d
}

// Grandfatherable reports whether a violation of ctl can be grandfathered
// at all under schema s: s is known and no read is schema-sensitive or
// unresolvable. Plan
// uses it for baseline eligibility; coverability and the mode stay
// with the caller.
func Grandfatherable(ctl *bundle.Control, s *tfprotov5.Schema) bool {
	return ctl != nil && s != nil && !slices.ContainsFunc(ctl.Reads, func(r string) bool { return sensitiveRead(s, r) })
}

// instanceIdentity is the identity the entry must equal: kind identity the
// instance key's prior identity object (null members dropped, every other
// member a string), kind id {"id": <prior id>}, which the planned state
// must keep.
func instanceIdentity(in Instance) (map[string]string, bool) {
	switch in.IdentityKind {
	case "identity":
		var raw map[string]*string
		if json.Unmarshal(in.PriorIdentity, &raw) != nil {
			return nil, false
		}
		out := map[string]string{}
		for k, v := range raw {
			if v != nil {
				out[k] = *v
			}
		}
		return out, len(out) > 0
	case "id":
		id := topID(in.Prior)
		return map[string]string{"id": id}, id != "" && topID(in.Planned) == id
	}
	return nil, false
}

// topID is the known top-level string id of v, "" otherwise.
func topID(v tftypes.Value) string {
	var attrs map[string]tftypes.Value
	var id string
	if !v.IsKnown() || v.IsNull() || v.As(&attrs) != nil {
		return ""
	}
	if a, ok := attrs["id"]; ok && a.IsKnown() && !a.IsNull() && a.As(&id) == nil {
		return id
	}
	return ""
}
