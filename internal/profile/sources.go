package profile

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/fsutil"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// Candidate sources, in tie-break order.
const (
	SourceEnv     = "env"     // COMPLIANCETF_PROFILE_PATH
	SourceService = "service" // bundle service
	SourceHCL     = "hcl"     // profile_path
	SourceCache   = "cache"   // <cache>/profiles/<org>/v<n>.dsse.json
)

const (
	maxFileBytes  = 4 << 20
	maxCacheFiles = 64
	issuedSkew    = 5 * time.Minute
)

var cacheNameRE = regexp.MustCompile(`^v([1-9][0-9]{0,17})\.dsse\.json$`)

// Pin is the embedded org pin of an org-specific build (trust.OrgPin); it
// always governs.
type Pin = trust.Pin

// Org is the reconciled org of a run. Governed here comes from the pin or
// COMPLIANCETF_GOVERNED only; Resolve adds profile governance.
type Org struct {
	ID       string
	Governed bool
}

// ResolveOrg reconciles the HCL and env org ids with the org pin and the
// COMPLIANCETF_GOVERNED value. It runs before any candidate is loaded.
func ResolveOrg(hclOrg, envOrg string, pin *Pin, envGoverned string) (Org, error) {
	var o Org
	switch envGoverned {
	case "", "false":
	case "true":
		o.Governed = true
	default:
		return Org{}, errors.New("COMPLIANCETF_GOVERNED: want true or false")
	}
	if hclOrg != "" && envOrg != "" && hclOrg != envOrg {
		return Org{}, fmt.Errorf("org_id %s and COMPLIANCETF_ORG_ID %s differ", safeOrg(hclOrg), safeOrg(envOrg))
	}
	o.ID = hclOrg + envOrg
	if hclOrg != "" && envOrg != "" {
		o.ID = hclOrg
	}
	if pin != nil {
		if o.ID != "" && o.ID != pin.OrgID {
			return Org{}, fmt.Errorf("org_id %s differs from the org pin %s of this build", safeOrg(o.ID), safeOrg(pin.OrgID))
		}
		o.ID, o.Governed = pin.OrgID, true
	}
	if o.ID == "" {
		if o.Governed {
			return Org{}, errors.New("governed run needs an org_id")
		}
		return o, nil
	}
	if !orgRE.MatchString(o.ID) {
		return Org{}, fmt.Errorf("org_id: want %s", orgRE)
	}
	return o, nil
}

// safeOrg is an org id for a diagnostic: the id when it matches orgRE, else a
// fixed placeholder, so an unvalidated input is never echoed.
func safeOrg(id string) string {
	if orgRE.MatchString(id) {
		return id
	}
	return "<invalid org_id>"
}

// Sources names where profile candidates come from. Service holds the
// envelope the fetch client returned (nil when not reached).
type Sources struct {
	EnvPath         string
	Service         []byte
	ServiceExpected bool // COMPLIANCETF_TOKEN and org_id set
	HCLPath         string
	CacheDir        string
}

// Rejection names a candidate that was not used and why. Rollback marks a
// verified candidate below the profile floor (evidence event
// rollback_rejected).
type Rejection struct {
	Source, Path, Reason string
	Rollback             bool
}

type candidate struct {
	source, path string
	p            *Profile
}

// Candidates are the signature-valid, parse-valid profiles for one org. Only
// LoadCandidates builds them.
type Candidates struct {
	org             string
	list            []candidate
	rejected        []Rejection
	warnings        []string
	serviceExpected bool
	serviceReached  bool
}

// LoadCandidates verifies every source the same way. org must come from
// ResolveOrg.
func LoadCandidates(src Sources, org string, revs trust.Revocations) Candidates {
	c := Candidates{org: org, serviceExpected: src.ServiceExpected, serviceReached: src.Service != nil}
	if !orgRE.MatchString(org) {
		return c
	}
	if src.EnvPath != "" {
		c.addFile(SourceEnv, src.EnvPath, 0, revs)
	}
	if src.Service != nil {
		c.add(SourceService, "", src.Service, 0, revs)
	}
	if src.HCLPath != "" {
		c.addFile(SourceHCL, src.HCLPath, 0, revs)
	}
	if src.CacheDir != "" {
		c.addCache(src.CacheDir, filepath.Join(src.CacheDir, "profiles", org), revs)
	}
	return c
}

func (c *Candidates) reject(source, path, format string, a ...any) {
	c.rejected = append(c.rejected, Rejection{Source: source, Path: path, Reason: fmt.Sprintf(format, a...)})
}

// addCache reads root/profiles/<org> only when every dir from root down
// passes fsutil.OpenTree, reading every file through its handle; otherwise the cache source is unavailable with a
// warning, so another local user cannot plant or swap cached profiles.
func (c *Candidates) addCache(root, dir string, revs trust.Revocations) {
	r, err := fsutil.OpenTree(root, dir, false)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			c.warnings = append(c.warnings, fmt.Sprintf("Profile cache ignored: %v.", err))
		}
		return
	}
	defer r.Close() //nolint:errcheck // dir handle
	ents, err := fsutil.ReadDir(r)
	if err != nil {
		c.reject(SourceCache, dir, "%v", err)
		return
	}
	type named struct {
		v    int64
		name string
	}
	var files []named
	for _, e := range ents {
		if m := cacheNameRE.FindStringSubmatch(e.Name()); m != nil && e.Type().IsRegular() {
			v, err := strconv.ParseInt(m[1], 10, 64)
			if err != nil {
				continue
			}
			files = append(files, named{v, e.Name()})
		}
	}
	if len(files) > maxCacheFiles {
		c.reject(SourceCache, dir, "too many cached profiles (%d > %d)", len(files), maxCacheFiles)
		return
	}
	slices.SortFunc(files, func(a, b named) int { return cmp.Compare(b.v, a.v) })
	for _, f := range files {
		path := filepath.Join(dir, f.name)
		b, err := fsutil.ReadFile(r, f.name, maxFileBytes)
		if err != nil {
			c.reject(SourceCache, path, "%v", err)
			continue
		}
		c.add(SourceCache, path, b, f.v, revs)
	}
}

func (c *Candidates) addFile(source, path string, wantVersion int64, revs trust.Revocations) {
	f, err := os.Open(path)
	if err != nil {
		c.reject(source, path, "%v", err)
		return
	}
	defer f.Close() //nolint:errcheck // read-only
	b, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		c.reject(source, path, "%v", err)
		return
	}
	if len(b) > maxFileBytes {
		c.reject(source, path, "file larger than %d bytes", maxFileBytes)
		return
	}
	c.add(source, path, b, wantVersion, revs)
}

func (c *Candidates) add(source, path string, env []byte, wantVersion int64, revs trust.Revocations) {
	v, err := verifyEnvelope(env, revs)
	if err != nil {
		c.reject(source, path, "%v", err)
		return
	}
	p, warns, err := Parse(v.Payload)
	switch {
	case err != nil:
		c.reject(source, path, "%v", err)
	case p.OrgID != c.org:
		c.reject(source, path, "wrong org (want %q)", c.org) // the signed org_id is not echoed
	case wantVersion != 0 && p.ProfileVersion != wantVersion:
		c.reject(source, path, "file name says v%d, payload is v%d", wantVersion, p.ProfileVersion)
	default:
		c.list = append(c.list, candidate{source, path, p})
		c.warnings = append(c.warnings, warns...)
	}
}

// FloorMode is the floor_mode of the highest-version candidate (expiry not
// considered, per the spec order); "online" for a run governed by pin or env
// with no candidate; "" when no floor mode is known. Candidates at the top
// version that disagree are an error.
func (c Candidates) FloorMode(governed bool) (string, error) {
	var top int64
	for _, cd := range c.list {
		top = max(top, cd.p.ProfileVersion)
	}
	mode, seen := "", false
	for _, cd := range c.list {
		switch {
		case cd.p.ProfileVersion != top:
		case !seen:
			mode, seen = cd.p.FloorMode, true
		case cd.p.FloorMode != mode:
			return "", fmt.Errorf("profiles at v%d disagree on floor_mode", top)
		}
	}
	if mode == "" && governed {
		mode = FloorOnline
	}
	return mode, nil
}

// FloorNeeds says whether Configure must obtain a floor before Resolve: some
// verified candidate is governed or lists bundles (over-approximates Resolve,
// which fails closed when the floor is missing). airgapPath is the
// floor_airgap_path of the highest-version candidates; disagreement there is
// an error, as for FloorMode.
func (c Candidates) FloorNeeds() (need bool, airgapPath string, err error) {
	var top int64
	for _, cd := range c.list {
		top = max(top, cd.p.ProfileVersion)
		need = need || cd.p.Governed || len(cd.p.Bundles) > 0
	}
	seen := false
	for _, cd := range c.list {
		switch {
		case cd.p.ProfileVersion != top:
		case !seen:
			airgapPath, seen = cd.p.FloorAirgapPath, true
		case cd.p.FloorAirgapPath != airgapPath:
			return false, "", fmt.Errorf("profiles at v%d disagree on floor_airgap_path", top)
		}
	}
	return need, airgapPath, nil
}

// Bundles lists, sorted and unique, every bundle_id any verified candidate
// requires, and the highest candidate version; Configure fetches them before
// the floor only to merge their revocations.
func (c Candidates) Bundles() (ids []string, top int64) {
	for _, cd := range c.list {
		top = max(top, cd.p.ProfileVersion)
		for _, b := range cd.p.Bundles {
			ids = append(ids, b.BundleID)
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids), top
}

// Fallback says how the profile outcome was reached.
type Fallback int

const (
	FreeTier       Fallback = iota // no org: default soft_fail, no floors
	ProfileApplied                 // a complete profile applies
	HardFailFloor                  // org set, not governed, no acceptable profile
)

// Input to Resolve. MinVersion is the effective profile minimum (trust
// state, release floor, floor statement, env). FloorMode is the mode in which
// the caller validated a floor statement, "" when none.
type Input struct {
	Org             Org
	Candidates      Candidates
	MinVersion      int64
	FloorMode       string
	ProviderVersion string
	Now             time.Time
}

// Resolution is the profile outcome and the input of the configure record.
type Resolution struct {
	OrgID    string
	Governed bool
	Profile  *Profile // whole profile, nil unless Fallback == ProfileApplied
	Source   string
	Path     string
	Fallback Fallback
	Warnings []string
	Rejected []Rejection
}

// Resolve selects the profile for a run and applies the fail-closed defaults.
func Resolve(in Input) (Resolution, error) {
	org := in.Org.ID
	if org == "" {
		return Resolution{Fallback: FreeTier}, nil
	}
	c := in.Candidates
	if c.org != org {
		return Resolution{}, fmt.Errorf("profile candidates loaded for org %s, run org is %s", safeOrg(c.org), safeOrg(org))
	}
	r := Resolution{OrgID: org, Rejected: slices.Clone(c.rejected), Warnings: slices.Clone(c.warnings)}

	var sel *candidate
	conflict := false
	for i := range c.list {
		cd := &c.list[i]
		p := cd.p
		switch {
		case !in.Now.Before(p.ExpiresAt):
			r.Rejected = append(r.Rejected, Rejection{Source: cd.source, Path: cd.path, Reason: fmt.Sprintf("v%d expired %s", p.ProfileVersion, p.ExpiresAt.Format(time.RFC3339))})
			continue
		case in.Now.Before(p.IssuedAt.Add(-issuedSkew)):
			r.Rejected = append(r.Rejected, Rejection{Source: cd.source, Path: cd.path, Reason: fmt.Sprintf("v%d issued in the future", p.ProfileVersion)})
			continue
		case p.ProfileVersion < in.MinVersion:
			r.Rejected = append(r.Rejected, Rejection{Source: cd.source, Path: cd.path, Reason: fmt.Sprintf("v%d is below the floor v%d", p.ProfileVersion, in.MinVersion), Rollback: true})
			continue
		}
		switch {
		case sel == nil || p.ProfileVersion > sel.p.ProfileVersion:
			sel, conflict = cd, false
		case p.ProfileVersion == sel.p.ProfileVersion && p.Digest != sel.p.Digest:
			conflict = true
		}
	}
	if conflict {
		r.Rejected = append(r.Rejected, Rejection{Reason: fmt.Sprintf("conflicting digests at v%d", sel.p.ProfileVersion)})
		sel = nil // never descend below a conflicting version
	}

	// Governed: pin, env, or any verified candidate at or above the selection.
	r.Governed = in.Org.Governed
	for _, cd := range c.list {
		if cd.p.Governed && (sel == nil || cd.p.ProfileVersion >= sel.p.ProfileVersion) {
			r.Governed = true
		}
	}

	if r.Governed || sel != nil && len(sel.p.Bundles) > 0 {
		want, err := c.FloorMode(r.Governed)
		if err != nil || want == "" || in.FloorMode != want {
			if err != nil {
				want = err.Error()
			}
			return Resolution{}, fmt.Errorf("Org floor for %s unavailable: governed runs need a signed floor statement (floor_mode %s).", org, want) //nolint:staticcheck // spec text
		}
	}

	if sel == nil {
		reason := "no profile found"
		if len(r.Rejected) > 0 {
			var rs []string
			for _, rj := range r.Rejected {
				rs = append(rs, strings.TrimSpace(rj.Source+" "+rj.Path+": "+rj.Reason))
			}
			reason = strings.Join(rs, "; ")
		}
		if r.Governed {
			return Resolution{}, fmt.Errorf("No acceptable org profile for governed org %s: %s.", org, reason) //nolint:staticcheck // spec text
		}
		r.Fallback = HardFailFloor
		r.Warnings = append(r.Warnings, fmt.Sprintf("Org profile for %s unavailable: hard_fail floor applied (%s).", org, reason))
		return r, nil
	}

	if err := CheckWrapper(in.ProviderVersion, sel.p.MinWrapperVersion); err != nil {
		return Resolution{}, err
	}
	r.Profile, r.Source, r.Path, r.Fallback = sel.p, sel.source, sel.path, ProfileApplied
	// A rolled-back candidate is named even when a newer one applies; its
	// configure record is rollback_rejected.
	for _, rj := range r.Rejected {
		if rj.Rollback {
			r.Warnings = append(r.Warnings, fmt.Sprintf("Org profile candidate rejected: %s.", strings.TrimSpace(rj.Source+" "+rj.Path+": "+rj.Reason)))
		}
	}
	if sel.source == SourceCache && c.serviceExpected && !c.serviceReached {
		r.Warnings = append([]string{fmt.Sprintf("Org profile for %s unavailable from the service: using cached v%d.", org, sel.p.ProfileVersion)}, r.Warnings...)
	}
	return r, nil
}
