package fetch

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"

	"github.com/compliancetf/terraform-provider-aws/internal/fsutil"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

const (
	maxProfileBytes = 4 << 20 // profile file limit of the profile loader
	keepProfiles    = 8       // newest cached versions kept per org, far below the loader's 64-file cap
)

var profileNameRE = regexp.MustCompile(`^v([1-9][0-9]{0,17})\.dsse\.json$`)

// Profile returns the org profile envelope for profile.Sources.Service. It
// returns nil with a warning when the service is not reached or offline (the
// profile package then falls back to its own cache), and nil without a
// warning when no token is set (the service is not expected). A 200 must
// verify and name org; it is then cached as profiles/<org>/v<n>.dsse.json.
// Errors follow Bundle: refusals, certificate failures, cancellation, 4xx and
// bad 200s are hard.
func (c *Client) Profile(ctx context.Context, org string, revs trust.Revocations) ([]byte, []string, error) {
	if !idRE.MatchString(org) {
		return nil, nil, fmt.Errorf("org %q: want %s", org, idRE)
	}
	switch {
	case c.cfg.Offline:
		return nil, []string{"COMPLIANCETF_OFFLINE is set: org profile not fetched."}, nil
	case c.cfg.Token == "":
		return nil, nil, nil
	}
	resp, err := c.get(ctx, "/v1/orgs/"+org+"/profile", "", http.Header{})
	var tr *transient
	if errors.As(err, &tr) {
		return nil, []string{"Org profile service unreachable. Reason: " + tr.reason + "."}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode == http.StatusNotModified {
		resp.Body.Close() //nolint:errcheck,gosec // read-only
		return nil, nil, errors.New("org profile: HTTP 304 to an unconditional request")
	}
	env, err := readBody(resp, "application/json", maxProfileBytes)
	if errors.As(err, &tr) {
		return nil, []string{"Org profile service unreachable. Reason: " + tr.reason + "."}, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("org profile from the service: %w", err)
	}
	v, err := trust.Verify(env, trust.PayloadProfile, revs)
	if err != nil {
		return nil, nil, fmt.Errorf("org profile from the service: %w", err)
	}
	p, _, err := profile.Parse(v.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("org profile from the service: %w", err)
	}
	if p.OrgID != org {
		return nil, nil, fmt.Errorf("org profile from the service is for another org, not %q", org)
	}
	var warns []string
	if err := storeProfile(c.cfg.CacheDir, filepath.Join(c.cfg.CacheDir, "profiles", org), p.ProfileVersion, env); err != nil {
		warns = append(warns, fmt.Sprintf("Profile cache not updated: %v.", err))
	}
	return env, warns, nil
}

// storeProfile writes a verified profile as v<version> unless that version is
// cached already (a different envelope at the same version stays for the
// profile loader's conflict check), then keeps the newest keepProfiles.
func storeProfile(root, dir string, version int64, env []byte) error {
	r, err := fsutil.OpenTree(root, dir, true)
	if err != nil {
		return err
	}
	defer r.Close() //nolint:errcheck // dir handle
	name := fmt.Sprintf("v%d.dsse.json", version)
	switch old, err := fsutil.ReadFile(r, name, maxProfileBytes); {
	case err == nil && bytes.Equal(old, env):
		return nil
	case err == nil:
		return fmt.Errorf("%s already cached with different content", name)
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	if err := writeAtomicIn(r, name, env, false); err != nil {
		return err // a concurrent run's v<n> is never replaced
	}
	ents, err := fsutil.ReadDir(r)
	if err != nil {
		return err
	}
	var vs []int64
	for _, e := range ents {
		if m := profileNameRE.FindStringSubmatch(e.Name()); m != nil && e.Type().IsRegular() {
			if v, err := strconv.ParseInt(m[1], 10, 64); err == nil {
				vs = append(vs, v)
			}
		}
	}
	slices.SortFunc(vs, func(a, b int64) int { return cmp.Compare(b, a) })
	for _, v := range vs[min(len(vs), keepProfiles):] {
		r.Remove(fmt.Sprintf("v%d.dsse.json", v)) //nolint:errcheck,gosec // best effort
	}
	return nil
}
