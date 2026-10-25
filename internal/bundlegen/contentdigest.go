package bundlegen

import (
	"slices"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

// ContentDigest is build.json content_digest: the P1 content digest
// of one bundle alone, bundle.ContentDigestOf over the archive file bodies in
// files (controls.json required; graph.json and iam-actions.json "" when
// absent) and the bundle-declared exemption_coverable of every control in
// that controls.json. It equals ControlSet.ContentDigest of the signed
// archive loaded alone with its own Coverable map. The step that adds
// graph.json recomputes it with this function.
func ContentDigest(bundleID string, files map[string][]byte) (string, error) {
	e := bundle.ContentEntry{BundleID: bundleID}
	for name, dst := range map[string]*string{bundle.ControlsFile: &e.Controls, bundle.GraphFile: &e.Graph, bundle.IAMActionsFile: &e.IAMActions} {
		body, ok := files[name]
		if !ok {
			if name == bundle.ControlsFile {
				return "", errf("E_EMIT", "bundle %s: content digest needs %s", bundleID, name)
			}
			continue
		}
		d, err := bundle.DigestJSON(body)
		if err != nil {
			return "", errf("E_EMIT", "bundle %s: %s: %v", bundleID, name, err)
		}
		*dst = d
	}
	cs, err := bundle.DecodeControls(files[bundle.ControlsFile])
	if err != nil {
		return "", errf("E_EMIT", "bundle %s: %v", bundleID, err)
	}
	ids, cov := []string{}, map[string][]string{}
	for _, c := range cs {
		kinds := make([]string, 0, len(c.ExemptionCoverable))
		for _, k := range c.ExemptionCoverable {
			kinds = append(kinds, string(k))
		}
		slices.Sort(kinds)
		kinds = slices.Compact(kinds)
		if prev, ok := cov[c.ID]; ok && !slices.Equal(prev, kinds) {
			// the provider rejects it control_coverable_conflict
			return "", errf("E_EMIT", "bundle %s: control %s declares different exemption_coverable lists", bundleID, c.ID)
		}
		ids, cov[c.ID] = append(ids, c.ID), kinds
	}
	return bundle.ContentDigestOf([]bundle.ContentEntry{e}, ids, cov), nil
}
