package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// ControlSet is the checked set of loaded bundles that enforcement uses.
// NewControlSet is its only constructor.
type ControlSet struct {
	digest    string
	index     map[string]map[On][]Control
	kinds     map[Kind]map[string][]Control    // kind -> resource type -> controls
	all       []Control                        // every control once, in load order
	versions  map[[2]string][]string           // kind, resource type -> "id@version", one per control
	coverable map[string][]ExemptionKind       // control id -> exemption_coverable
	content   [][4]string                      // bundle_id, controls, graph, iam_actions digests; sorted by bundle_id
	catalogs  map[[3]string]*iampolicy.Catalog // control key -> its bundle's iam-actions.json
	revs      trust.Revocations
}

// NewControlSet merges revs with every bundle's revocations, checks every
// bundle against the merged set (org, revocation, issued_at, expiry), and
// indexes the controls by resource type and op. Any failing bundle fails the
// set; grace-window warnings are returned.
func NewControlSet(org string, now time.Time, revs trust.Revocations, bundles ...*Bundle) (*ControlSet, []string, error) {
	if len(bundles) == 0 {
		return nil, nil, errors.New("no bundles to load")
	}
	bundles = slices.Clone(bundles)
	slices.SortFunc(bundles, func(a, b *Bundle) int { return strings.Compare(a.Digest, b.Digest) })
	merged := revs
	ids := map[string]bool{}
	for _, b := range bundles {
		if ids[b.Manifest.BundleID] {
			return nil, nil, fmt.Errorf("duplicate bundle_id %s", b.Manifest.BundleID)
		}
		ids[b.Manifest.BundleID] = true
		var err error
		if merged, err = trust.Merge(merged, b.Revocations); err != nil {
			return nil, nil, err
		}
	}
	s := &ControlSet{index: map[string]map[On][]Control{}, kinds: map[Kind]map[string][]Control{}, versions: map[[2]string][]string{},
		coverable: map[string][]ExemptionKind{}, catalogs: map[[3]string]*iampolicy.Catalog{}, revs: merged}
	var warns, digests []string
	keys := map[[3]string][2]string{}  // control key -> bundle_id and control digest of its first copy
	catalogs := map[[3]string]string{} // control key -> iam-actions.json digest of its first copy
	for _, b := range bundles {
		w, err := b.Check(org, now, merged)
		if errors.Is(err, ErrExpired) && b.Embedded {
			w, err = "Embedded "+err.Error()+"; it stays loaded.", nil
		}
		if err != nil {
			return nil, nil, err
		}
		if w != "" {
			warns = append(warns, w)
		}
		digests = append(digests, b.Digest)
		s.content = append(s.content, [4]string{b.Manifest.BundleID, b.content[ControlsFile], b.content[GraphFile], b.content[IAMActionsFile]})
		for _, c := range b.Controls {
			key := [3]string{c.ID, string(c.Kind), c.ResourceType}
			d, err := controlDigest(&c)
			if err != nil {
				return nil, nil, err
			}
			if prev, dup := keys[key]; dup {
				// The same digest dedupes.
				if prev[1] != d {
					a, z := min(prev[0], b.Manifest.BundleID), max(prev[0], b.Manifest.BundleID)
					return nil, nil, fmt.Errorf("bundles %s and %s disagree on control %s (%s)", a, z, c.ID, c.ResourceType)
				}
				// Copies bound to different IAM catalogs keep none (sticky:
				// only a first copy sets one), so CheckCatalogs rejects the
				// control if it calls iam.*.
				if catalogs[key] != b.content[IAMActionsFile] {
					delete(s.catalogs, key)
				}
				continue
			}
			keys[key] = [2]string{b.Manifest.BundleID, d}
			catalogs[key] = b.content[IAMActionsFile]
			if b.IAMCatalog != nil {
				s.catalogs[key] = b.IAMCatalog
			}
			// Lists are parsed sorted and unique, so equal sets compare equal.
			if prev, ok := s.coverable[c.ID]; ok && !slices.Equal(prev, c.ExemptionCoverable) {
				return nil, nil, fmt.Errorf("control_coverable_conflict: control %s declares different exemption_coverable lists", c.ID)
			}
			s.coverable[c.ID] = slices.Clone(c.ExemptionCoverable)
			s.all = append(s.all, c)
			byOp := s.index[c.ResourceType]
			if byOp == nil {
				byOp = map[On][]Control{}
				s.index[c.ResourceType] = byOp
			}
			for _, op := range c.On {
				byOp[op] = append(byOp[op], c)
			}
			if s.kinds[c.Kind] == nil {
				s.kinds[c.Kind] = map[string][]Control{}
			}
			s.kinds[c.Kind][c.ResourceType] = append(s.kinds[c.Kind][c.ResourceType], c)
			vk := [2]string{string(c.Kind), c.ResourceType}
			s.versions[vk] = append(s.versions[vk], c.ID+"@"+c.Version)
		}
	}
	slices.SortFunc(s.content, func(x, y [4]string) int { return strings.Compare(x[0], y[0]) })
	// digests is already sorted: bundles are sorted by Digest.
	s.digest = digestOf(strings.Join(digests, "\n"))
	return s, warns, nil
}

// controlDigest identifies a control's content for cross-bundle dedupe:
// DigestJSON of the decoded control, every field included.
func controlDigest(c *Control) (string, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return DigestJSON(data)
}

func digestOf(preimage string) string {
	sum := sha256.Sum256([]byte(preimage))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Digest is sha256 over the sorted bundle digests joined by "\n".
func (s *ControlSet) Digest() string { return s.digest }

// IAMCatalog is the iam-actions.json of the bundle that holds c, nil when
// that bundle has none (celeng rejects its iam.* controls iam_catalog_missing).
func (s *ControlSet) IAMCatalog(c *Control) *iampolicy.Catalog {
	return s.catalogs[[3]string{c.ID, string(c.Kind), c.ResourceType}]
}

// All returns every control of the set once (any kind, any op).
func (s *ControlSet) All() []Control { return slices.Clone(s.all) }

// ContentDigest is the content digest:
// "sha256:" + hex(sha256(JCS({bundles: [{bundle_id, controls, graph,
// iam_actions}], coverable}))), the file digests DigestJSON ("" when a file
// is absent). coverable is the bundle-declared exemption_coverable map
// (exceptions.Coverability.Kinds, the lists of Coverable); every loaded
// control id appears, [] when no kind covers it. The signed profile's
// coverable lists and forbid_controls are not inputs. Nothing else is.
//
// Cache contract: the digest keys the celeng prefilter memo and
// the IAM document cache, and it is profile and floor_mode invariant by
// design (Kinds is the bundle-declared map, before any profile merge or
// airgap break_glass drop). A value cached under it
// must be a pure function of bundle content plus Kinds and of the inputs its
// own key adds (the memo adds the projected reads, and op, env and provider
// when the expression reads them; the
// IAM cache the document and catalog digest); never of floor_mode, the
// profile mode table or budgets, break_glass, or an env or clock value the
// key does not carry (timeouts and budget-limit errors are never cached).
// Coverability gating (break_glass included) is re-asked through
// exceptions.Coverability.Coverable at use time and is never cached under
// this key. TestContentDigestCacheContract pins the floor_mode invariance of
// the digest and Kinds.
func (s *ControlSet) ContentDigest(coverable map[string][]string) string {
	entries := make([]ContentEntry, 0, len(s.content))
	for _, e := range s.content {
		entries = append(entries, ContentEntry{BundleID: e[0], Controls: e[1], Graph: e[2], IAMActions: e[3]})
	}
	ids := make([]string, 0, len(s.coverable))
	for id := range s.coverable {
		ids = append(ids, id)
	}
	return ContentDigestOf(entries, ids, coverable)
}

// ContentEntry is one bundle's content-digest input: its bundle_id and the
// DigestJSON of its controls.json, graph.json and iam-actions.json ("" when
// the file is absent).
type ContentEntry struct {
	BundleID, Controls, Graph, IAMActions string
}

// ContentDigestOf is the one content digest implementation, shared by
// ControlSet.ContentDigest and the bundle generator's build.json
// content_digest. ids are the loaded control ids, each listed with
// [] unless coverable gives kinds; entries are sorted by bundle_id here.
func ContentDigestOf(entries []ContentEntry, ids []string, coverable map[string][]string) string {
	cov := map[string]any{}
	for _, id := range ids {
		cov[id] = []any{}
	}
	for id, kinds := range coverable {
		ks := slices.Clone(kinds)
		slices.Sort(ks)
		list := []any{}
		for _, k := range slices.Compact(ks) { // a kind set: order and repeats carry nothing
			list = append(list, k)
		}
		cov[id] = list
	}
	entries = slices.Clone(entries)
	slices.SortFunc(entries, func(x, y ContentEntry) int { return strings.Compare(x.BundleID, y.BundleID) })
	bundles := []any{}
	for _, e := range entries {
		bundles = append(bundles, map[string]any{"bundle_id": e.BundleID, "controls": e.Controls, "graph": e.Graph, "iam_actions": e.IAMActions})
	}
	var buf bytes.Buffer
	if err := writeJCS(&buf, map[string]any{"bundles": bundles, "coverable": cov}); err != nil {
		panic(err) // unreachable: strings, lists and maps only
	}
	return "sha256:" + sha256Hex(buf.Bytes())
}

// VersionsDigest is the plan-to-apply stamp of a managed resource type:
// VersionsDigestOf(resourceType, resource, deletion_guard). Data source and
// ephemeral controls sharing the type name are not in its per-type list;
// a change to them still moves it through Digest.
func (s *ControlSet) VersionsDigest(resourceType string) string {
	return s.VersionsDigestOf(resourceType, KindResource, KindDeletionGuard)
}

// VersionsDigestOf is sha256 over Digest, "\n", and the sorted "id@version"
// of every control of resourceType whose kind is one of kinds, joined by
// "\n". Evidence records use it for the kind a stage evaluates.
func (s *ControlSet) VersionsDigestOf(resourceType string, kinds ...Kind) string {
	var v []string
	for _, k := range kinds {
		v = append(v, s.versions[[2]string{string(k), resourceType}]...)
	}
	slices.Sort(v)
	return digestOf(s.digest + "\n" + strings.Join(v, "\n"))
}

// For returns the controls of resourceType whose on list contains op, in
// bundle digest order, then controls.json order. Callers must not modify it.
func (s *ControlSet) For(resourceType string, op On) []Control {
	return s.index[resourceType][op]
}

// OfKind returns the controls of kind and resourceType in the order of For.
// Data source and ephemeral controls have no on list, so only OfKind sees
// them. Callers must not modify it.
func (s *ControlSet) OfKind(kind Kind, resourceType string) []Control {
	return s.kinds[kind][resourceType]
}

// Coverable is a copy of every loaded control id's bundle-declared
// exemption_coverable list (possibly empty). Only exceptions.NewCoverability
// reads it.
func (s *ControlSet) Coverable() map[string][]ExemptionKind {
	out := make(map[string][]ExemptionKind, len(s.coverable))
	for id, kinds := range s.coverable {
		out[id] = slices.Clone(kinds)
	}
	return out
}

// Revocations is the merged revocation set the bundles were checked against,
// for the trust state writer.
func (s *ControlSet) Revocations() trust.Revocations { return s.revs }

// ControlRevoked reports whether a merged revoked_controls entry names a
// loaded control id at its major version (the integer revocation version is
// the semver major, as baselines read it). Grants bind to it.
func (s *ControlSet) ControlRevoked(id string) bool {
	for _, c := range s.all { // every kind, data_source and ephemeral included
		major, err := strconv.ParseInt(strings.SplitN(c.Version, ".", 2)[0], 10, 64)
		if c.ID == id && (err != nil || s.revs.ControlRevoked(id, major)) {
			return true // an unparsable version fails closed
		}
	}
	return false
}

// Resolve maps an exception control reference to loaded control ids: a
// control id resolves to itself, a tool_refs alias to every control that
// lists it (sorted); nil when nothing matches. Every kind resolves, also
// data source and ephemeral controls, which have no op.
func (s *ControlSet) Resolve(ref string) []string {
	var out []string
	for _, c := range s.all {
		if c.ID == ref {
			return []string{ref}
		}
		for _, refs := range c.ToolRefs {
			if slices.Contains(refs, ref) && !slices.Contains(out, c.ID) {
				out = append(out, c.ID)
			}
		}
	}
	slices.Sort(out)
	return out
}

// ResolveFold is Resolve for the forbid_environment_scoped list, which the
// exceptions package compares case-insensitively: ref matches control ids
// and tool_refs aliases under Unicode simple folding, and a ref that is both
// a control id and another control's alias resolves to both (sorted; nil
// when nothing matches). Widening only ever forbids more.
func (s *ControlSet) ResolveFold(ref string) []string {
	var out []string
	for _, c := range s.all {
		hit := strings.EqualFold(c.ID, ref)
		for _, refs := range c.ToolRefs {
			hit = hit || slices.ContainsFunc(refs, func(r string) bool { return strings.EqualFold(r, ref) })
		}
		if hit && !slices.Contains(out, c.ID) {
			out = append(out, c.ID)
		}
	}
	slices.Sort(out)
	return out
}
