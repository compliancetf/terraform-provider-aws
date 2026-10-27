package bundle_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/exceptions"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

const inputsDir = "testdata/contentdigest"

// inputs parses dir/profile.json and builds the coverability from the signed
// bundle lists and that profile, as Configure does. Nothing else
// in dir is read.
func inputs(t *testing.T, set *bundle.ControlSet, dir string) (*profile.Profile, exceptions.Coverability, []string) {
	t.Helper()
	return inputsDeclared(t, set.Coverable(), dir)
}

// inputsDeclared is inputs over a given bundle-declared map.
func inputsDeclared(t *testing.T, declared map[string][]bundle.ExemptionKind, dir string) (*profile.Profile, exceptions.Coverability, []string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, _, err := profile.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	cov, warns := exceptions.NewCoverability(declared, &p.Exceptions, p.FloorMode, p.FloorMode)
	return p, cov, warns
}

// inputsDigest is the content digest as Configure computes it from dir.
func inputsDigest(t *testing.T, set *bundle.ControlSet, dir string) string {
	t.Helper()
	_, cov, _ := inputs(t, set, dir)
	return set.ContentDigest(cov.Kinds())
}

func swapGraphSet(t *testing.T) *bundle.ControlSet {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/bundles/swap-graph/a.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	b, err := bundle.ReadArchive(raw, bundle.TestVerify)
	if err != nil {
		t.Fatal(err)
	}
	set, _, err := bundle.NewControlSet("bobthecorp", time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC), trust.NoRevocations(), b)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// TestContentDigestInputs: the content digest inputs are closed to
// bundle content plus the bundle-declared coverable map. A profile that
// forbids an id changes enforcement (Coverable) but not the digest; a
// profile coverable list changes neither (it is ignored); changing the
// profile mode_floor, budgets or floor_mode (one fixture each) leaves it
// unchanged; a grant, baseline, verdict or memo entry binds it and is never
// an input.
func TestContentDigestInputs(t *testing.T) {
	const id = "rds_kms_key_policy_denies"
	set := swapGraphSet(t)
	baseProfile, baseCov, _ := inputs(t, set, inputsDir)
	base := inputsDigest(t, set, inputsDir)
	if want := set.ContentDigest(bundleKinds(set.Coverable())); base != want {
		t.Fatalf("base digest %s, want the bundle-only %s", base, want)
	}
	for name, tc := range map[string]struct {
		kind    string
		changes bool
	}{"coverable-kind-added": {"self_service", false}, "forbid-added": {"grant", true}} {
		dir := filepath.Join(inputsDir, name)
		if _, cov, _ := inputs(t, set, dir); (cov.Coverable(id, tc.kind) != baseCov.Coverable(id, tc.kind)) != tc.changes {
			t.Errorf("%s: Coverable(%s, %s) changed %v, want %v", name, id, tc.kind, !tc.changes, tc.changes)
		}
		if d := inputsDigest(t, set, dir); d != base {
			t.Errorf("%s: a profile coverability change moved the digest to %s, want %s", name, d, base)
		}
	}
	// Each profile-field fixture changes exactly its field; assert it differs
	// first so an edited fixture cannot pass by changing nothing.
	// binders-changed keeps the base profile; the binder loop below checks it.
	differs := map[string]func(p *profile.Profile) bool{
		"mode-floor-changed": func(p *profile.Profile) bool { return p.ModeFloor.Default != baseProfile.ModeFloor.Default },
		"budgets-changed":    func(p *profile.Profile) bool { return p.Budgets != baseProfile.Budgets },
		"floor-mode-changed": func(p *profile.Profile) bool { return p.FloorMode != baseProfile.FloorMode },
		"binders-changed":    func(*profile.Profile) bool { return true },
	}
	for name, changed := range differs {
		dir := filepath.Join(inputsDir, name)
		if p, _, _ := inputs(t, set, dir); !changed(p) {
			t.Errorf("%s: the fixture does not change its field", name)
		}
		if d := inputsDigest(t, set, dir); d != base {
			t.Errorf("%s: digest %s, want %s", name, d, base)
		}
	}
	// Each binder carries the digest it binds; adding it changed nothing.
	for _, f := range []string{"grant.json", "baseline.json", "verdict.json", "memo.json"} {
		raw, err := os.ReadFile(filepath.Join(inputsDir, "binders-changed", f))
		if err != nil {
			t.Fatal(err)
		}
		var binder struct {
			ContentDigest string `json:"content_digest"`
		}
		if err := json.Unmarshal(raw, &binder); err != nil || binder.ContentDigest != base {
			t.Errorf("binders-changed/%s binds %q (%v), want %s", f, binder.ContentDigest, err, base)
		}
	}
}

// TestContentDigestCacheContract: the content digest keys the
// celeng prefilter memo and the IAM document cache, and it is floor_mode
// invariant while break_glass coverability is not. Two runs that differ only
// in floor_mode share the digest and Kinds, yet Coverable and its warnings
// differ: a value cached under the digest must be a pure function of bundle
// content plus Kinds, and break_glass gating must be re-asked through
// Coverable at use time. The bundle map here also lists break_glass for id.
func TestContentDigestCacheContract(t *testing.T) {
	const id = "rds_kms_key_policy_denies"
	set := swapGraphSet(t)
	declared := set.Coverable()
	declared[id] = []bundle.ExemptionKind{bundle.CoverBreakGlass, bundle.CoverGrant}
	_, online, onlineWarns := inputsDeclared(t, declared, inputsDir)
	_, airgap, airgapWarns := inputsDeclared(t, declared, filepath.Join(inputsDir, "floor-mode-changed"))
	if !reflect.DeepEqual(online.Kinds(), airgap.Kinds()) {
		t.Fatalf("Kinds differ across floor_mode: %v vs %v", online.Kinds(), airgap.Kinds())
	}
	if set.ContentDigest(online.Kinds()) != set.ContentDigest(airgap.Kinds()) {
		t.Fatal("the content digest must not depend on floor_mode")
	}
	if !online.Coverable(id, string(bundle.CoverBreakGlass)) || airgap.Coverable(id, string(bundle.CoverBreakGlass)) {
		t.Errorf("Coverable(%s, break_glass) online %v airgap %v, want true and false", id,
			online.Coverable(id, string(bundle.CoverBreakGlass)), airgap.Coverable(id, string(bundle.CoverBreakGlass)))
	}
	if len(onlineWarns) != 0 || len(airgapWarns) != 1 {
		t.Errorf("warnings online %q airgap %q, want none and one", onlineWarns, airgapWarns)
	}
	if !reflect.DeepEqual(airgap.Kinds(), bundleKinds(declared)) {
		t.Errorf("airgap Kinds %v: Kinds is the bundle-declared map, not the gate", airgap.Kinds())
	}
}

// bundleKinds is a bundle-declared map (set.Coverable) as the sorted string
// map ContentDigest takes.
func bundleKinds(declared map[string][]bundle.ExemptionKind) map[string][]string {
	out := map[string][]string{}
	for id, kinds := range declared {
		out[id] = []string{}
		for _, k := range kinds {
			out[id] = append(out[id], string(k))
		}
	}
	return out
}
