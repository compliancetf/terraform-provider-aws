package bundlegen

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/exceptions"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

const contentDir = "testdata/contentdigest"

// testVerify checks a single-signature envelope against the derived test
// bundle key (the key go generate ./testdata/generate.go signs with).
func testVerify(env []byte, payloadType string) (trust.Verified, error) {
	var e struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(env, &e); err != nil || len(e.Signatures) != 1 || e.PayloadType != payloadType {
		return trust.Verified{}, errors.New("bad envelope")
	}
	payload, _ := base64.StdEncoding.DecodeString(e.Payload)
	sig, _ := base64.StdEncoding.DecodeString(e.Signatures[0].Sig)
	sum := sha256.Sum256(trust.PAE(e.PayloadType, payload))
	if !ecdsa.VerifyASN1(&testkeys.Bundle().PublicKey, sum[:], sig) {
		return trust.Verified{}, errors.New("signature invalid")
	}
	return trust.Verified{Payload: payload, KeyID: e.Signatures[0].KeyID}, nil
}

// loadedDigest is the provider's content digest of the signed fixture archive
// loaded alone, with its own bundle-declared coverable map (no profile).
func loadedDigest(t *testing.T, dir string) string {
	t.Helper()
	set := loadedSet(t, dir)
	cov := map[string][]string{}
	for id, kinds := range set.Coverable() {
		cov[id] = []string{}
		for _, k := range kinds {
			cov[id] = append(cov[id], string(k))
		}
	}
	return set.ContentDigest(cov)
}

// loadedSet is the signed fixture archive of dir loaded alone.
func loadedSet(t *testing.T, dir string) *bundle.ControlSet {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(contentDir, dir, "bundle.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := bundle.ReadArchive(raw, testVerify)
	if err != nil {
		t.Fatal(err)
	}
	set, _, err := bundle.NewControlSet("bobthecorp", time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC), trust.NoRevocations(), b)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func buildDigest(t *testing.T, files map[string][]byte) string {
	t.Helper()
	var b struct {
		ContentDigest string `json:"content_digest"`
	}
	if err := json.Unmarshal(files["soc2-aws/build.json"], &b); err != nil {
		t.Fatal(err)
	}
	return b.ContentDigest
}

// syncFixture checks (or with -update writes) the generated soc2-aws archive
// files of dir; the signed bundle.tar.gz is rebuilt by
// go generate ./testdata/generate.go.
func syncFixture(t *testing.T, dir string, files map[string][]byte) map[string][]byte {
	t.Helper()
	// content-lock.json is the generator's top-level lock, not an archive file.
	for name, src := range map[string]string{bundle.ControlsFile: "soc2-aws/" + bundle.ControlsFile, bundle.IAMActionsFile: "soc2-aws/" + bundle.IAMActionsFile, LockFile: LockFile} {
		p := filepath.Join(contentDir, dir, name)
		if *update {
			if err := os.WriteFile(p, files[src], 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if got, err := os.ReadFile(p); err != nil || !bytes.Equal(got, files[src]) {
			t.Fatalf("%s/%s differs from the generator output (run with -update, then go generate ./testdata/generate.go): %v", dir, name, err)
		}
	}
	return readTree(t, filepath.Join(contentDir, dir))
}

// TestContentDigest: build.json content_digest equals the
// provider's ControlSet.ContentDigest of the signed archive; graph.json
// with controls.json unchanged changes it while content-lock.json stays
// unchanged; a changed exemption_coverable changes it.
func TestContentDigest(t *testing.T) {
	in := loadInputs(t, inputs, true)
	gen := generate(t, in)
	base := buildDigest(t, gen)
	baseFiles := syncFixture(t, "base", gen)
	if got := loadedDigest(t, "base"); got != base || base == "" {
		t.Fatalf("base: build.json %q, loaded archive %s", base, got)
	}

	// swap-graph: the base files plus graph.json (recomputed with
	// ContentDigest).
	swapFiles := syncFixture(t, "swap-graph", gen)
	for _, name := range []string{bundle.ControlsFile, "content-lock.json"} {
		if !bytes.Equal(swapFiles[name], baseFiles[name]) {
			t.Fatalf("swap-graph %s must equal base", name)
		}
	}
	swap, err := ContentDigest("soc2-aws", swapFiles)
	if err != nil {
		t.Fatal(err)
	}
	if swapFiles[bundle.GraphFile] == nil || swap == base || swap != loadedDigest(t, "swap-graph") {
		t.Fatalf("swap-graph: %s, base %s, loaded %s", swap, base, loadedDigest(t, "swap-graph"))
	}

	// coverable-changed: one disposition's exemption_coverable differs.
	d := in.Catalog.Dispositions.Controls["s3_bobthecorp_versioning_on"]
	d.ExemptionCoverable = []bundle.ExemptionKind{"grant"}
	in.Catalog.Dispositions.Controls["s3_bobthecorp_versioning_on"] = d
	cgen := generate(t, in)
	changed := buildDigest(t, cgen)
	ccFiles := syncFixture(t, "coverable-changed", cgen)
	if bytes.Equal(ccFiles[bundle.ControlsFile], baseFiles[bundle.ControlsFile]) || !bytes.Equal(ccFiles["content-lock.json"], baseFiles["content-lock.json"]) {
		t.Fatal("coverable-changed: controls.json must differ from base, content-lock.json must not")
	}
	if changed == base || changed != loadedDigest(t, "coverable-changed") {
		t.Fatalf("coverable-changed: build.json %s, base %s, loaded %s", changed, base, loadedDigest(t, "coverable-changed"))
	}

	// Only archive content is an input: build.json, manifest.json and
	// content-lock.json in the file map change nothing.
	if got, err := ContentDigest("soc2-aws", baseFiles); err != nil || got != base {
		t.Fatalf("fixture files: %s (%v), want %s", got, err, base)
	}
	if _, err := ContentDigest("soc2-aws", map[string][]byte{bundle.GraphFile: []byte("{}")}); err == nil {
		t.Fatal("missing controls.json must fail")
	}
}

// verdictVectors are the content digests the verdict producer computes, from
// its own implementation, for these fixtures: base, swap-graph and
// coverable-changed are each archive alone as soc2-aws, controls-only is
// base controls.json alone, two-bundles is base as soc2-aws plus swap-graph
// as soc2-aws-graph. A change here breaks every verdict, candidate and
// approval binding: change both implementations together.
var verdictVectors = map[string]string{
	"base":              "sha256:b05cc43394b886f25106595e21c1ca34c2f1421095024e741d2238e15de54094",
	"controls-only":     "sha256:d67526238531081a0a97a06da1810cec0708c0b3862b782e3a64a65af50e6d2e",
	"coverable-changed": "sha256:ebe7b41c23c958644f94df4756d383838dbe58445faf73072d47e45f3232cf9d",
	"swap-graph":        "sha256:1f2de994dfde01ff192c1781887d1fbf4113dd94c81d4b10213b2929f92163f2",
	"two-bundles":       "sha256:74de6de10a75a06ff9890a9485768a075d5500a11f01853f147e59aa15f8873d",
}

// TestContentDigestBundleOnly: Configure's content digest
// (ContentDigest of Coverability.Kinds) is over the bundle-declared
// coverable lists only. A signed profile that forbids a control changes
// enforcement (Coverable) and one that lists coverable kinds does not (the
// list is ignored); both leave the digest equal to the no-profile digest and
// to the verdict producer's vectors.
func TestContentDigestBundleOnly(t *testing.T) {
	const (
		kms = "iam_bobthecorp_no_kms_wildcard"
		rds = "rds_bobthecorp_storage_encrypted"
		s3  = "s3_bobthecorp_versioning_on"
	)
	ex := &profile.Exceptions{
		Coverable:      map[string][]string{kms: {"break_glass", "grant"}, s3: {"self_service"}, "not_loaded": {"grant"}},
		ForbidControls: []string{rds},
	}
	for _, dir := range []string{"base", "swap-graph", "coverable-changed"} {
		set := loadedSet(t, dir)
		bare, _ := exceptions.NewCoverability(set.Coverable(), nil, "online", "online")
		cov, _ := exceptions.NewCoverability(set.Coverable(), ex, "online", "online")
		if cov.Coverable(kms, "grant") || bare.Coverable(kms, "grant") || cov.Coverable(rds, "baseline") || !bare.Coverable(rds, "baseline") {
			t.Fatalf("%s: forbid_controls must change enforcement and the profile coverable list must not", dir)
		}
		got, noProfile := set.ContentDigest(cov.Kinds()), set.ContentDigest(bare.Kinds())
		if got != noProfile || got != verdictVectors[dir] || got != loadedDigest(t, dir) {
			t.Errorf("%s: with profile %s, without %s, want %s", dir, got, noProfile, verdictVectors[dir])
		}
	}

	base, swap := readTree(t, filepath.Join(contentDir, "base")), readTree(t, filepath.Join(contentDir, "swap-graph"))
	if d, err := ContentDigest("soc2-aws", map[string][]byte{bundle.ControlsFile: base[bundle.ControlsFile]}); err != nil || d != verdictVectors["controls-only"] {
		t.Errorf("controls-only: %s (%v), want %s", d, err, verdictVectors["controls-only"])
	}
	entry := func(id string, files map[string][]byte) bundle.ContentEntry {
		e := bundle.ContentEntry{BundleID: id}
		for name, dst := range map[string]*string{bundle.ControlsFile: &e.Controls, bundle.GraphFile: &e.Graph, bundle.IAMActionsFile: &e.IAMActions} {
			if body, ok := files[name]; ok {
				d, err := bundle.DigestJSON(body)
				if err != nil {
					t.Fatal(err)
				}
				*dst = d
			}
		}
		return e
	}
	// swap-graph has the base controls.json, so one id set and one map.
	cov, _ := exceptions.NewCoverability(loadedSet(t, "base").Coverable(), ex, "online", "online")
	ids := slices.Collect(maps.Keys(cov.Kinds()))
	if d := bundle.ContentDigestOf([]bundle.ContentEntry{entry("soc2-aws-graph", swap), entry("soc2-aws", base)}, ids, cov.Kinds()); d != verdictVectors["two-bundles"] {
		t.Errorf("two-bundles: %s, want %s", d, verdictVectors["two-bundles"])
	}
}
