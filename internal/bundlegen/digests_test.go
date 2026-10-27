package bundlegen

import (
	"bytes"
	"encoding/json"
	"maps"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/exceptions"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

var catalogFiles = []string{"manifest.json", "controls.json", "frameworks_metadata.json", "provider_dispositions.json"}

// copyCatalog copies the test catalog export to a temp dir, passing each file
// through edit, and returns the dir.
func copyCatalog(t *testing.T, edit func(name string, data []byte) []byte) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range catalogFiles {
		data, err := os.ReadFile(filepath.Join(inputs, "catalog", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), edit(name, data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

type buildDigests struct {
	Catalog struct {
		ControlsSHA256     string `json:"controls_sha256"`
		DispositionsSHA256 string `json:"dispositions_sha256"`
	} `json:"catalog"`
	ContentDigest string `json:"content_digest"`
}

// TestDigests: every build.json digest is the internal/bundle
// per-artifact digest (DigestJSON of the catalog files, the bundle content digest of
// the emitted bundle); reordered and re-spaced disposition JSON keeps its
// digest and the output bytes; a symlinked input or a symlink in the output
// fails E_SPECIAL_FILE (FIFOs: digests_unix_test.go); inputs without the
// catalog digests do not generate.
func TestDigests(t *testing.T) {
	in := loadInputs(t, inputs, true)
	gen := generate(t, in)
	want := map[string]string{}
	for _, name := range []string{"controls.json", "provider_dispositions.json"} {
		raw, err := os.ReadFile(filepath.Join(inputs, "catalog", name))
		if err != nil {
			t.Fatal(err)
		}
		if want[name], err = bundle.DigestJSON(raw); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	for _, p := range slices.Sorted(maps.Keys(gen)) {
		id, ok := strings.CutSuffix(p, "/build.json")
		if !ok {
			continue
		}
		n++
		var b buildDigests
		if err := json.Unmarshal(gen[p], &b); err != nil {
			t.Fatal(err)
		}
		if b.Catalog.ControlsSHA256 != want["controls.json"] || b.Catalog.DispositionsSHA256 != want["provider_dispositions.json"] {
			t.Errorf("%s: catalog digests %+v, want %v", id, b.Catalog, want)
		}
		if cd, err := ContentDigest(id, bundleFiles(gen, id)); err != nil || b.ContentDigest != cd {
			t.Errorf("%s: content_digest %s, ContentDigest %s (%v)", id, b.ContentDigest, cd, err)
		}
	}
	if n == 0 {
		t.Fatal("no build.json")
	}
	// The provider's ControlSet.ContentDigest of the signed soc2-aws archive.
	if got := buildDigest(t, gen); got != loadedDigest(t, "base") {
		t.Fatalf("soc2-aws content_digest %s, loaded archive %s", got, loadedDigest(t, "base"))
	}

	t.Run("dispositions reordered", func(t *testing.T) {
		var orig []byte
		dir := copyCatalog(t, func(name string, data []byte) []byte {
			if name != "provider_dispositions.json" {
				return data
			}
			orig = data
			var v any
			if err := json.Unmarshal(data, &v); err != nil {
				t.Fatal(err)
			}
			var b strings.Builder
			writeShuffled(&b, v, rand.New(rand.NewPCG(7, 7)))
			return []byte(" \n" + b.String() + "\n\n")
		})
		re, err := os.ReadFile(filepath.Join(dir, "provider_dispositions.json"))
		if err != nil || bytes.Equal(re, orig) {
			t.Fatalf("reordered file must differ in bytes: %v", err)
		}
		r := in
		if r.Catalog, err = LoadCatalog(dir); err != nil {
			t.Fatal(err)
		}
		if r.Catalog.DispositionsSHA256 != want["provider_dispositions.json"] {
			t.Fatalf("reordered dispositions_sha256 %s, want %s", r.Catalog.DispositionsSHA256, want["provider_dispositions.json"])
		}
		if bad := diffFiles(generate(t, r), gen); bad != nil {
			t.Fatalf("reordered dispositions change the output: %v", bad)
		}
		// A changed value changes the digest.
		dir = copyCatalog(t, func(name string, data []byte) []byte {
			if name == "provider_dispositions.json" {
				return bytes.Replace(data, []byte(`"severity": "high"`), []byte(`"severity": "low"`), 1)
			}
			return data
		})
		if c, err := LoadCatalog(dir); err != nil || c.DispositionsSHA256 == want["provider_dispositions.json"] {
			t.Fatalf("changed dispositions keep their digest: %v", err)
		}
	})

	t.Run("symlink input", func(t *testing.T) {
		for _, name := range catalogFiles {
			dir := copyCatalog(t, func(_ string, data []byte) []byte { return data })
			p := filepath.Join(dir, name)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			abs, err := filepath.Abs(filepath.Join(inputs, "catalog", name))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(abs, p); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadCatalog(dir); errCode(err) != "E_SPECIAL_FILE" {
				t.Errorf("symlinked %s: %v", name, err)
			}
		}
		// A symlink inside the dir, which os.Root would follow, fails too.
		dir := copyCatalog(t, func(_ string, data []byte) []byte { return data })
		p := filepath.Join(dir, "controls.json")
		if err := os.Rename(p, filepath.Join(dir, "real.json")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("real.json", p); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCatalog(dir); errCode(err) != "E_SPECIAL_FILE" {
			t.Errorf("in-dir symlink: %v", err)
		}
	})

	t.Run("symlink output", func(t *testing.T) {
		out := &Output{Files: map[string][]byte{"soc2-aws/build.json": gen["soc2-aws/build.json"]}}
		target := t.TempDir()
		for _, rel := range []string{"soc2-aws", "soc2-aws/build.json", "x/y/link"} {
			dir := t.TempDir()
			p := filepath.Join(dir, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, p); err != nil {
				t.Fatal(err)
			}
			if err := out.WriteDir(dir); errCode(err) != "E_SPECIAL_FILE" {
				t.Errorf("symlink %s in the output dir: %v", rel, err)
			}
			if _, err := ReadOutputDir(dir); errCode(err) != "E_SPECIAL_FILE" {
				t.Errorf("ReadOutputDir with symlink %s: %v", rel, err)
			}
		}
		// The post-write walk: a parent swapped for a symlink inside the
		// root (os.Root follows it) is found after the writes.
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "real"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("real", filepath.Join(dir, "soc2-aws")); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close() //nolint:errcheck // test
		if _, err := walkRoot(root); errCode(err) != "E_SPECIAL_FILE" {
			t.Errorf("walkRoot with an in-root symlink: %v", err)
		}
		if ents, err := os.ReadDir(target); err != nil || len(ents) != 0 {
			t.Fatalf("a write went through a symlink: %v %v", ents, err)
		}
		// A regular leftover is E_OUTPUT, an empty dir writes.
		dir = t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "old.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := out.WriteDir(dir); errCode(err) != "E_OUTPUT" {
			t.Errorf("leftover file: %v", err)
		}
		dir = t.TempDir()
		if err := out.WriteDir(dir); err != nil {
			t.Fatal(err)
		}
		if got, err := ReadOutputDir(dir); err != nil || !bytes.Equal(got.Files["soc2-aws/build.json"], gen["soc2-aws/build.json"]) {
			t.Fatalf("written output does not read back: %v", err)
		}
	})

	t.Run("no catalog digests", func(t *testing.T) {
		m := in
		m.Catalog.DispositionsSHA256 = ""
		if _, err := Generate(m, testOpts); errCode(err) != "E_INPUT" || !strings.Contains(err.Error(), "LoadCatalog") {
			t.Fatalf("missing dispositions digest: %v", err)
		}
		m = in
		m.Catalog.ControlsSHA256 = "sha256:abc"
		if _, err := Generate(m, testOpts); errCode(err) != "E_INPUT" {
			t.Fatalf("malformed controls digest: %v", err)
		}
	})
}

// TestCoverableSignedOnly: bundle coverability is each control's
// exemption_coverable in the signed controls.json. A later disposition file
// and a build.json that both claim every kind for coverableID leave the
// loaded Coverable and the content digest of the signed archive unchanged.
func TestCoverableSignedOnly(t *testing.T) {
	g0 := generate(t, loadInputs(t, inputs, true))
	signed, err := os.ReadFile(filepath.Join(contentDir, "base", bundle.ControlsFile))
	if err != nil || !bytes.Equal(signed, g0["soc2-aws/"+bundle.ControlsFile]) {
		t.Fatalf("the signed base fixture must hold the generated controls.json (TestContentDigest -update): %v", err)
	}
	signedKinds := []bundle.ExemptionKind{bundle.CoverBaseline, bundle.CoverGrant}
	all := []bundle.ExemptionKind{bundle.CoverBaseline, bundle.CoverBreakGlass, bundle.CoverGrant, bundle.CoverSelfService}

	// The disposition file now claims every kind; so does its build.json.
	allRaw, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	in1, err := coverableInputs(t, coverableID, allRaw)
	if err != nil {
		t.Fatal(err)
	}
	g1 := generate(t, in1)
	if got := emittedCoverable(t, g1); len(got) == 0 || !bytes.Equal(got[0], allRaw) {
		t.Fatalf("the differing disposition must reach the generator: %s", got)
	}
	var bj map[string]any
	if err := json.Unmarshal(g1["soc2-aws/build.json"], &bj); err != nil {
		t.Fatal(err)
	}
	bj["exemption_coverable"] = map[string]any{coverableID: all}
	bj["coverable"] = map[string]any{coverableID: all}
	tampered, err := json.Marshal(bj)
	if err != nil {
		t.Fatal(err)
	}

	// The provider loads the signed archive; build.json and the disposition
	// file are not in it and never consulted.
	raw, err := os.ReadFile(filepath.Join(contentDir, "base", "bundle.tar.gz"))
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
	if got := set.Coverable()[coverableID]; !slices.Equal(got, signedKinds) {
		t.Fatalf("loaded Coverable %v, want %v from the signed controls.json", got, signedKinds)
	}
	cov, warns := exceptions.NewCoverability(set.Coverable(), nil)
	if len(warns) > 0 {
		t.Fatalf("coverability warnings: %v", warns)
	}
	for _, k := range all {
		if got := cov.Coverable(coverableID, string(k)); got != slices.Contains(signedKinds, k) {
			t.Errorf("Coverable(%s, %s) = %v", coverableID, k, got)
		}
	}

	// build.json is no content digest input either: the signed files with
	// the tampered build.json digest as the signed archive does.
	files := bundleFiles(g0, "soc2-aws")
	files["build.json"] = tampered
	if got, err := ContentDigest("soc2-aws", files); err != nil || got != buildDigest(t, g0) || got != loadedDigest(t, "base") {
		t.Fatalf("content digest with a tampered build.json %s (%v), want %s", got, err, buildDigest(t, g0))
	}
}
