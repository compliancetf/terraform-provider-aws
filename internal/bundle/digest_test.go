package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const digestFixtures = "testdata/digest"

func readDigestFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(digestFixtures, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// dirModes are the modes the dir-manifest golden expects; git stores only
// 0644/0755 subject to umask, so the test sets them on a copy.
var dirModes = map[string]fs.FileMode{
	"a.b": 0o644, "a.txt": 0o644, "b/x": 0o644, "b.txt": 0o644, "sub/run.sh": 0o755, "sub/z.json": 0o600,
}

// copyTree copies the dir-manifest tree into a temp dir with dirModes.
func copyTree(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	for rel, mode := range dirModes {
		p := filepath.Join(dst, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, readDigestFixture(t, "dir-manifest/tree/"+rel), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil { // WriteFile's mode is masked by umask
			t.Fatal(err)
		}
	}
	return dst
}

// TestDigestAlgorithms is the digest algorithms oracle.
func TestDigestAlgorithms(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		for _, dir := range []string{"json-reordered-keys", "json-whitespace"} {
			a, errA := DigestJSON(readDigestFixture(t, dir+"/a.json"))
			b, errB := DigestJSON(readDigestFixture(t, dir+"/b.json"))
			if errA != nil || errB != nil || a != b || !digestRE.MatchString(a) {
				t.Errorf("%s: %s (%v) != %s (%v)", dir, a, errA, b, errB)
			}
		}
		// A valid surrogate pair digests as the literal code point.
		if got, want := mustDigestJSON(t, `["\ud83d\ude00"]`), mustDigestJSON(t, "[\"\U0001F600\"]"); got != want {
			t.Errorf("surrogate pair: %s, want %s", got, want)
		}
		// Escaped backslash before "u" is literal text, not an escape.
		for _, ok := range []string{`["\\ud800"]`, `{"\\udc00":"\\\\ud800"}`, "[\"\u00e9\ufffd\"]"} {
			if _, err := DigestJSON([]byte(ok)); err != nil {
				t.Errorf("DigestJSON(%s): %v", ok, err)
			}
		}
		entries, err := os.ReadDir(filepath.Join(digestFixtures, "json-invalid"))
		if err != nil || len(entries) == 0 {
			t.Fatal(err)
		}
		bad := []string{`["\ud800`, `["\ud83d\u12"]`, `["\u12"]`, `["\uzzzz"]`, `{"a":["\udfff"]}`, "[\"\ufdd0\"]", "[\"\U0010FFFF\"]",
			`["\udc00\ud800"]`,                 // reversed pair: lone low then lone high
			"[\"\xff\"]", "[\"\xed\xa0\x80\"]"} // raw invalid UTF-8, raw surrogate bytes
		for _, e := range entries {
			bad = append(bad, string(readDigestFixture(t, "json-invalid/"+e.Name())))
		}
		for _, b := range bad {
			if _, err := DigestJSON([]byte(b)); !errors.Is(err, ErrNotJSON) || err.Error() != "digest_not_json" {
				t.Errorf("DigestJSON(%q): %v, want digest_not_json", b, err)
			}
		}
	})

	t.Run("binary", func(t *testing.T) {
		body := readDigestFixture(t, "binary/blob.bin")
		const want = "sha256:5a3130a236ae7d4b6f52ceaedff70e8cde652dfc1fea981480c7fd626080c387"
		sum := sha256.Sum256(body)
		if got := DigestRaw(body); got != want || got != "sha256:"+hex.EncodeToString(sum[:]) {
			t.Fatalf("DigestRaw %s, want %s", got, want)
		}
		if _, err := DigestJSON(body); !errors.Is(err, ErrNotJSON) {
			t.Fatalf("binary as JSON: %v", err)
		}
	})

	t.Run("dir", func(t *testing.T) {
		golden := readDigestFixture(t, "dir-manifest/manifest.json")
		if c, err := canonicalJSON(golden); err != nil || string(c) != string(golden) {
			t.Fatalf("golden manifest is not JCS: %v", err)
		}
		// The committed tree, the golden manifest and dirModes name the same
		// files, and the golden carries dirModes' modes.
		var entries []struct{ Path, Mode string }
		if err := json.Unmarshal(golden, &entries); err != nil {
			t.Fatal(err)
		}
		inGolden := map[string]string{}
		for _, e := range entries {
			inGolden[e.Path] = e.Mode
		}
		var inTree []string
		tree := filepath.Join(digestFixtures, "dir-manifest/tree")
		if err := filepath.WalkDir(tree, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				rel, _ := filepath.Rel(tree, p) //nolint:errcheck // p is under tree
				inTree = append(inTree, filepath.ToSlash(rel))
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if len(inTree) != len(dirModes) || len(inGolden) != len(dirModes) {
			t.Fatalf("tree %v, golden %v, dirModes %v name different files", inTree, inGolden, dirModes)
		}
		for _, rel := range inTree {
			mode, ok := dirModes[rel]
			if !ok || inGolden[rel] != fmt.Sprintf("%04o", mode) {
				t.Fatalf("%s: dirModes %04o (listed %v), golden mode %q", rel, mode, ok, inGolden[rel])
			}
		}
		root := copyTree(t)
		got, err := DigestDir(root)
		if err != nil || got != DigestRaw(golden) {
			t.Fatalf("DigestDir %s (%v), want %s", got, err, DigestRaw(golden))
		}
		if err := os.Chmod(filepath.Join(root, "a.txt"), 0o600); err != nil {
			t.Fatal(err)
		}
		if changed, err := DigestDir(root); err != nil || changed == got {
			t.Fatalf("a mode change must change the digest: %s (%v)", changed, err)
		}
		// Directories carry no entry: an empty tree is the digest of [].
		empty := t.TempDir()
		if err := os.Mkdir(filepath.Join(empty, "d"), 0o755); err != nil {
			t.Fatal(err)
		}
		if d, err := DigestDir(empty); err != nil || d != DigestRaw([]byte("[]")) {
			t.Fatalf("empty tree: %s (%v)", d, err)
		}
		f := filepath.Join(empty, "f")
		if err := os.WriteFile(f, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := DigestDir(f); err == nil || errors.Is(err, ErrSpecialFile) {
			t.Fatalf("a regular file root: %v", err)
		}
	})
}

func mustDigestJSON(t *testing.T, s string) string {
	t.Helper()
	d, err := DigestJSON([]byte(s))
	if err != nil {
		t.Fatalf("DigestJSON(%s): %v", s, err)
	}
	return d
}

// wantSpecial asserts DigestDir(root) is digest_special_file naming rel.
func wantSpecial(t *testing.T, root, rel string) {
	t.Helper()
	_, err := DigestDir(root)
	if !errors.Is(err, ErrSpecialFile) || !strings.HasPrefix(err.Error(), rel+": ") {
		t.Fatalf("DigestDir: %v, want %s: digest_special_file", err, rel)
	}
}

// TestCoverableBundleSource: bundle coverability comes only from each
// control's exemption_coverable in the signed controls.json. The fixture
// source dir also holds a build.json and a sidecar coverable.json claiming
// more kinds; the built archive never carries them, the loaded coverability
// and the content digest come from controls.json alone, and a manifest that
// lists either file does not load.
func TestCoverableBundleSource(t *testing.T) {
	const dir = "testdata/contentdigest/coverable-from-build-json"
	const id = "rds_db_instance_encryption_at_rest_enabled"
	for _, side := range []string{"build.json", "coverable.json"} {
		raw, err := os.ReadFile(filepath.Join(dir, side))
		if err != nil || !strings.Contains(string(raw), "break_glass") {
			t.Fatalf("fixture %s must claim other kinds: %v", side, err)
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, "bundle.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ReadArchive(raw, testVerify)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range b.Manifest.Files {
		if f.Path != ControlsFile {
			t.Fatalf("archive carries %s", f.Path)
		}
	}
	set := swapSet(t, b)
	if got := set.Coverable()[id]; len(got) != 1 || got[0] != CoverGrant {
		t.Fatalf("Coverable %v, want [grant] from controls.json", got)
	}
	controls, err := os.ReadFile(filepath.Join(dir, ControlsFile))
	if err != nil {
		t.Fatal(err)
	}
	cd, err := DigestJSON(controls)
	if err != nil {
		t.Fatal(err)
	}
	want := sha(`{"bundles":[{"bundle_id":"bobthecorp-coverable-source","controls":"` + cd +
		`","graph":"","iam_actions":""}],"coverable":{"` + id + `":["grant"]}}`)
	if got := set.ContentDigest(map[string][]string{id: {"grant"}}); got != want {
		t.Fatalf("content digest %s, want %s", got, want)
	}

	// A signed manifest listing build.json or the sidecar is not a bundle.
	m := `{"format":"compliancetf.bundle-manifest/v2","bundle_id":"bobthecorp-coverable-source","bundle_version":1,` +
		`"org_id":"bobthecorp","profile":"soc2","catalog":{"snapshot_id":"snap_20261004_000000_000000","schema_version":"1"},` +
		`"provider":{"address":"registry.compliance.tf/compliancetf/aws","version_range":">= 2.0.0, < 3.0.0"},` +
		`"upstream":{"source":"hashicorp/aws","version_range":">= 6.0.0, < 7.0.0"},` +
		`"schema_compat_digest":"sha256:3864bd2f9a9ef9d7f0a7757e5ad8ac9d3549d6243ff7e7881cba021d81baf574",` +
		`"issued_at":"2026-10-01T00:00:00Z","expires_at":"2027-04-01T00:00:00Z","min_bundle_version":1,"min_profile_version":0,` +
		`"files":[{"path":"controls.json","sha256":"` + strings.TrimPrefix(DigestRaw(controls), "sha256:") + `","size":` + strconv.Itoa(len(controls)) + `}%s]}`
	if _, err := ParseManifest([]byte(fmt.Sprintf(m, ""))); err != nil {
		t.Fatalf("baseline manifest: %v", err)
	}
	for _, side := range []string{"build.json", "coverable.json"} {
		extra := `,{"path":"` + side + `","sha256":"` + strings.Repeat("0", 64) + `","size":1}`
		if _, err := ParseManifest([]byte(fmt.Sprintf(m, extra))); err == nil || !strings.Contains(err.Error(), "unknown") {
			t.Errorf("manifest listing %s: %v", side, err)
		}
	}
}
