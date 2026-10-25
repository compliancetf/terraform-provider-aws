package bundle

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

const swapDir = "../../testdata/bundles/swap-graph"

func swapBundle(t *testing.T, name string) *Bundle {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(swapDir, name+".tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ReadArchive(raw, testVerify)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func swapSet(t *testing.T, bs ...*Bundle) *ControlSet {
	t.Helper()
	s, _, err := NewControlSet("bobthecorp", now, trust.NoRevocations(), bs...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestContentDigestJCS: the canonical JSON form is RFC 8785 (its section
// 3.2.2 example), and the JSON digest is sha256 over it.
func TestContentDigestJCS(t *testing.T) {
	in, err := os.ReadFile("testdata/contentdigest/rfc8785-input.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/contentdigest/rfc8785-output.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := canonicalJSON(in)
	if err != nil || string(got) != string(want) {
		t.Fatalf("JCS\n got %s (%v)\nwant %s", got, err, want)
	}
	if d, err := DigestJSON(in); err != nil || d != sha(string(want)) {
		t.Fatalf("DigestJSON %s, %v", d, err)
	}
	for _, tc := range []struct{ in, want string }{
		{`[0, -0, 1e21, 1e-7, 123e-9, 1.5e300, -12.50, 100]`, `[0,0,1e+21,1e-7,1.23e-7,1.5e+300,-12.5,100]`},
		// UTF-16 order: U+00E9 < U+1F600 (D83D DE00) < U+FB01; code point order differs.
		{"{\"b\":1,\"a\":{\"d\":[],\"c\":{}},\"\u00e9\":2,\"\U0001F600\":3,\"\ufb01\":4}",
			"{\"a\":{\"c\":{},\"d\":[]},\"b\":1,\"\u00e9\":2,\"\U0001F600\":3,\"\ufb01\":4}"},
		{"\"\u2028<>&\\u001f\"", "\"\u2028<>&\\u001f\""}, // U+2028 and <>& stay literal
	} {
		if got, err := canonicalJSON([]byte(tc.in)); err != nil || string(got) != tc.want {
			t.Errorf("JCS %s: got %s (%v), want %s", tc.in, got, err, tc.want)
		}
	}
	for _, bad := range []string{``, `{`, `{"a":1,"a":2}`, `[1] [2]`, `1e400`, "\"\xff\"", `{"a":1}x`} {
		if _, err := DigestJSON([]byte(bad)); err == nil || err.Error() != "digest_not_json" {
			t.Errorf("DigestJSON(%q): %v, want digest_not_json", bad, err)
		}
	}
}

// TestContentDigest: the swap-graph bundles a and b are signed and identical
// except graph.json; their content digests differ. The coverable map is an
// input (a kind change, a loaded id with no kind), bundle load order
// is not.
func TestContentDigest(t *testing.T) {
	a, b := swapBundle(t, "a"), swapBundle(t, "b")
	if a.content[ControlsFile] != b.content[ControlsFile] || a.content[IAMActionsFile] != b.content[IAMActionsFile] ||
		a.content[GraphFile] == b.content[GraphFile] || a.content[GraphFile] == "" {
		t.Fatalf("fixture: a %v, b %v", a.content, b.content)
	}
	// iam-actions.json is parsed for celeng.Content.IAMCatalog.
	if a.IAMCatalog == nil || b.IAMCatalog == nil || a.IAMCatalog.Digest() != b.IAMCatalog.Digest() {
		t.Fatal("swap bundles must expose their action catalog")
	}
	const id = "rds_kms_key_policy_denies"
	cov := map[string][]string{id: {"grant"}}
	da, db := swapSet(t, a).ContentDigest(cov), swapSet(t, b).ContentDigest(cov)
	if !digestRE.MatchString(da) || da == db {
		t.Fatalf("graph.json swap: a %s, b %s", da, db)
	}
	// Normative preimage: JCS of {bundles, coverable}, "" for an absent file.
	want := sha(`{"bundles":[{"bundle_id":"bobthecorp-swap-graph","controls":"` + a.content[ControlsFile] +
		`","graph":"` + a.content[GraphFile] + `","iam_actions":"` + a.content[IAMActionsFile] +
		`"}],"coverable":{"` + id + `":["grant"]}}`)
	if da != want {
		t.Fatalf("preimage: %s, want %s", da, want)
	}
	if d := swapSet(t, a).ContentDigest(map[string][]string{id: {"baseline", "grant"}}); d == da {
		t.Fatal("a coverable kind must change the digest")
	}
	// Kinds are a set: order and repeats do not change the digest.
	if d := swapSet(t, a).ContentDigest(map[string][]string{id: {"grant", "baseline", "grant"}}); d != swapSet(t, a).ContentDigest(map[string][]string{id: {"baseline", "grant"}}) {
		t.Fatal("kind order or repeats changed the digest")
	}
	// A loaded id missing from the map, or mapped to nil, is listed as [].
	none := swapSet(t, a).ContentDigest(nil)
	if none == da || none != swapSet(t, a).ContentDigest(map[string][]string{id: nil}) {
		t.Fatal("a loaded id without kinds must appear as []")
	}

	// Load order: two bundles in either order give one digest.
	other := goodBundle(t)
	cov2 := map[string][]string{id: {"grant"}, "rds_db_instance_encryption_at_rest_enabled": {"grant"}}
	if swapSet(t, a, other).ContentDigest(cov2) != swapSet(t, other, a).ContentDigest(cov2) {
		t.Fatal("bundle load order must not change the digest")
	}
	if other.IAMCatalog != nil {
		t.Fatal("a bundle without iam-actions.json has no catalog")
	}
	// good.tar.gz has no graph.json or iam-actions.json: "" in the preimage;
	// its control with exemption_coverable [] is listed as [].
	got := swapSet(t, other).ContentDigest(map[string][]string{"rds_db_instance_encryption_at_rest_enabled": {"grant"}})
	if want := sha(`{"bundles":[{"bundle_id":"bobthecorp-soc2","controls":"` + other.content[ControlsFile] +
		`","graph":"","iam_actions":""}],"coverable":{"rds_db_instance_encryption_at_rest_enabled":["grant"],` +
		`"s3_bucket_level_public_access_prohibited":[]}}`); got != want || other.content[ControlsFile] == "" {
		t.Fatalf("absent files: %s, want %s", got, want)
	}
}
