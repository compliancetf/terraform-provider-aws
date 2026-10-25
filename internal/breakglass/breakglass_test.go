package breakglass

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict"
)

// fixture is one internal/breakglass/testdata case: a verified verdict with
// one receipt built and signed in code (keys generated per run), changed as
// the fields say, then Verify and Honor.
type fixture struct {
	Description string `json:"description"`
	Policy      struct {
		Disabled         bool     `json:"disabled,omitempty"`           // break_glass.enabled false
		ProfileFloorMode *string  `json:"profile_floor_mode,omitempty"` // default "online"
		FloorMode        *string  `json:"floor_mode,omitempty"`         // obtained mode, default "online"
		NoKeys           bool     `json:"no_keys,omitempty"`            // empty receipt_keys
		Coverable        []string `json:"coverable,omitempty"`          // default every control
	} `json:"policy"`
	// IssuedFor replaces verdict members the receipt is computed for
	// (org_id, plan_digest, request digest inputs).
	IssuedFor map[string]string `json:"issued_for,omitempty"`
	// ReceiptSet replaces receipt members before signing; null removes one.
	ReceiptSet map[string]json.RawMessage `json:"receipt_set,omitempty"`
	// Sign: good (default), wrong_key (not a profile key), verdict_key (a
	// key the profile lists only for verdicts), revoked, tampered (a member
	// changed after signing), short_key (key window ends before consumed_at),
	// ends_between / starts_between (valid at only one of consumed_at and the
	// verdict issued_at).
	Sign       string            `json:"sign,omitempty"`
	VerdictSet map[string]string `json:"verdict_set,omitempty"`
	Embed      int               `json:"embed,omitempty"` // copies of the receipt, default 1
	// MalformedCopy appends a copy with override_id ovr-01 made invalid by
	// unknown_member, case_variant_array or duplicate_number.
	MalformedCopy string `json:"malformed_copy,omitempty"`
	Base          string `json:"base,omitempty"` // verdict issued_at, default 2026-10-18T10:00:00Z
	Queries       []struct {
		Control string `json:"control"`
		Key     string `json:"key"`
		Result  string `json:"result"`
		Want    bool   `json:"want"`
	} `json:"queries"`
	Warning string `json:"warning"` // substring of the warning per receipt; "" = no warning
}

const (
	ctl1 = "CTF.S3.1"
	ctl2 = "CTF.S3.2"
	key1 = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	key2 = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	ovID = "ovr-01"
)

type testKey struct {
	priv   *ecdsa.PrivateKey
	signer profile.SignerKey
}

func newKey(t *testing.T, use string, notBefore, notAfter time.Time) testKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{priv, profile.SignerKey{KID: trust.KIDFromSPKI(der), Alg: trust.AlgES256, Use: use,
		SPKIB64: base64.StdEncoding.EncodeToString(der), NotBefore: notBefore, NotAfter: notAfter}}
}

func sign(t *testing.T, k testKey, doc map[string]json.RawMessage) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := bundle.CanonicalJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(signed)
	der, err := ecdsa.SignASN1(rand.Reader, k.priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig, err := json.Marshal(verdict.Signature{KID: k.signer.KID, Alg: trust.AlgES256, Value: base64.RawURLEncoding.EncodeToString(der)})
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func str(v string) json.RawMessage { j, _ := json.Marshal(v); return j } //nolint:errcheck // a string always marshals

func doc(issued time.Time) verdict.Document {
	return verdict.Document{Format: verdict.Format, OrgID: "bobthecorp", Workspace: "prod", Environment: "production", RunID: "run-1",
		PlanDigest:    "sha256:4444444444444444444444444444444444444444444444444444444444444444",
		ContentDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333", FloorEpoch: "3",
		IssuedAt: issued.UTC().Format(time.RFC3339), ExpiresAt: issued.Add(12 * time.Hour).UTC().Format(time.RFC3339)}
}

// build returns the policy and verified verdict of fx.
func build(t *testing.T, fx *fixture) (Policy, *verdict.Verdict) {
	t.Helper()
	issued := time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)
	if fx.Base != "" {
		var err error
		if issued, err = time.Parse(time.RFC3339, fx.Base); err != nil {
			t.Fatal(err)
		}
	}
	window := func(use string) testKey {
		return newKey(t, use, issued.Add(-30*24*time.Hour), issued.Add(30*24*time.Hour))
	}
	receiptKey, verdictKey := window("receipt"), window("verdict")
	p := &profile.Profile{OrgID: "bobthecorp", FloorMode: profile.FloorOnline,
		Verdict:    &profile.Verdict{PublicKeys: []profile.SignerKey{verdictKey.signer}},
		BreakGlass: &profile.BreakGlass{Enabled: !fx.Policy.Disabled, ReceiptKeys: []profile.SignerKey{receiptKey.signer}}}
	if fx.Policy.ProfileFloorMode != nil {
		p.FloorMode = *fx.Policy.ProfileFloorMode
	}
	if fx.Policy.NoKeys {
		p.BreakGlass.ReceiptKeys = nil
	}
	pol := Policy{Profile: p, FloorMode: profile.FloorOnline, Revocations: trust.NoRevocations(), Coverable: func(string) bool { return true }}
	if fx.Policy.FloorMode != nil {
		pol.FloorMode = *fx.Policy.FloorMode
	}
	if fx.Policy.Coverable != nil {
		cov := fx.Policy.Coverable
		pol.Coverable = func(id string) bool { return slices.Contains(cov, id) }
	}

	d := doc(issued)
	for k, v := range fx.VerdictSet {
		setDoc(t, &d, k, v)
	}
	scope := d
	for k, v := range fx.IssuedFor {
		setDoc(t, &scope, k, v)
	}
	r := Receipt{OverrideID: ovID, Controls: []string{ctl1}, InstanceKeys: []string{key1}}
	m := map[string]json.RawMessage{
		"format": str(Format), "override_id": str(ovID), "org_id": str(scope.OrgID), "run_id": str("run-1"),
		"override_digest": str("sha256:5555555555555555555555555555555555555555555555555555555555555555"),
		"request_digest":  str(RequestDigest(&scope, &r)), "controls": json.RawMessage(`["` + ctl1 + `"]`),
		"instance_keys": json.RawMessage(`["` + key1 + `"]`), "plan_digest": str(scope.PlanDigest),
		"consumed_at": str(issued.Add(-10 * time.Minute).Format(time.RFC3339)), "expires_at": str(issued.Add(6 * time.Hour).Format(time.RFC3339)),
	}
	for k, v := range fx.ReceiptSet {
		if string(v) == "null" {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	signer := receiptKey
	switch fx.Sign {
	case "", "good", "tampered":
	case "wrong_key":
		signer = window("receipt")
	case "verdict_key":
		signer = verdictKey
	case "revoked":
		p.RevokedKIDs = []string{receiptKey.signer.KID}
	case "short_key", "ends_between", "starts_between":
		// consumed_at is issued-10m and Skew 5m: ends_between is valid at
		// consumed_at only, starts_between at the verdict issued_at only.
		from, to := issued.Add(-30*24*time.Hour), issued.Add(-time.Hour)
		switch fx.Sign {
		case "ends_between":
			to = issued.Add(-8 * time.Minute)
		case "starts_between":
			from, to = issued, issued.Add(time.Hour)
		}
		short := newKey(t, "receipt", from, to)
		p.BreakGlass.ReceiptKeys = append(p.BreakGlass.ReceiptKeys, short.signer)
		signer = short
	default:
		t.Fatalf("unknown sign %q", fx.Sign)
	}
	m["signature"] = sign(t, signer, withoutSig(m))
	if fx.Sign == "tampered" {
		m["run_id"] = str("run-2")
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for range max(fx.Embed, 1) {
		d.BreakGlassReceipts = append(d.BreakGlassReceipts, raw)
	}
	if fx.MalformedCopy != "" {
		// Each variant keeps override_id ovr-01 readable by a lenient decoder.
		prefix := map[string]string{
			"unknown_member":     `"extra":"x",`,
			"case_variant_array": `"OVERRIDE_ID":[],`,
			"duplicate_number":   `"override_id":5,`,
		}[fx.MalformedCopy]
		if prefix == "" {
			t.Fatalf("unknown malformed_copy %q", fx.MalformedCopy)
		}
		d.BreakGlassReceipts = append(d.BreakGlassReceipts, json.RawMessage("{"+prefix+string(raw[1:])))
	}
	return pol, &verdict.Verdict{Doc: d}
}

func withoutSig(m map[string]json.RawMessage) map[string]json.RawMessage {
	c := map[string]json.RawMessage{}
	for k, v := range m {
		if k != "signature" {
			c[k] = v
		}
	}
	return c
}

func setDoc(t *testing.T, d *verdict.Document, k, v string) {
	t.Helper()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m[k]; !ok {
		t.Fatalf("no verdict member %q", k)
	}
	m[k] = str(v)
	if b, err = json.Marshal(m); err != nil {
		t.Fatal(err)
	}
	*d = verdict.Document{}
	if err := json.Unmarshal(b, d); err != nil {
		t.Fatal(err)
	}
}

func loadFixtures(t *testing.T) map[string]fixture {
	t.Helper()
	files, err := filepath.Glob("testdata/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	out := map[string]fixture{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var fx fixture
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&fx); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if len(fx.Queries) == 0 {
			t.Fatalf("%s: no queries", f)
		}
		out[strings.TrimSuffix(filepath.Base(f), ".json")] = fx
	}
	return out
}

// TestFixtures: every rejection fixture keeps enforcement (no query is
// honored) with its warning, and the valid scoped downgrade honors
// exactly the listed control on the listed action key.
func TestFixtures(t *testing.T) {
	for name, fx := range loadFixtures(t) {
		t.Run(name, func(t *testing.T) {
			pol, v := build(t, &fx)
			set, warns := Verify(pol, v)
			switch {
			case fx.Warning == "" && len(warns) != 0:
				t.Errorf("%s: warnings %q, want none", fx.Description, warns)
			case fx.Warning != "" && (len(warns) != max(fx.Embed, 1)+count(fx.MalformedCopy != "") || slices.ContainsFunc(warns, func(w string) bool { return !strings.Contains(w, fx.Warning) })):
				t.Errorf("%s: warnings %q, want one per receipt containing %q", fx.Description, warns, fx.Warning)
			}
			for _, q := range fx.Queries {
				got := set.Honor(q.Control, q.Key, q.Result)
				if len(got) > 1 || (len(got) == 1) != q.Want || len(got) == 1 && (got[0].ID != ovID || !reDigest.MatchString(got[0].ReceiptDigest)) {
					t.Errorf("%s: Honor(%s, %s, %s) = %+v; want honored %v", fx.Description, q.Control, q.Key, q.Result, got, q.Want)
				}
			}
		})
	}
}

func count(b bool) int {
	if b {
		return 1
	}
	return 0
}

// TestParseStrict: duplicate members (top level or inside the signature), a
// null member and a case-variant member are refused by parse itself, not
// only by a later signature check.
func TestParseStrict(t *testing.T) {
	fx := fixture{}
	_, v := build(t, &fx)
	good := string(v.Doc.BreakGlassReceipts[0])
	if _, err := parse([]byte(good)); err != nil {
		t.Fatalf("valid receipt: %v", err)
	}
	for name, raw := range map[string]string{
		"duplicate member":           strings.Replace(good, `"format":`, `"run_id":"run-1","format":`, 1),
		"duplicate signature member": strings.Replace(good, `"kid":`, `"alg":"ES256","kid":`, 1),
		"null member":                strings.Replace(good, `"format":`, `"predecessor_receipt_digest":null,"format":`, 1),
		"case variant member":        strings.Replace(good, `"run_id":`, `"Run_ID":`, 1),
	} {
		if raw == good {
			t.Fatalf("%s: no change", name)
		}
		if _, err := parse([]byte(raw)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// TestRequestDigestGolden pins B9 for fixed inputs: JCS of the nine members
// with sorted controls and instance keys, sha256, "sha256:" hex.
func TestRequestDigestGolden(t *testing.T) {
	d := doc(time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC))
	r := Receipt{OverrideID: ovID, Controls: []string{ctl2, ctl1}, InstanceKeys: []string{key2, key1}}
	const want = "sha256:ffcfba1425fc82016bc29d89371238c3dc661d79a738a1f80e0b7b61e0e12e56" // computed independently (python json sort_keys + sha256)
	if got := RequestDigest(&d, &r); got != want {
		t.Fatalf("RequestDigest = %s, want %s", got, want)
	}
}

// TestNoLocalClock (E10): no source file of the package reads the clock, and
// receipts consumed in 2001 and 2099 are honored alike, so moving the local
// clock forward or back never changes whether a receipt is honored.
func TestNoLocalClock(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	clock := regexp.MustCompile(`time\.(Now|Since|Until|Tick|After|NewTimer|NewTicker)\(`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if clock.Match(b) {
			t.Errorf("%s reads the local clock", f)
		}
	}
	for _, base := range []string{"2001-01-01T00:00:00Z", "2099-12-31T00:00:00Z"} {
		fx := fixture{Base: base}
		pol, v := build(t, &fx)
		if set, warns := Verify(pol, v); len(warns) != 0 || set.Len() != 1 {
			t.Errorf("base %s: %d honored, warnings %q; want 1, none", base, set.Len(), warns)
		}
	}
}

// TestNilSafe: a nil verdict, a nil set and a zero Policy honor nothing.
func TestNilSafe(t *testing.T) {
	set, warns := Verify(Policy{}, nil)
	if set.Len() != 0 || warns != nil {
		t.Fatalf("nil verdict: %d, %q", set.Len(), warns)
	}
	var s *Set
	if got := s.Honor(ctl1, key1, "fail"); got != nil {
		t.Fatal("nil set honored")
	}
	fx := fixture{}
	pol, v := build(t, &fx)
	pol.Coverable = nil
	set, _ = Verify(pol, v)
	if got := set.Honor(ctl1, key1, "fail"); got != nil {
		t.Fatal("nil coverability gate honored")
	}
}

// TestReceiptKeyRevokedByBundle: a receipt kid in the merged
// bundle revocations.json is never honored, as one in revoked_kids; the
// zero-value set honors none.
func TestReceiptKeyRevokedByBundle(t *testing.T) {
	pol, v := build(t, &fixture{})
	if set, warns := Verify(pol, v); set.Len() != 1 || len(warns) != 0 {
		t.Fatalf("baseline fixture: %d honored, warnings %q", set.Len(), warns)
	}
	kid := pol.Profile.BreakGlass.ReceiptKeys[0].KID
	revoked, err := trust.ParseRevocations([]byte(`{"format":"compliancetf.revocations/v1","epoch":1,"revoked_keys":[{"kid":"` + kid +
		`","revoked_at":"2026-10-01T00:00:00Z"}],"revoked_bundles":[],"revoked_controls":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	for name, revs := range map[string]trust.Revocations{"revocations.json": revoked, "zero value": {}} {
		pol.Revocations = revs
		set, warns := Verify(pol, v)
		if set.Len() != 0 || len(warns) != 1 || !strings.Contains(warns[0], "receipt signature invalid: kid revoked") {
			t.Errorf("%s: %d honored, warnings %q", name, set.Len(), warns)
		}
	}
}
