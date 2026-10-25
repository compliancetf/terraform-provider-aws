package exceptions

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

const (
	org = "bobthecorp"
	ws  = "bobthecorp-reporting-prod"
	idp = "https://idp.bobthecorp.example"
)

var keyFrom, keyTo = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)

func spki(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func extKey(t *testing.T, k *ecdsa.PrivateKey, nb, na time.Time) trust.ExtKey {
	der := spki(t, k)
	return trust.ExtKey{KID: trust.KIDFromSPKI(der), Alg: trust.AlgES256, SPKI: der, NotBefore: nb, NotAfter: na}
}

func payload(mut func(map[string]any)) []byte {
	p := map[string]any{
		"format": Format, "grant_id": "bobthecorp-legacy-db", "org_id": org, "workspaces": []string{ws},
		"controls": []string{"rds_db_instance_encryption_at_rest_enabled", "CKV_AWS_16"},
		"selector": legacySelector,
		"reason":   "Migration ticket OPS-4411", "ticket": "OPS-4411",
		"approvers": []map[string]string{{"subject": "alice@bobthecorp.example", "issuer": idp},
			{"subject": "bob@bobthecorp.example", "issuer": idp + "/oidc"}},
		"content_digest": "sha256:" + strings.Repeat("ab", 32), "floor_epoch": 0,
		"issued_at": "2026-10-01T00:00:00Z", "expires_at": "2027-03-31T00:00:00Z",
	}
	if mut != nil {
		mut(p)
	}
	b, _ := json.Marshal(p)
	return b
}

func approvers(a ...string) func(map[string]any) {
	return func(p map[string]any) {
		var l []map[string]string
		for i := 0; i < len(a); i += 2 {
			l = append(l, map[string]string{"subject": a[i], "issuer": a[i+1]})
		}
		p["approvers"] = l
	}
}

// legacySelector is the grant and sidecar selector of the goldens.
const legacySelector = "type == 'aws_db_instance' && resource.identifier.matches('^legacy-')"

func selector(v any) func(map[string]any) {
	return func(p map[string]any) { p["selector"] = v }
}

// TestGrantPayload pins the grant payload format and the approver rule.
func TestGrantPayload(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(map[string]any)
		ok   bool
	}{
		{"good", nil, true},
		{"unscoped", func(p map[string]any) { delete(p, "workspaces") }, true},
		{"selector without type", selector("resource.identifier == 'x'"), true},
		{"dyn selector", selector("resource.storage_encrypted"), true},
		{"single approver", approvers("alice@bobthecorp.example", idp), false},
		{"same subject twice", approvers("alice@bobthecorp.example", idp, "ALICE@bobthecorp.example", idp+"/x"), false},
		{"issuer with port", approvers("a", idp+":8443", "b", idp), false},
		{"issuer upper-case host", approvers("a", "https://IDP.bobthecorp.example", "b", idp), false},
		{"issuer trailing slash", approvers("a", idp+"/", "b", idp), false},
		{"issuer http", approvers("a", "http://idp.bobthecorp.example", "b", idp), false},
		{"issuer dot segment", approvers("a", idp+"/../x", "b", idp), false},
		{"issuer userinfo", approvers("a", "https://u@idp.bobthecorp.example", "b", idp), false},
		{"issuer query", approvers("a", idp+"?x=1", "b", idp), false},
		{"subject with space", approvers("alice smith", idp, "b", idp), false},
		{"unknown member", func(p map[string]any) { p["coverable"] = []string{"grant"} }, false},
		{"null selector", selector(nil), false},
		{"null optional", func(p map[string]any) { p["workspaces"] = nil }, false},
		{"missing member", func(p map[string]any) { delete(p, "content_digest") }, false},
		{"missing selector", func(p map[string]any) { delete(p, "selector") }, false},
		{"floor_epoch fraction", func(p map[string]any) { p["floor_epoch"] = json.Number("1.0") }, false},
		{"floor_epoch exponent", func(p map[string]any) { p["floor_epoch"] = json.Number("1e3") }, false},
		{"floor_epoch negative", func(p map[string]any) { p["floor_epoch"] = -1 }, false},
		{"duplicate control folded", func(p map[string]any) { p["controls"] = []string{"CKV_AWS_16", "ckv_aws_16"} }, false},
		{"no controls", func(p map[string]any) { p["controls"] = []string{} }, false},
		{"duplicate workspace", func(p map[string]any) { p["workspaces"] = []string{ws, ws} }, false},
		{"empty workspace", func(p map[string]any) { p["workspaces"] = []string{""} }, false},
		{"v0.1 selector object", selector(map[string]any{"resource_type": "aws_db_instance",
			"match": []map[string]string{{"path": "identifier", "op": "regex_match", "value": "^legacy-"}}}), false},
		{"empty selector", selector(""), false},
		{"selector syntax error", selector("type == "), false},
		{"selector not bool", selector("1"), false},
		{"selector unknown variable", selector("nope == 1"), false},
		{"selector calls iam", selector("iam.grants(resource, 's3:GetObject')"), false},
		{"wrong format", func(p map[string]any) { p["format"] = "compliancetf.exception-grant/v2" }, false},
		{"expires before issued", func(p map[string]any) { p["expires_at"] = "2026-09-01T00:00:00Z" }, false},
		{"bad content digest", func(p map[string]any) { p["content_digest"] = "sha256:AB" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, err := parse(payload(tc.mut))
			if err == nil {
				err = checkApprovers(g.Approvers)
			}
			if (err == nil) != tc.ok {
				t.Fatalf("err %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

// TestGrantKeyPurpose: a profile grant key verifies exception grants only,
// may not shadow a compiled kid and needs a window.
func TestGrantKeyPurpose(t *testing.T) {
	kms := testkeys.CustomerKMS()
	emb, err := trust.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	kr, err := trust.ExceptionKeyring(emb, []trust.ExtKey{extKey(t, kms, keyFrom, keyTo)})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"issued_at":"2026-10-01T00:00:00Z"}`)
	sum := sha256.Sum256(trust.PAE(trust.PayloadProfile, body))
	sig, err := kms.Sign(nil, sum[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	env, _ := json.Marshal(map[string]any{"payloadType": trust.PayloadProfile, "payload": base64.StdEncoding.EncodeToString(body),
		"signatures": []map[string]string{{"keyid": trust.KIDFromSPKI(spki(t, kms)), "sig": base64.StdEncoding.EncodeToString(sig)}}})
	if _, err := kr.Verify(env, trust.PayloadProfile, trust.NoRevocations()); err == nil {
		t.Fatal("grant key verified a profile")
	}
	exc := extKey(t, testkeys.Exception(), keyFrom, keyTo)
	withExc, err := trust.ExceptionKeyring(emb, []trust.ExtKey{exc})
	if err != nil {
		t.Fatal(err)
	}
	mismatch := extKey(t, kms, keyFrom, keyTo)
	mismatch.KID = exc.KID
	for _, tc := range []struct {
		name string
		base *trust.Keyring
		ext  []trust.ExtKey
	}{
		{"inverted window", emb, []trust.ExtKey{extKey(t, kms, keyTo, keyFrom)}},
		{"zero window", emb, []trust.ExtKey{extKey(t, kms, time.Time{}, keyTo)}},
		{"duplicate", emb, []trust.ExtKey{extKey(t, kms, keyFrom, keyTo), extKey(t, kms, keyFrom, keyTo)}},
		{"shadows compiled", withExc, []trust.ExtKey{exc}},
		{"kid mismatch", emb, []trust.ExtKey{mismatch}},
	} {
		if _, err := trust.ExceptionKeyring(tc.base, tc.ext); err == nil {
			t.Errorf("%s accepted", tc.name)
		}
	}
}

func FuzzParseGrant(f *testing.F) {
	f.Add(payload(nil))
	f.Add([]byte(`{"format":null}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if g, err := parse(b); err == nil && (g.Format != Format || len(g.Controls) == 0 || g.sel == nil) {
			t.Fatalf("accepted an incomplete grant: %+v", g)
		}
	})
}
