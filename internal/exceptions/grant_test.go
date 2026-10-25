package exceptions

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

var update = flag.Bool("update", false, "regenerate testdata/grants")

var now = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

// compiled stands in for the compiled keyring: the embedded keys plus the
// test exception key (keyring_test.json has no exception key).
func compiled(t *testing.T) *trust.Keyring {
	t.Helper()
	emb, err := trust.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	kr, err := trust.ExceptionKeyring(emb, []trust.ExtKey{extKey(t, testkeys.Exception(), keyFrom, keyTo)})
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func grantKey(t *testing.T, k *ecdsa.PrivateKey) profile.GrantKey {
	der := spki(t, k)
	return profile.GrantKey{KID: trust.KIDFromSPKI(der), Alg: trust.AlgES256, SPKIB64: base64.StdEncoding.EncodeToString(der),
		NotBefore: keyFrom, NotAfter: keyTo}
}

// table is the mode table for a bobthecorp profile with the given trusted
// scope and grant keys, plus untrusted local values.
func table(t *testing.T, scope *profile.Scope, ex profile.Exceptions, localWS, localEnv string) profile.ModeTable {
	t.Helper()
	p := &profile.Profile{OrgID: org, Scope: scope, Exceptions: ex}
	mt, err := profile.ComputeModeTable(profile.TableInput{Resolution: profile.Resolution{OrgID: org, Fallback: profile.ProfileApplied, Profile: p},
		Workspace: localWS, EnvEnvironment: localEnv})
	if err != nil {
		t.Fatal(err)
	}
	return mt
}

func sign(t *testing.T, body []byte, signers ...crypto.Signer) []byte {
	t.Helper()
	sum := sha256.Sum256(trust.PAE(trust.PayloadExceptionGrant, body))
	var sigs []map[string]string
	for _, s := range signers {
		sig, err := s.Sign(nil, sum[:], crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		der, _ := x509.MarshalPKIXPublicKey(s.Public())
		sigs = append(sigs, map[string]string{"keyid": trust.KIDFromSPKI(der), "sig": base64.StdEncoding.EncodeToString(sig)})
	}
	b, _ := json.Marshal(map[string]any{"payloadType": trust.PayloadExceptionGrant,
		"payload": base64.StdEncoding.EncodeToString(body), "signatures": sigs})
	return b
}

// tamper replaces the payload of a signed envelope, keeping the signature.
func tamper(t *testing.T, env, body []byte) []byte {
	var e map[string]any
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	e["payload"] = base64.StdEncoding.EncodeToString(body)
	b, _ := json.Marshal(e)
	return b
}

func verifier(t *testing.T, mt profile.ModeTable) *Verifier {
	t.Helper()
	v, err := NewVerifier(VerifierInput{Compiled: compiled(t), Revocations: trust.NoRevocations(), Table: mt, OrgID: org, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func code(err error) string {
	var ge *GrantError
	if errors.As(err, &ge) {
		return ge.Code
	}
	if err != nil {
		return "other: " + err.Error()
	}
	return ""
}

// TestGrantFixtures is the oracle over testdata/grants.
func TestGrantFixtures(t *testing.T) {
	exc, kms := testkeys.Exception(), testkeys.CustomerKMS()
	good := sign(t, payload(nil), exc)
	gen := map[string][]byte{
		"good":         good,
		"customer-kms": sign(t, payload(nil), kms),
		"forged-approver": tamper(t, good, payload(func(p map[string]any) {
			p["approvers"] = []map[string]string{{"subject": "mallory@bobthecorp.example", "issuer": "https://idp.bobthecorp.example"},
				{"subject": "bob@bobthecorp.example", "issuer": "https://idp.bobthecorp.example/oidc"}}
		})),
		"widened-selector": tamper(t, good, payload(func(p map[string]any) {
			p["selector"] = "type == 'aws_db_instance'"
		})),
		"expired":           sign(t, payload(func(p map[string]any) { p["expires_at"] = "2026-10-05T00:00:00Z" }), exc),
		"wrong-workspace":   sign(t, payload(func(p map[string]any) { p["workspaces"] = []string{"bobthecorp-other"} }), exc),
		"workspace-spoof":   good,
		"environment-spoof": sign(t, payload(func(p map[string]any) { delete(p, "workspaces"); p["environments"] = []string{"prod"} }), exc),
	}
	dir := filepath.Join("testdata", "grants")
	scoped := table(t, &profile.Scope{Workspace: ws}, profile.Exceptions{GrantKeys: []profile.GrantKey{grantKey(t, kms)}}, "", "")
	for _, tc := range []struct {
		name, want string
		mt         profile.ModeTable
	}{
		{"good", "", scoped},
		{"customer-kms", "", scoped},
		{"forged-approver", CodeSignature, scoped},
		{"widened-selector", CodeSignature, scoped},
		{"expired", CodeExpired, scoped},
		{"wrong-workspace", CodeWrongWorkspace, scoped},
		// Spoofs: no trusted scope, only the local value names the grant's scope.
		{"workspace-spoof", CodeScopeUntrusted, table(t, nil, profile.Exceptions{}, ws, "")},
		{"environment-spoof", CodeScopeUntrusted, table(t, nil, profile.Exceptions{}, "", "prod")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".dsse.json")
			if *update {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(gen[tc.name], '\n'), 0o644); err != nil { //nolint:gosec // test fixture
					t.Fatal(err)
				}
			}
			env, err := os.ReadFile(path) //nolint:gosec // test fixture
			if err != nil {
				t.Fatal(err)
			}
			g, err := verifier(t, tc.mt).VerifyGrant(env)
			if got := code(err); got != tc.want {
				t.Fatalf("code %q, want %q (%v)", got, tc.want, err)
			}
			if tc.want == CodeScopeUntrusted && !errors.Is(err, profile.ErrScopeUntrusted) {
				t.Fatal("scope error does not wrap profile.ErrScopeUntrusted")
			}
			if tc.want == "" && (g.GrantID != "bobthecorp-legacy-db" || g.Digest == "" || g.PayloadDigest == "") {
				t.Fatalf("grant not filled: %+v", g)
			}
			if want := map[string]string{"good": SourceKeyring, "customer-kms": SourceProfile}[tc.name]; g.Source != want {
				t.Fatalf("source %q, want %q", g.Source, want)
			}
		})
	}
}

// TestGrantRules covers the rules beyond the named fixtures.
func TestGrantRules(t *testing.T) {
	exc, kms := testkeys.Exception(), testkeys.CustomerKMS()
	scoped := table(t, &profile.Scope{Workspace: ws, Environment: "prod"},
		profile.Exceptions{GrantKeys: []profile.GrantKey{grantKey(t, kms)}, ForbidEnvironmentScoped: []string{"ckv_aws_16"}}, "", "")
	with := func(f func(map[string]any)) []byte { return sign(t, payload(f), exc) }
	revs, err := trust.ParseRevocations([]byte(`{"format":"compliancetf.revocations/v1","epoch":1,"revoked_keys":[{"kid":"` +
		grantKey(t, kms).KID + `","revoked_at":"2026-09-01T00:00:00Z"}],"revoked_bundles":[],"revoked_controls":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		env  []byte
		want string
		in   func(*VerifierInput)
	}{
		{"unscoped grant", with(func(p map[string]any) { delete(p, "workspaces") }), "", nil},
		{"single approver", with(approvers("alice@bobthecorp.example", idp)), CodeApprovers, nil},
		{"bundle key signer", sign(t, payload(nil), testkeys.Bundle()), CodeSignature, nil},
		{"customer key not listed", sign(t, payload(nil), kms), CodeSignature, func(in *VerifierInput) {
			in.Table = table(t, &profile.Scope{Workspace: ws}, profile.Exceptions{}, "", "")
		}},
		{"revoked customer key", sign(t, payload(nil), kms), CodeSignature, func(in *VerifierInput) { in.Revocations = revs }},
		{"key not yet valid at now", sign(t, payload(nil), exc), CodeKeyNotValid, func(in *VerifierInput) { in.Now = keyFrom.Add(-time.Hour) }},
		// Key window pins: not_before is inclusive, not_after exclusive, and
		// the key check runs before expiry.
		{"key valid from not_before", with(dates(keyFrom, keyFrom.Add(time.Hour))), "", func(in *VerifierInput) { in.Now = keyFrom }},
		{"key valid until not_after", with(dates(keyTo.Add(-time.Hour), keyTo)), "", func(in *VerifierInput) { in.Now = keyTo.Add(-time.Nanosecond) }},
		{"key not valid at not_after", with(dates(keyTo.Add(-time.Hour), keyTo)), CodeKeyNotValid, func(in *VerifierInput) { in.Now = keyTo }},
		{"profile key not valid at now", sign(t, payload(nil), kms), CodeKeyNotValid, func(in *VerifierInput) { in.Now = keyTo.Add(time.Hour) }},
		// issued_at outside the key window: trust skips the signature.
		{"issued before key not_before", with(dates(keyFrom.Add(-time.Hour), keyFrom.Add(time.Hour))), CodeSignature, func(in *VerifierInput) { in.Now = keyFrom }},
		{"expires after key not_after", with(func(p map[string]any) { p["expires_at"] = "2028-06-01T00:00:00Z" }), CodeInvalid, nil},
		{"issued in the future", with(func(p map[string]any) { p["issued_at"] = "2026-10-06T12:10:00Z" }), CodeInvalid, nil},
		{"wrong org", with(func(p map[string]any) { p["org_id"] = "bobthecorp-other" }), CodeWrongOrg, nil},
		{"free tier", with(nil), CodeWrongOrg, func(in *VerifierInput) { in.OrgID = "" }},
		{"wrong environment", with(func(p map[string]any) { p["environments"] = []string{"staging"}; p["controls"] = []string{"x"} }), CodeWrongEnvironment, nil},
		{"environment scope forbidden (case-folded)", with(func(p map[string]any) { p["environments"] = []string{"prod"} }), CodeEnvironmentForbidden, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := VerifierInput{Compiled: compiled(t), Revocations: trust.NoRevocations(), Table: scoped, OrgID: org, Now: now}
			if tc.in != nil {
				tc.in(&in)
			}
			v, err := NewVerifier(in)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := v.VerifyGrant(tc.env); code(err) != tc.want {
				t.Fatalf("code %q, want %q (%v)", code(err), tc.want, err)
			}
		})
	}
}

// dates sets issued_at and expires_at.
func dates(issued, expires time.Time) func(map[string]any) {
	return func(p map[string]any) {
		p["issued_at"], p["expires_at"] = issued.Format(time.RFC3339), expires.Format(time.RFC3339)
	}
}

// TestGrantVerifierConfig: configuration faults are errors of NewVerifier,
// never a grant_signature on every grant.
func TestGrantVerifierConfig(t *testing.T) {
	emb, err := trust.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	shadow := grantKey(t, testkeys.Exception()) // same kid as a compiled key
	for _, tc := range []struct {
		name string
		in   VerifierInput
		want string
	}{
		{"nil keyring", VerifierInput{Revocations: trust.NoRevocations(), Now: now}, "other"},
		{"zero now", VerifierInput{Compiled: compiled(t), Revocations: trust.NoRevocations()}, "other"},
		{"invalid revocations", VerifierInput{Compiled: compiled(t), Now: now}, "other"},
		{"grant key shadows compiled kid", VerifierInput{Compiled: compiled(t), Revocations: trust.NoRevocations(), Now: now,
			Table: table(t, nil, profile.Exceptions{GrantKeys: []profile.GrantKey{shadow}}, "", "")}, CodeKeysInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewVerifier(tc.in)
			if got := code(err); got != tc.want && (tc.want != "other" || !strings.HasPrefix(got, "other")) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	v, err := NewVerifier(VerifierInput{Compiled: emb, Revocations: trust.NoRevocations(), Now: now, OrgID: org})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyGrant(sign(t, payload(nil), testkeys.Exception())); code(err) != CodeNoKeys {
		t.Fatalf("no exception keys: %v", err)
	}
}
