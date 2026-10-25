package profile

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

var update = flag.Bool("update", false, "regenerate testdata/profiles fixtures")

const fixtureDir = "../../testdata/profiles"

// testKey is the derived ctftest profile key (testkeys.Profile): its public
// half is in keyring_test.json, so ctftest builds verify fixtures with the
// real trust.Verify; release keyrings never contain it.
var testKey = testkeys.Profile()

func testKID() string {
	der, _ := x509.MarshalPKIXPublicKey(testKey.Public())
	return trust.KIDFromSPKI(der)
}

func signProfile(payload []byte) []byte {
	sig := ed25519.Sign(testKey, trust.PAE(trust.PayloadProfile, payload))
	b, _ := json.MarshalIndent(map[string]any{"payloadType": trust.PayloadProfile,
		"payload":    base64.StdEncoding.EncodeToString(payload),
		"signatures": []map[string]string{{"keyid": testKID(), "sig": base64.StdEncoding.EncodeToString(sig)}}}, "", "  ")
	return append(b, '\n')
}

func basePayload(version int, mut func(m map[string]any)) []byte {
	m := map[string]any{
		"format": Format, "org_id": "bobthecorp", "profile_version": version,
		"issued_at": "2026-10-01T00:00:00Z", "expires_at": "2026-10-30T00:00:00Z",
		"governed": false, "floor_mode": "online", "min_wrapper_version": "0.2.0",
		"mode_floor":       map[string]any{"default": "soft_fail", "environments": map[string]string{"prod": "hard_fail"}},
		"control_floors":   map[string]string{"bobthecorp-s3-001": "hard_fail"},
		"verdict_required": false,
		"bundles":          []map[string]any{{"bundle_id": "bobthecorp-soc2", "min_version": 3}},
		"exceptions": map[string]any{"coverable": map[string][]string{"bobthecorp-s3-001": {"grant", "self_service"}},
			"self_service": []string{"bobthecorp-s3-001"}, "max_lifetime_days": 30},
		"evidence": map[string]any{"required": true, "sinks": []any{}},
		"budgets":  map[string]any{"per_resource_ms": 200, "per_run_s": 120},
	}
	if mut != nil {
		mut(m)
	}
	b, _ := json.Marshal(m)
	return b
}

func TestGenerateProfiles(t *testing.T) {
	if !*update {
		t.Skip("run with -update to regenerate")
	}
	gk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	gder, _ := x509.MarshalPKIXPublicKey(gk.Public())
	_ = crypto.SHA256
	v7 := basePayload(7, func(m map[string]any) {
		m["governed"] = true
		m["exceptions"].(map[string]any)["grant_keys"] = []map[string]any{{"kid": trust.KIDFromSPKI(gder),
			"alg": "ES256", "spki_b64": base64.StdEncoding.EncodeToString(gder),
			"not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"}}
	})
	bad := signProfile(v7)
	var env map[string]any
	_ = json.Unmarshal(bad, &env)
	s := env["signatures"].([]any)[0].(map[string]any)
	raw, _ := base64.StdEncoding.DecodeString(s["sig"].(string))
	raw[0] ^= 1
	s["sig"] = base64.StdEncoding.EncodeToString(raw)
	bad, _ = json.MarshalIndent(env, "", "  ")
	files := map[string][]byte{
		"v7":      signProfile(v7),
		"v6":      signProfile(basePayload(6, nil)),
		"bad-sig": append(bad, '\n'),
		"expired": signProfile(basePayload(8, func(m map[string]any) {
			m["issued_at"], m["expires_at"] = "2026-08-01T00:00:00Z", "2026-08-30T00:00:00Z"
		})),
		"wrong-org": signProfile(basePayload(9, func(m map[string]any) { m["org_id"] = "bobthecorp-eu" })),
		"airgap-breakglass": signProfile(basePayload(9, func(m map[string]any) {
			m["floor_mode"], m["floor_airgap_path"] = "airgap", "/etc/compliancetf/floor.dsse.json"
			m["break_glass"] = map[string]any{"enabled": true}
		})),
		"scoped": signProfile(basePayload(5, func(m map[string]any) {
			m["scope"] = map[string]string{"environment": "prod", "workspace": "bobthecorp-app-prod"}
		})),
	}
	if err := os.MkdirAll(fixtureDir, 0o750); err != nil {
		t.Fatal(err)
	}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(fixtureDir, "bobthecorp-"+n+".dsse.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDir, "bobthecorp-"+name+".dsse.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseFixtures(t *testing.T) {
	for name, want := range map[string]string{
		"v7": "", "v6": "", "expired": "", "wrong-org": "", "scoped": "",
		"airgap-breakglass": "break_glass is unavailable with floor_mode airgap",
		"bad-sig":           "signature invalid",
	} {
		t.Run(name, func(t *testing.T) {
			v, err := verifyEnvelope(fixture(t, name), trust.NoRevocations())
			if err == nil {
				_, _, err = Parse(v.Payload)
			}
			if want == "" && err != nil || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
				t.Fatalf("err = %v, want %q", err, want)
			}
		})
	}
	v, _ := verifyEnvelope(fixture(t, "scoped"), trust.NoRevocations())
	p, _, _ := Parse(v.Payload)
	if p.Scope == nil || p.Scope.Environment != "prod" || p.Scope.Workspace != "bobthecorp-app-prod" {
		t.Fatalf("scope = %+v", p.Scope)
	}
}

// TestParseErrorsValueFree: profile parse errors name the field, never a
// value from the signed payload.
func TestParseErrorsValueFree(t *testing.T) {
	const marker = "BOBTHECORP-MARKER-2"
	ex := func(f func(e map[string]any)) func(m map[string]any) {
		return func(m map[string]any) { f(m["exceptions"].(map[string]any)) }
	}
	for name, mut := range map[string]func(m map[string]any){
		"format":        func(m map[string]any) { m["format"] = marker },
		"org_id":        func(m map[string]any) { m["org_id"] = marker },
		"min_wrapper":   func(m map[string]any) { m["min_wrapper_version"] = marker },
		"floor_mode":    func(m map[string]any) { m["floor_mode"] = marker },
		"issued_at":     func(m map[string]any) { m["issued_at"] = marker },
		"unknown field": func(m map[string]any) { m[marker] = 1 },
		"mode value":    func(m map[string]any) { m["control_floors"] = map[string]string{"x": marker} },
		"dup bundle": func(m map[string]any) {
			m["bundles"] = []map[string]any{{"bundle_id": marker, "min_version": 1}, {"bundle_id": marker, "min_version": 1}}
		},
		"coverable kind": ex(func(e map[string]any) { e["coverable"] = map[string][]string{marker: {marker}} }),
		"self_service":   ex(func(e map[string]any) { e["self_service"], e["forbid_controls"] = []string{marker}, []string{marker} }),
		"break_glass":    func(m map[string]any) { m["break_glass"] = map[string]any{"enabled": marker} },
		"data_sources":   func(m map[string]any) { m["data_sources"] = marker },
	} {
		_, _, err := Parse(basePayload(7, mut))
		if err == nil || strings.Contains(err.Error(), marker) {
			t.Errorf("%s: error %v", name, err)
		}
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]func(m map[string]any){
		"unknown field":           func(m map[string]any) { m["allow_degraded"] = true },
		"nested unknown field":    func(m map[string]any) { m["budgets"].(map[string]any)["x"] = 1 },
		"bad format":              func(m map[string]any) { m["format"] = "compliancetf.profile/v2" },
		"lifetime over 30 days":   func(m map[string]any) { m["expires_at"] = "2026-11-05T00:00:00Z" },
		"bad mode":                func(m map[string]any) { m["control_floors"] = map[string]string{"x": "strict"} },
		"floor_mode missing":      func(m map[string]any) { delete(m, "floor_mode") },
		"airgap path with online": func(m map[string]any) { m["floor_airgap_path"] = "/x" },
		"bad min_wrapper_version": func(m map[string]any) { m["min_wrapper_version"] = "latest" },
		"null coverable list": func(m map[string]any) {
			m["exceptions"].(map[string]any)["coverable"] = map[string]any{"bobthecorp-s3-001": nil}
		},
		"self_service forbidden case-insensitively": func(m map[string]any) {
			m["exceptions"].(map[string]any)["forbid_controls"] = []string{"BOBTHECORP-S3-001"}
		},
		"self_service forbidden": func(m map[string]any) {
			m["exceptions"].(map[string]any)["forbid_controls"] = []string{"bobthecorp-s3-001"}
		},
		"unknown exemption kind": func(m map[string]any) {
			m["exceptions"].(map[string]any)["coverable"] = map[string][]string{"bobthecorp-s3-001": {"waiver"}}
		},
		"grant key alg": func(m map[string]any) {
			m["exceptions"].(map[string]any)["grant_keys"] = []map[string]any{{"kid": "sha256:00", "alg": "RS256",
				"spki_b64": "AA==", "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"}}
		},
		"duplicate bundle": func(m map[string]any) {
			m["bundles"] = []map[string]any{{"bundle_id": "a", "min_version": 1}, {"bundle_id": "a", "min_version": 2}}
		},
		"trailing data":        nil,
		"org charset":          func(m map[string]any) { m["org_id"] = "../etc" },
		"break_glass not bool": func(m map[string]any) { m["break_glass"] = map[string]any{"enabled": "yes"} },
		"version zero":         func(m map[string]any) { m["profile_version"] = 0 },
		"bad data_sources":     func(m map[string]any) { m["data_sources"] = "hard_fail" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			payload := basePayload(7, mut)
			if mut == nil {
				payload = append(payload, ']')
			}
			if _, _, err := Parse(payload); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	ed := basePayload(7, func(m map[string]any) {
		der, _ := x509.MarshalPKIXPublicKey(testKey.Public())
		m["exceptions"].(map[string]any)["grant_keys"] = []map[string]any{{"kid": trust.KIDFromSPKI(der), "alg": "Ed25519",
			"spki_b64": base64.StdEncoding.EncodeToString(der), "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"}}
	})
	if _, _, err := Parse(ed); (err == nil) != allowEd25519 {
		t.Fatalf("Ed25519 grant key with allowEd25519=%v: %v", allowEd25519, err)
	}
	for _, v := range []string{"advisory", "deny"} {
		p, _, err := Parse(basePayload(7, func(m map[string]any) { m["data_sources"] = v }))
		if err != nil || p.DataSources != v {
			t.Fatalf("data_sources %s: %v", v, err)
		}
	}
	_, warns, err := Parse(basePayload(7, func(m map[string]any) { m["budgets"] = map[string]any{"per_resource_ms": 1} }))
	if err != nil || len(warns) != 1 {
		t.Fatalf("clamp: %v %v", warns, err)
	}
}

func TestCheckWrapper(t *testing.T) {
	for _, c := range []struct {
		v, min string
		ok     bool
	}{
		{"0.3.0", "0.2.0", true}, {"v0.2.0", "0.2.0", true}, {"0.1.9", "0.2.0", false},
		{"0.2.0-rc.1", "0.2.0", false}, {"0.2.0-rc.9", "0.2.0-rc.10", false}, {"0.2.0-rc.10", "0.2.0-rc.10", true}, {"0.2.0", "0.2.0-rc.10", true}, {"dev", "0.2.0", false}, {"dev", "", true}, {"1.10.0", "1.9.0", true},
	} {
		err := CheckWrapper(c.v, c.min)
		if (err == nil) != c.ok {
			t.Errorf("CheckWrapper(%q, %q) = %v", c.v, c.min, err)
		}
	}
}
