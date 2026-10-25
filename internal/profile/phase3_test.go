package profile

import (
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// p256Key derives a public P-256 test key from a label; only its SPKI is used.
func p256Key(label string) []byte {
	s := sha256.Sum256([]byte(label))
	k, err := ecdh.P256().NewPrivateKey(s[:])
	if err != nil {
		panic(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(k.PublicKey())
	return der
}

func signerKey(label, use string) map[string]any {
	der := p256Key(label)
	return map[string]any{"kid": trust.KIDFromSPKI(der), "alg": "ES256", "use": use,
		"spki_b64": base64.StdEncoding.EncodeToString(der), "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"}
}

// phase3 sets every verdict, baseline, break_glass and revoked_kids field
// to a valid value.
func phase3(m map[string]any) {
	m["verdict"] = map[string]any{"public_keys": []any{signerKey("verdict-a", "verdict"), signerKey("verdict-b", "verdict")},
		"max_ttl": "48h", "graph_unknown": "block"}
	m["baseline"] = map[string]any{"public_keys": []any{signerKey("baseline-a", "baseline")}, "max_days": 90}
	m["break_glass"] = map[string]any{"enabled": true, "receipt_keys": []any{signerKey("receipt-a", "receipt")}}
	m["revoked_kids"] = []string{trust.KIDFromSPKI(p256Key("verdict-old"))}
}

// TestParsePhase3Fields: the verdict, baseline, break_glass and
// revoked_kids fields decode into typed values; key windows end at the
// profile's expires_at; max_ttl defaults to 24h.
func TestParsePhase3Fields(t *testing.T) {
	p, _, err := Parse(basePayload(7, phase3))
	if err != nil {
		t.Fatal(err)
	}
	v, b, bg := p.Verdict, p.Baseline, p.BreakGlass
	if v == nil || len(v.PublicKeys) != 2 || v.PublicKeys[0].KID != trust.KIDFromSPKI(p256Key("verdict-a")) ||
		v.GraphUnknown != GraphUnknownBlock || p.GraphUnknown() != GraphUnknownBlock || p.VerdictTTL() != 48*time.Hour {
		t.Fatalf("verdict %+v", v)
	}
	if !v.PublicKeys[0].NotAfter.Equal(p.ExpiresAt) {
		t.Fatalf("key window not limited to expires_at: %v", v.PublicKeys[0].NotAfter)
	}
	if b == nil || len(b.PublicKeys) != 1 || b.MaxDays != 90 || bg == nil || !bg.Enabled || len(bg.ReceiptKeys) != 1 ||
		len(p.RevokedKIDs) != 1 {
		t.Fatalf("baseline %+v break_glass %+v revoked %v", b, bg, p.RevokedKIDs)
	}
	p, _, err = Parse(basePayload(7, func(m map[string]any) { m["verdict"] = map[string]any{} }))
	if err != nil || p.VerdictTTL() != DefaultVerdictTTL || p.Verdict.GraphUnknown != GraphUnknownPending {
		t.Fatalf("defaults: %v %+v", err, p)
	}
	p, _, err = Parse(basePayload(7, func(m map[string]any) {
		m["break_glass"] = map[string]any{"enabled": true}
		delete(m, "floor_mode")
		delete(m, "bundles")
	}))
	if err != nil || !p.BreakGlass.Enabled || len(p.BreakGlass.ReceiptKeys) != 0 {
		t.Fatalf("enabled without floor_mode or receipt keys honors nothing and loads as before: %v", err)
	}
	if p, _, err = Parse(basePayload(7, nil)); err != nil || p.Verdict != nil || p.Baseline != nil || p.BreakGlass != nil ||
		p.VerdictTTL() != DefaultVerdictTTL || p.GraphUnknown() != GraphUnknownPending {
		t.Fatalf("absent: %v %+v", err, p)
	}
	var none *Profile
	if none.VerdictTTL() != DefaultVerdictTTL || none.GraphUnknown() != GraphUnknownPending {
		t.Fatal("nil profile: want the defaults")
	}
}

// TestParsePhase3Rejects: every verdict gate field rule fails closed with an error that
// names the field and never a value of the signed payload.
func TestParsePhase3Rejects(t *testing.T) {
	const marker = "BOBTHECORP-MARKER-3"
	key := func(block, list string, i int, f func(k map[string]any)) func(m map[string]any) {
		return func(m map[string]any) {
			phase3(m)
			f(m[block].(map[string]any)[list].([]any)[i].(map[string]any))
		}
	}
	set := func(block, field string, v any) func(m map[string]any) {
		return func(m map[string]any) {
			phase3(m)
			m[block].(map[string]any)[field] = v
		}
	}
	for name, tc := range map[string]struct {
		mut  func(m map[string]any)
		want string
	}{
		"verdict unknown field":    {set("verdict", marker, 1), "unknown member"},
		"verdict not object":       {func(m map[string]any) { m["verdict"] = marker }, "unknown member"},
		"baseline unknown field":   {set("baseline", "max_ttl", "24h"), "unknown member"},
		"break_glass unknown":      {set("break_glass", "approvers", 2), "unknown member"},
		"key unknown field":        {key("verdict", "public_keys", 0, func(k map[string]any) { k["comment"] = marker }), "unknown member"},
		"enabled not bool":         {set("break_glass", "enabled", marker), "unknown member"},
		"max_ttl over 72h":         {set("verdict", "max_ttl", "73h"), "verdict.max_ttl"},
		"max_ttl zero":             {set("verdict", "max_ttl", "0s"), "verdict.max_ttl"},
		"max_ttl negative":         {set("verdict", "max_ttl", "-1h"), "verdict.max_ttl"},
		"max_ttl not duration":     {set("verdict", "max_ttl", marker), "verdict.max_ttl"},
		"max_ttl number":           {set("verdict", "max_ttl", 86400), "unknown member"},
		"graph_unknown other":      {set("verdict", "graph_unknown", marker), "verdict.graph_unknown"},
		"max_days zero with keys":  {set("baseline", "max_days", 0), "baseline.max_days"},
		"max_days negative":        {set("baseline", "max_days", -1), "baseline.max_days"},
		"verdict key use baseline": {key("verdict", "public_keys", 0, func(k map[string]any) { k["use"] = "baseline" }), "verdict.public_keys 0: use must be verdict"},
		"baseline key use verdict": {key("baseline", "public_keys", 0, func(k map[string]any) { k["use"] = "verdict" }), "baseline.public_keys 0: use must be baseline"},
		"receipt key use missing":  {key("break_glass", "receipt_keys", 0, func(k map[string]any) { delete(k, "use") }), "break_glass.receipt_keys 0: use must be receipt"},
		"key alg":                  {key("verdict", "public_keys", 1, func(k map[string]any) { k["alg"] = "RS256" }), "verdict.public_keys 1: alg not allowed"},
		"key kid mismatch": {key("baseline", "public_keys", 0, func(k map[string]any) {
			k["kid"] = trust.KIDFromSPKI(p256Key(marker))
		}), "baseline.public_keys 0: kid does not match spki_b64"},
		"key spki not base64": {key("break_glass", "receipt_keys", 0, func(k map[string]any) { k["spki_b64"] = marker }), "kid does not match spki_b64"},
		"key empty window": {key("verdict", "public_keys", 0, func(k map[string]any) {
			k["not_before"] = "2026-10-30T00:00:00Z"
		}), "verdict.public_keys 0: empty validity window"},
		"duplicate kid": {func(m map[string]any) {
			phase3(m)
			m["verdict"].(map[string]any)["public_keys"] = []any{signerKey("verdict-a", "verdict"), signerKey("verdict-a", "verdict")}
		}, "verdict.public_keys 1: duplicate kid"},
		"enabled airgap": {func(m map[string]any) {
			phase3(m)
			m["floor_mode"] = "airgap"
		}, "break_glass is unavailable with floor_mode airgap"},
		"revoked kid bad": {func(m map[string]any) { m["revoked_kids"] = []string{marker} }, "revoked_kids: bad or duplicate entry 0"},
		"revoked kid duplicate": {func(m map[string]any) {
			phase3(m)
			m["revoked_kids"] = append(m["revoked_kids"].([]string), m["revoked_kids"].([]string)[0])
		}, "revoked_kids: bad or duplicate entry 1"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := Parse(basePayload(7, tc.mut))
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), marker) {
				t.Fatalf("err = %v, want %q and no value", err, tc.want)
			}
		})
	}
}
