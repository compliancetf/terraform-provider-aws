package trust

import (
	"strings"
	"testing"
)

const sigMarker = "BOBTHECORP-MARKER-2"

// TestSignedParseErrorsValueFree: parse errors on signed payloads (floor
// statement, revocations, issued_at) name the field, never its value, and
// never carry decoder text that quotes the input.
func TestSignedParseErrorsValueFree(t *testing.T) {
	floor := func(k string, v any) []byte {
		return floorStatement("sha256:"+strings.Repeat("a", 64), func(p map[string]any) { p[k] = v })
	}
	for name, payload := range map[string][]byte{
		"format":           floor("format", sigMarker),
		"org_id":           floor("org_id", sigMarker),
		"keyring_digest":   floor("keyring_digest", sigMarker),
		"min_wrapper":      floor("min_wrapper_version", sigMarker),
		"bundles key":      floor("bundles", map[string]int64{sigMarker: 1}),
		"issued_at":        floor("issued_at", sigMarker),
		"expires_at":       floor("expires_at", sigMarker),
		"unknown field":    floor(sigMarker, 1),
		"wrong type value": floor("epoch", sigMarker),
	} {
		if _, err := parseFloor(payload); err == nil || strings.Contains(err.Error(), sigMarker) {
			t.Errorf("floor %s: error %v", name, err)
		}
	}
	rev := func(body string) string {
		return `{"format":"compliancetf.revocations/v1","epoch":1,` + body + `}`
	}
	kid := "sha256:" + strings.Repeat("a", 64)
	for name, doc := range map[string]string{
		"format":        strings.Replace(rev(`"revoked_keys":[]`), "compliancetf.revocations/v1", sigMarker, 1),
		"kid":           rev(`"revoked_keys":[{"kid":"` + sigMarker + `","revoked_at":"2026-01-01T00:00:00Z"}]`),
		"revoked_at":    rev(`"revoked_keys":[{"kid":"` + kid + `","revoked_at":"` + sigMarker + `"}]`),
		"dup bundle":    rev(`"revoked_bundles":[{"bundle_id":"` + sigMarker + `","below_version":1},{"bundle_id":"` + sigMarker + `","below_version":2}]`),
		"dup control":   rev(`"revoked_controls":[{"id":"` + sigMarker + `","version":1},{"id":"` + sigMarker + `","version":1}]`),
		"type mismatch": rev(`"revoked_keys":"` + sigMarker + `"`),
	} {
		if _, err := ParseRevocations([]byte(doc)); err == nil || strings.Contains(err.Error(), sigMarker) {
			t.Errorf("revocations %s: error %v", name, err)
		}
	}
	for _, p := range []string{`{"issued_at":"` + sigMarker + `"}`, `{"issued_at":["` + sigMarker + `"]}`} {
		if _, err := payloadIssuedAt([]byte(p)); err == nil || strings.Contains(err.Error(), sigMarker) {
			t.Errorf("issued_at %s: error %v", p, err)
		}
	}
}
