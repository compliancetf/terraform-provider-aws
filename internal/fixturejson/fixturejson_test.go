package fixturejson

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestStringErrorValueFree: a wrong fixture string names the expected type,
// never the value.
func TestStringErrorValueFree(t *testing.T) {
	for _, raw := range []string{`1234567890`, `{"k": "bobthecorp-secret"}`, `"bobthecorp-secret`} {
		_, _, err := String(json.RawMessage(raw))
		if err == nil || strings.Contains(err.Error(), "1234567890") || strings.Contains(err.Error(), "bobthecorp-secret") {
			t.Fatalf("%s: %v", raw, err)
		}
	}
	if s, known, err := String(json.RawMessage(`"eu-west-1"`)); s != "eu-west-1" || !known || err != nil {
		t.Fatalf("got %q %v %v", s, known, err)
	}
	if _, known, err := String(json.RawMessage(`{"$unknown": true}`)); known || err != nil {
		t.Fatalf("unknown: %v %v", known, err)
	}
}
