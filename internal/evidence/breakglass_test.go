package evidence

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestBreakGlassID: results[].break_glass_id is optional; an
// override_id token validates in the schema and the writer, anything else is
// refused by both.
func TestBreakGlassID(t *testing.T) {
	sch := compileSchema(t)
	evalLine := string(goodLines(t)[2])
	const at = `"decision":"logged"`
	if !strings.Contains(evalLine, at) {
		t.Fatalf("fixture lacks %s", at)
	}
	for id, ok := range map[string]bool{"ovr-01": true, "has space": false, "": false} {
		line := strings.Replace(evalLine, at, `"break_glass_id":"`+id+`","decision":"warning"`, 1)
		if err := validateLine(sch, []byte(line)); (err == nil) != ok {
			t.Errorf("schema on %q: %v, want ok %v", id, err, ok)
		}
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		// The writer omits an empty id, so it never writes the "" case.
		if err := validate(&r); (err == nil) != (ok || id == "") {
			t.Errorf("validate on %q: %v, want ok %v", id, err, ok)
		}
	}
}
