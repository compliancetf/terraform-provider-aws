package trust

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// TestCheckWrapperValueFree: the signed minimum's prerelease text is never
// echoed; its numeric core is.
func TestCheckWrapperValueFree(t *testing.T) {
	err := CheckWrapper("1.0.0", "2.0.0-BOBTHECORP-MARKER-2")
	if err == nil || err.Error() != "provider 1.0.0 is below the org minimum 2.0.0 prerelease" {
		t.Errorf("error %v", err)
	}
	if err := CheckWrapper("1.0.0", "x BOBTHECORP-MARKER-2"); err == nil || strings.Contains(err.Error(), "MARKER") {
		t.Errorf("error %v", err)
	}
}

func TestMaxWrapper(t *testing.T) {
	for _, c := range []struct{ a, b, want string }{
		{"", "", ""},
		{"", "1.0.0", "1.0.0"},
		{"1.5.0", "", "1.5.0"},
		{"1.5.0", "1.0.0", "1.5.0"},
		{"1.0.0", "1.5.0", "1.5.0"},
		{"1.10.0", "1.9.9", "1.10.0"},
		{"2.0.0-rc.1", "2.0.0", "2.0.0"},
		{"2.0.0", "2.0.0-rc.1", "2.0.0"},
		{"2.0.0-rc.1", "2.0.0-rc.2", "2.0.0"},
		{"2.0.0-rc.2", "2.0.0-rc.1", "2.0.0"},
		{"2.0.0-rc.1", "2.0.0-rc.1", "2.0.0-rc.1"},
		{"2.0.0-rc.1", "1.9.0", "2.0.0-rc.1"},
		{"1.9.0", "2.0.0-rc.1", "2.0.0-rc.1"},
		{"bogus", "1.0.0", "bogus"}, // fails closed in CheckWrapper
		{"1.0.0", "bogus", "bogus"},
		{"bogus", "worse", "worse"}, // lexically higher, either order
		{"worse", "bogus", "worse"},
	} {
		if got := maxWrapper(c.a, c.b); got != c.want {
			t.Errorf("maxWrapper(%q, %q) = %q, want %q", c.a, c.b, got, c.want)
		}
	}
}

// wrapperOrder is testdata/wrapper_order.json, the version parity order
// vectors; ctfkit pkg/verdict carries a byte-identical copy.
type wrapperOrder struct {
	Check []struct {
		V   string `json:"v"`
		Min string `json:"min"`
		OK  bool   `json:"ok"`
	} `json:"check"`
	Max []struct{ A, B, Want string } `json:"max"`
}

func loadWrapperOrder(t *testing.T) wrapperOrder {
	t.Helper()
	raw, err := os.ReadFile("testdata/wrapper_order.json")
	if err != nil {
		t.Fatal(err)
	}
	var w wrapperOrder
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	if len(w.Check) == 0 || len(w.Max) == 0 {
		t.Fatal("testdata/wrapper_order.json has no check or max vectors")
	}
	return w
}

func TestWrapperOrderVectors(t *testing.T) {
	w := loadWrapperOrder(t)
	for _, c := range w.Check {
		if err := CheckWrapper(c.V, c.Min); (err == nil) != c.OK {
			t.Errorf("CheckWrapper(%q, %q) = %v, want ok %v", c.V, c.Min, err, c.OK)
		}
	}
	for _, c := range w.Max {
		if got := maxWrapper(c.A, c.B); got != c.Want {
			t.Errorf("maxWrapper(%q, %q) = %q, want %q", c.A, c.B, got, c.Want)
		}
	}
}

// TestMaxWrapperLattice: the merged floor admits exactly what both floors
// admit, so the high-water is the same in any merge order.
func TestMaxWrapperLattice(t *testing.T) {
	vs := []string{"", "6.66.0-compliancetf.1", "6.67.0-beta.1", "6.67.0-beta.2", "6.67.0-rc.1", "6.67.0-rc.2",
		"6.67.0", "6.67.0-compliancetf.1", "6.67.0-compliancetf.2", "6.68.0-beta.1", "6.68.0",
		"6.67.0-beta.01", "6.67.0-compliancetf.01"}
	probes := slices.Concat(vs[1:], []string{"6.67.0-beta.3", "6.67.0-compliancetf.3", "6.69.0", "dev"})
	admits := func(m, v string) bool { return CheckWrapper(v, m) == nil }
	for _, a := range vs {
		for _, b := range vs {
			ab := maxWrapper(a, b)
			for _, v := range probes {
				if admits(ab, v) != (admits(a, v) && admits(b, v)) {
					t.Errorf("maxWrapper(%q, %q) = %q: admits %q %v", a, b, ab, v, admits(ab, v))
				}
			}
		}
	}
}

func TestCheckWrapperParityMessage(t *testing.T) {
	err := CheckWrapper("6.67.0", "6.67.0-compliancetf.1")
	if err == nil || err.Error() != "provider 6.67.0 is below the org minimum 6.67.0-compliancetf.1" {
		t.Errorf("error %v", err)
	}
}

// TestCheckWrapperNonCanonical: a non-canonical parity form is an "other"
// prerelease, below the release and never read as its canonical twin.
func TestCheckWrapperNonCanonical(t *testing.T) {
	for _, c := range []struct {
		v, m string
		ok   bool
	}{
		{"6.67.0", "6.67.0-compliancetf.01", true},
		{"6.67.0-compliancetf.01", "6.67.0-compliancetf.1", false},
		{"6.67.0-compliancetf.01", "6.67.0", false},
		{"6.67.0-compliancetf.1", "6.67.0-compliancetf.01", true},
	} {
		if err := CheckWrapper(c.v, c.m); (err == nil) != c.ok {
			t.Errorf("CheckWrapper(%q, %q) = %v, want ok %v", c.v, c.m, err, c.ok)
		}
	}
}
