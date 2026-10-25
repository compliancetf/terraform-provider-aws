package lib

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
)

func TestJSONPath(t *testing.T) {
	doc := `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"]}],
		"a/b": 1, "m~n": 2, "": 3, "n": {"int": 7, "neg": -0, "float": 1.5, "exp": 1e2, "null": null, "t": true}}`
	runHelperCases(t, doc, []helperCase{
		{`json.path(v, "/Version")`, "2012-10-17", nil},
		{`json.path(v, "/Statement/0/Effect")`, "Allow", nil},
		{`json.path(v, "/Statement/0/Action/0")`, "s3:GetObject", nil},
		{`json.path(v, "/Statement/0/Action")`, []any{"s3:GetObject"}, nil},
		{`json.path(v, "/a~1b")`, int64(1), nil}, // RFC 6901 escapes
		{`json.path(v, "/m~0n")`, int64(2), nil},
		{`json.path(v, "/")`, int64(3), nil}, // the empty key
		{`json.path(v, "/n/int") == 7`, true, nil},
		{`json.path(v, "/n/neg") == 0`, true, nil},
		{`json.path(v, "/n/float") == 1.5`, true, nil},
		{`json.path(v, "/n/exp") == 100.0`, true, nil},
		{`json.path(v, "/n/t")`, true, nil},
		{`json.path(v, "") == json.path(v, "")`, true, nil}, // whole document
		// missing -> null
		{`json.path(v, "/Missing") == null`, true, nil},
		{`json.path(v, "/n/null") == null`, true, nil},
		{`json.path(v, "/Statement/1") == null`, true, nil},
		{`json.path(v, "/Statement/-") == null`, true, nil},
		{`json.path(v, "/Statement/99999999999999999999") == null`, true, nil},
		{`json.path(v, "/Version/x") == null`, true, nil}, // below a scalar
		{`json.path(v, "/Missing/x") == null`, true, nil},
		// malformed pointer: type_error, never a miss
		{`json.path(v, "Version")`, nil, ErrInvalid},
		{`json.path(v, "/a~2b")`, nil, ErrInvalid},
		{`json.path(v, "/a~")`, nil, ErrInvalid},
		{`json.path(v, "/Missing/a~2")`, nil, ErrInvalid}, // whole pointer checked before the walk
		{`json.path(v, "/Version/~")`, nil, ErrInvalid},
		{`json.path(v, "/Statement/00")`, nil, ErrInvalid},
		{`json.path(v, "/Statement/+0")`, nil, ErrInvalid},
		{`json.path(v, "/Statement/x")`, nil, ErrInvalid},
	})
	for name, bad := range map[string]string{
		"duplicate key":           `{"a": 1, "a": 2}`,
		"nested duplicate key":    `{"a": [{"b": 1, "b": 1}]}`,
		"escaped duplicate key":   `{"a": 1, "\u0061": 2}`,
		"trailing value":          `{"a": 1} {"a": 2}`,
		"trailing garbage":        `{"a": 1}x`,
		"truncated":               `{"a": 1`,
		"empty":                   ``,
		"not json":                `BOBTHECORP-MARKER-1`,
		"invalid utf-8":           "{\"a\": \"\xff\"}",
		"integer beyond int64":    `{"a": 9223372036854775808}`,
		"number beyond float64":   `{"a": 1e400}`,
		"single quotes":           `{'a': 1}`,
		"trailing comma":          `{"a": 1,}`,
		"duplicate key, deep hit": `{"x": {"a": 1, "a": 2}, "y": 1}`,
	} {
		t.Run(name, func(t *testing.T) {
			runHelperCases(t, bad, []helperCase{{`json.path(v, "/y")`, nil, ErrInvalid}})
		})
	}
	// scalars at the top level are documents too
	runHelperCases(t, `"BOBTHECORP-MARKER-2"`, []helperCase{{`json.path(v, "") == "BOBTHECORP-MARKER-2"`, true, nil}})
	// a null or non-string document is a type error, never null
	runHelperCases(t, nil, []helperCase{{`json.path(v, "/a")`, nil, errNoOverload}})
	runHelperCases(t, map[string]any{"a": 1}, []helperCase{{`json.path(v, "/a")`, nil, errNoOverload}})
}

// TestJSONPathSize: the 256 KiB limit is checked before decode, so an
// oversized malformed document is limit, never type_error.
func TestJSONPathSize(t *testing.T) {
	runHelperCases(t, sizedDoc(MaxDocBytes, false), []helperCase{{`json.path(v, "/a") != null`, true, nil}})
	runHelperCases(t, sizedDoc(MaxDocBytes+1, false), []helperCase{{`json.path(v, "/a")`, nil, ErrLimit}})
	runHelperCases(t, sizedDoc(MaxDocBytes+1, true), []helperCase{{`json.path(v, "/a")`, nil, ErrLimit}})
}

// TestJSONPathUnknown: an unknown document or pointer makes the call
// unknown, never a decided value (strict, as the other helpers).
func TestJSONPathUnknown(t *testing.T) {
	env, err := cel.NewEnv(Helpers(), JSON(), cel.Variable("v", cel.DynType), cel.Variable("p", cel.StringType))
	if err != nil {
		t.Fatal(err)
	}
	for _, expr := range []string{
		`json.path(v, "/a") == "x"`,
		`json.path(v, "/a") != "x"`,
		`json.path(v, "/a") == null`,
		`json.path("{\"a\": 1}", p) == 1`,
		`json.path("{\"a\": 1, \"a\": 2}", p) == 1`, // malformed but unknown pointer: still unknown, never pass
	} {
		t.Run(expr, func(t *testing.T) {
			a, iss := env.Compile(expr)
			if iss.Err() != nil {
				t.Fatal(iss.Err())
			}
			prg, err := env.Program(a, cel.EvalOptions(cel.OptPartialEval))
			if err != nil {
				t.Fatal(err)
			}
			vars, err := cel.PartialVars(map[string]any{"v": `{"a": "x"}`, "p": "/a"},
				cel.AttributePattern("v"), cel.AttributePattern("p"))
			if err != nil {
				t.Fatal(err)
			}
			got, _, _ := prg.Eval(vars)
			if !types.IsUnknown(got) {
				t.Fatalf("got %v, want unknown", got)
			}
		})
	}
}

// limitsCase is one testdata/crosscheck/limits case. The document is
// generated: doc_bytes long, valid or (malformed) with a duplicate key, so a
// limit result on a malformed document proves admission ran before decode.
type limitsCase struct {
	ID          string
	DocBytes    int  `json:"doc_bytes"`
	Malformed   bool `json:"malformed"`
	RemainingUS int  `json:"remaining_us"`
	Expect      struct {
		ErrClass string `json:"err_class"` // "", "limit" or "type_error"
	}
}

func TestJSONLimitsFixtures(t *testing.T) {
	for _, name := range []string{"doc_size", "admission"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "crosscheck", "limits", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var f struct {
			Format string
			Cases  []limitsCase
		}
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatal(err)
		}
		if f.Format != "compliancetf.lib-limits/v1" || len(f.Cases) == 0 {
			t.Fatalf("%s: format %q, %d cases", name, f.Format, len(f.Cases))
		}
		for _, tc := range f.Cases {
			t.Run(name+"/"+tc.ID, func(t *testing.T) {
				c := newDocCache(1 << 30)
				doc := sizedDoc(tc.DocBytes, tc.Malformed)
				_, err := c.path(doc, "/a", time.Duration(tc.RemainingUS)*time.Microsecond)
				want := map[string]error{"": nil, "limit": ErrLimit, "type_error": ErrInvalid}[tc.Expect.ErrClass]
				if !errors.Is(err, want) || (want == nil) != (err == nil) {
					t.Fatalf("got %v, want %v", err, want)
				}
				if decoded := c.decodes; tc.Expect.ErrClass == "limit" && decoded != 0 {
					t.Fatalf("limit after %d decodes; admission must run before decode", decoded)
				}
			})
		}
	}
}

// TestDocCache: one decode per distinct document, errors cached as their
// class, cleared and refilled when full, oversized documents never cached.
func TestDocCache(t *testing.T) {
	c := newDocCache(1300) // each test document costs entryBytes, its length and 2 * nodeBytes
	budget := 50 * time.Millisecond
	for range 3 {
		if v, err := c.path(`{"a": "x"}`, "/a", budget); err != nil || v != "x" {
			t.Fatalf("got %v, %v", v, err)
		}
		if _, err := c.path(`{"a": 1, "a": 2}`, "/a", budget); !errors.Is(err, ErrInvalid) {
			t.Fatalf("got %v", err)
		}
	}
	if c.decodes != 2 {
		t.Fatalf("%d decodes, want 2", c.decodes)
	}
	// a spent budget is limit even on a hit: never depends on cache state
	for _, spent := range []time.Duration{0, -time.Second} {
		if v, err := c.path(`{"a": "x"}`, "/a", spent); !errors.Is(err, ErrLimit) {
			t.Fatalf("hit with budget %v: %v, %v, want limit", spent, v, err)
		}
	}
	// filling past the cap clears the cache and refills it
	if _, err := c.path(`{"b": "`+strings.Repeat("y", 40)+`"}`, "/b", budget); err != nil {
		t.Fatal(err)
	}
	if _, err := c.path(`{"a": "x"}`, "/a", budget); err != nil || c.decodes != 4 {
		t.Fatalf("after clear: %v, %d decodes, want 4", err, c.decodes)
	}
	// a document larger than the cache is decoded every time, never stored
	big := `{"c": "` + strings.Repeat("z", 800) + `"}`
	for range 2 {
		if _, err := c.path(big, "/c", budget); err != nil {
			t.Fatal(err)
		}
	}
	if c.decodes != 6 || c.bytes > c.max {
		t.Fatalf("%d decodes, %d of %d bytes", c.decodes, c.bytes, c.max)
	}
	// dense documents are charged per decoded value, not per byte
	d := newDocCache(1 << 30)
	dense := "[" + strings.Repeat("1,", 999) + "1]"
	if _, err := d.path(dense, "/0", budget); err != nil || d.bytes != entryBytes+len(dense)+1001*nodeBytes {
		t.Fatalf("dense charge %d, %v", d.bytes, err)
	}
	// json documents are keyed apart from iam documents of the same text
	if jsonKey("iam", nil, "{}") == jsonKey("json", nil, "{}") {
		t.Fatal("kind is not part of the key")
	}
}

// TestDocCacheEntryOverhead: tiny distinct documents (error entries keep
// no tree) still pay the per-entry overhead, so the entry count, and with it
// the map's memory, stays bounded by the cap.
func TestDocCacheEntryOverhead(t *testing.T) {
	c := newDocCache(1 << 20)
	for i := range 20000 {
		c.path("x"+strconv.Itoa(i), "", time.Second)
	}
	if len(c.m) > c.max/entryBytes {
		t.Fatalf("%d entries in a %d-byte cache", len(c.m), c.max)
	}
}

// sizedDoc returns a document of exactly n bytes; malformed adds a
// duplicate key.
func sizedDoc(n int, malformed bool) string {
	head := `{"a":"`
	if malformed {
		head = `{"a":1,"a":"`
	}
	return head + strings.Repeat("x", n-len(head)-2) + `"}`
}

// TestJSONPathLiveDeadline: json.path admits against the
// evaluation's remaining budget (DeadlineVar), like iam.parse; a missing,
// spent or mistyped deadline admits nothing (fail closed).
func TestJSONPathLiveDeadline(t *testing.T) {
	env, err := cel.NewEnv(JSON(), cel.Variable("v", cel.StringType))
	if err != nil {
		t.Fatal(err)
	}
	a, iss := env.Compile(`json.path(v, "/a") == 1`)
	if iss.Err() != nil {
		t.Fatal(iss.Err())
	}
	prg, err := env.Program(a)
	if err != nil {
		t.Fatal(err)
	}
	for i, tc := range []struct {
		deadline any
		want     error
	}{
		{time.Now().Add(-time.Second), ErrLimit}, // spent
		{time.Now().Add(time.Minute), nil},
		{nil, ErrLimit},         // no entry
		{"tomorrow", ErrLimit},  // not a time.Time
		{time.Time{}, ErrLimit}, // zero deadline (ctx without one)
	} {
		vars := map[string]any{"v": fmt.Sprintf(`{"a": 1, "n": %d}`, i)} // new document: no cache hit
		if tc.deadline != nil {
			vars[DeadlineVar] = tc.deadline
		}
		out, _, err := prg.Eval(vars)
		if tc.want != nil {
			if !errors.Is(err, tc.want) {
				t.Fatalf("deadline %v: %v, %v, want %v", tc.deadline, out, err, tc.want)
			}
			continue
		}
		if err != nil || out != types.True {
			t.Fatalf("deadline %v: %v, %v, want true", tc.deadline, out, err)
		}
	}
}

// TestSetDocCacheBytes: the process cap (celeng Options.DocCacheBytes) is
// enforced: a smaller cap clears a cache already over it, a document that
// does not fit beside the cached one clears and refills, and a cap below one
// entry caches nothing.
func TestSetDocCacheBytes(t *testing.T) {
	t.Cleanup(func() { SetDocCacheBytes(DefaultDocCacheBytes) })
	SetDocCacheBytes(0) // empty
	SetDocCacheBytes(DefaultDocCacheBytes)
	deadline := time.Now().Add(time.Minute)
	doc := func(i int) string { return fmt.Sprintf(`{"a": %d}`, 1000+i) } // same length, 2 values each
	one := entryBytes + len(doc(0)) + 2*nodeBytes
	parse := func(i int) int {
		before := DocDecodes()
		if _, err := docs.path(doc(i), "/a", time.Until(deadline)); err != nil {
			t.Fatal(err)
		}
		return DocDecodes() - before
	}
	parse(0)
	parse(1)
	SetDocCacheBytes(one) // two entries cached: over the new cap, cleared
	if docs.bytes != 0 || len(docs.m) != 0 {
		t.Fatalf("over the new cap: %d bytes, %d entries, want cleared", docs.bytes, len(docs.m))
	}
	if n := parse(0) + parse(0); n != 1 {
		t.Fatalf("one entry fits: %d decodes, want 1", n)
	}
	if n := parse(1) + parse(0); n != 2 { // 1 clears 0
		t.Fatalf("second entry over the cap: %d decodes, want 2", n)
	}
	SetDocCacheBytes(one - 1)
	if n := parse(2) + parse(2); n != 2 {
		t.Fatalf("cap below one entry: %d decodes, want 2", n)
	}
}
