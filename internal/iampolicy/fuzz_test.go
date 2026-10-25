package iampolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// FuzzNormalize: never panics; on error the policy is nil and the error
// text is one of the closed reason codes (so it cannot carry document
// bytes); output is deterministic; re-normalizing the re-serialized decoded
// document gives the same output; every *_all flag implies its *_any flag.
// go test ./internal/iampolicy -run '^$' -fuzz FuzzNormalize -fuzztime 60s
func FuzzNormalize(f *testing.F) {
	seeds, _ := filepath.Glob(filepath.Join(casesDir, "*.json"))
	for _, s := range seeds {
		if b, err := os.ReadFile(s); err == nil && !strings.HasSuffix(s, ".golden.json") {
			f.Add(string(b))
		}
	}
	c := loadFixture(f)
	f.Fuzz(func(t *testing.T, doc string) {
		if p, err := Normalize(doc, Options{Partition: "aws", Catalog: c}); err != nil {
			checkErr(t, p, err)
		} else if p.Catalog != c.Digest() {
			t.Fatal("expanded policy without the catalog digest")
		}
		o := Options{Partition: "aws"}
		p, err := Normalize(doc, o)
		if err != nil {
			checkErr(t, p, err)
			return
		}
		got := render(t, doc, o)
		if again := render(t, doc, o); !bytes.Equal(got, again) {
			t.Fatal("non-deterministic output")
		}
		for _, st := range p.Statements {
			if (st.ActionAll && !st.ActionAny) || (st.PrincipalAll && !st.PrincipalAny) || (st.ResourceAll && !st.ResourceAny) {
				t.Fatal("*_all without *_any")
			}
		}
		raw, err := decode(doc)
		if err != nil {
			t.Fatalf("decode failed after Normalize succeeded: %v", err)
		}
		re, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		if len(re) > MaxDocBytes {
			return // escaping can grow the document past the size limit
		}
		if again := render(t, string(re), o); !bytes.Equal(got, again) {
			t.Fatalf("re-serialized document normalizes differently:\n%s\n%s", got, again)
		}
	})
}

func checkErr(t *testing.T, p *Policy, err error) {
	t.Helper()
	var e *Error
	if p != nil || !errors.As(err, &e) || !slices.Contains(reasons, e.Reason) {
		t.Fatalf("bad error result: policy %v, error %v", p != nil, err)
	}
	if !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrLimit) {
		t.Fatalf("error %v wraps neither ErrInvalid nor ErrLimit", err)
	}
	if err.Error() != e.err.Error()+": "+e.Reason {
		t.Fatalf("error text %q is not class + reason", err)
	}
}

func TestLimits(t *testing.T) {
	stmt := `{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}`
	many := func(n int) string {
		return `{"Version":"2012-10-17","Statement":[` + strings.TrimSuffix(strings.Repeat(stmt+",", n), ",") + `]}`
	}
	big := `{"Version":"2012-10-17","Id":"` + strings.Repeat("x", MaxDocBytes) + `","Statement":[]}`
	for _, c := range []struct {
		name, doc string
		o         Options
		class     error
		reason    string
	}{
		{"doc_size", big, Options{}, ErrLimit, rDocSize},
		{"statement_count", many(MaxStatements + 1), Options{}, ErrLimit, rStatementCount},
		{"partition", many(1), Options{Partition: "aws:x"}, ErrInvalid, rPartition},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, err := Normalize(c.doc, c.o)
			checkErr(t, p, err)
			var e *Error
			if errors.As(err, &e); !errors.Is(err, c.class) || e.Reason != c.reason {
				t.Fatalf("got %v, want %v %s", err, c.class, c.reason)
			}
		})
	}
	if p, err := Normalize(many(MaxStatements), Options{}); err != nil || len(p.Statements) != MaxStatements {
		t.Fatalf("500 statements: %v", err)
	}
	doc := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"111111111111"},"Action":"kms:Decrypt","Resource":"*"}}`
	p, err := Normalize(doc, Options{Partition: "aws-cn"})
	if err != nil || p.Statements[0].Principals["aws"][0] != "arn:aws-cn:iam::111111111111:root" {
		t.Fatalf("aws-cn partition: %v %v", p, err)
	}
}
