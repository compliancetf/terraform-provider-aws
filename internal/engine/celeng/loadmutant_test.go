package celeng

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

// TestLoadMutant: the verify-only LoadMutant drops the iam polarity lint and
// nothing else, and never changes what Load accepts (shared AST cache).
func TestLoadMutant(t *testing.T) {
	neg := `!(iam.parse(resource.policy).statements.all(s, !(s.effect == "Allow" && iam.grants(s, "s3:putbucketpolicy"))))`
	ctl := func(expr string, mode bundle.PresenceMode) []bundle.Control {
		return []bundle.Control{{ID: "m", Version: "1.0.0", Kind: bundle.KindResource, ResourceType: "aws_s3_bucket_policy",
			Reads: []string{"policy"}, PresenceMode: mode, On: []bundle.On{bundle.OnCreate}, Expr: &expr,
			Action: bundle.ActionDeny, Severity: bundle.SeverityHigh, Message: "m"}}
	}
	e, s, content := New(testOpts), awsSubset(t), Content{IAMCatalog: fixtureCatalog(t)}
	lint := func(err error) bool {
		var d *LoadDiag
		return errors.As(err, &d) && d.Code == "control_iam_unconditional_polarity"
	}
	if _, _, err := e.Load(ctl(neg, bundle.PresenceEffective), s, content); !lint(err) {
		t.Fatalf("Load: %v, want control_iam_unconditional_polarity", err)
	}
	if _, _, err := e.LoadMutant(ctl(neg, bundle.PresenceEffective), s, content); err != nil {
		t.Fatalf("LoadMutant: %v", err)
	}
	if _, _, err := e.Load(ctl(neg, bundle.PresenceEffective), s, content); !lint(err) {
		t.Fatalf("Load after LoadMutant: %v, want control_iam_unconditional_polarity", err)
	}
	if _, _, err := Load(ctl(neg, bundle.PresenceEffective), s); !lint(err) {
		t.Fatalf("package Load after LoadMutant: %v", err)
	}
	// every other check stays on: an effective control reading config
	var d *LoadDiag
	cfg := strings.ReplaceAll(neg, "resource.policy", "config.policy")
	if _, _, err := e.LoadMutant(ctl(cfg, bundle.PresenceEffective), s, content); !errors.As(err, &d) || d.Code != "control_vars" {
		t.Fatalf("LoadMutant config in effective: %v, want control_vars", err)
	}
	if _, _, err := e.LoadMutant(ctl(neg, bundle.PresenceEffective), s, Content{}); !errors.As(err, &d) || d.Code != "iam_catalog_missing" {
		t.Fatalf("LoadMutant without catalog: %v, want iam_catalog_missing", err)
	}
}

// TestLoadMutantCallers: only the generator's verify uses LoadMutant; no
// provider package can reach the unlinted load. Any selector named
// LoadMutant counts (a call or a method value); inside celeng only
// evaluate.go, which declares it, may name it.
func TestLoadMutantCallers(t *testing.T) {
	root := "../../.."
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && rel != "." || d.Name() == "vendor" || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		for _, use := range loadMutantUses(t, p) {
			if !loadMutantAllowed(rel) {
				t.Errorf("%s:%d names LoadMutant; only internal/bundlegen may", rel, use)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func loadMutantAllowed(rel string) bool {
	return rel == "internal/engine/celeng/evaluate.go" || path.Dir(rel) == "internal/bundlegen"
}

// loadMutantUses returns the lines of every selector .LoadMutant in file p.
func loadMutantUses(t *testing.T, p string) []int {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var lines []int
	ast.Inspect(f, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "LoadMutant" {
			lines = append(lines, fset.Position(sel.Pos()).Line)
		}
		return true
	})
	return lines
}

// TestLoadMutantUsesMethodValue: the guard sees a method value, not only a
// call, and rejects it outside the allowed files.
func TestLoadMutantUsesMethodValue(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.go")
	src := "package x\n\nfunc f(e interface{ LoadMutant() }) { g := e.LoadMutant; _ = g }\n"
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := loadMutantUses(t, p); len(got) != 1 || got[0] != 3 {
		t.Fatalf("uses %v, want line 3", got)
	}
	for rel, want := range map[string]bool{"internal/proxy/x.go": false, "internal/engine/celeng/load.go": false,
		"internal/engine/celeng/evaluate.go": true, "internal/bundlegen/verify.go": true} {
		if loadMutantAllowed(rel) != want {
			t.Errorf("%s: allowed %v, want %v", rel, !want, want)
		}
	}
}
