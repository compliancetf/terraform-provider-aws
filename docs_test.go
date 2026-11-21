package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/lifecycle"
)

var envName = regexp.MustCompile(`^COMPLIANCETF_[A-Z0-9_]+$`)

// TestReferenceDocumentsSettings: every compliance {} attribute is in
// docs/reference.md, and every COMPLIANCETF_* variable the provider code
// names has a row in the variable table of docs/reference.md or, for test
// builds, of DEVELOPING.md.
func TestReferenceDocumentsSettings(t *testing.T) {
	ref := readDoc(t, "docs/reference.md")
	dev := readDoc(t, "DEVELOPING.md")

	for attr := range lifecycle.BlockType().AttributeTypes {
		if !strings.Contains(ref, "| `"+attr+"` |") {
			t.Errorf("compliance {} attribute %s has no row in docs/reference.md#configuration", attr)
		}
	}

	names := map[string]string{}
	for _, root := range []string{"main.go", "internal", "pkg"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				if s, err := strconv.Unquote(lit.Value); err == nil && envName.MatchString(s) {
					names[s] = path
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(names) == 0 {
		t.Fatal("no COMPLIANCETF_* variable found in the code")
	}

	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	for _, n := range sorted {
		if !strings.Contains(ref, "| `"+n+"` |") && !strings.Contains(dev, "| `"+n+"` |") {
			t.Errorf("%s (read in %s) is in neither docs/reference.md#environment-variables nor the DEVELOPING.md table", n, names[n])
		}
	}
}

func readDoc(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
