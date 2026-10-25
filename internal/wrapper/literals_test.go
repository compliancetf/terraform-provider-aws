package wrapper

import (
	"bufio"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// awsLiterals are the provider identity strings that must come from
// wrapper.json.
var awsLiterals = []string{"hashicorp/aws", "terraform-provider-aws", "aws_"}

// allowedLiterals are format enum values that contain "aws_" without naming
// this wrapper's identity: the bundle tool slug for AWS Config and the
// wrapper.json verdict_kms value every wrapper accepts.
var allowedLiterals = []string{"aws_config", "aws_kms"}

// TestNoAWSLiterals: no string literal in a non-test .go file of a
// package the provider binary links names the aws wrapper; the identity
// comes from wrapper.json through Config. Import paths and the module path
// (which embeds terraform-provider-aws, also inside generated proto
// descriptors) are not identity. Comments are not checked. Every file of a
// linked package is read, whatever its build tags.
func TestNoAWSLiterals(t *testing.T) {
	root := filepath.Join("..", "..")
	mod := modulePath(t, root)
	seen := map[string]bool{}
	queue := []string{mod}
	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]
		if seen[pkg] {
			continue
		}
		seen[pkg] = true
		dir := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(strings.TrimPrefix(pkg, mod), "/")))
		imports, err := linkedImports(dir)
		if err != nil {
			t.Fatalf("%s: %v", pkg, err)
		}
		for _, imp := range imports {
			if imp == mod || strings.HasPrefix(imp, mod+"/") {
				queue = append(queue, imp)
			}
		}
		found, err := findLiterals(dir, mod)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range found {
			t.Errorf("%s: take it from wrapper.Config", f)
		}
	}
	if !seen[mod+"/internal/proxy"] || !seen[mod+"/internal/lifecycle"] {
		t.Fatalf("the import walk missed the proxy or lifecycle: %d packages", len(seen))
	}
}

// buildTags are the tag sets a provider binary is built with: release,
// conformance and ctftest.
var buildTags = [][]string{nil, {"conformance"}, {"ctftest"}, {"ctftest", "conformance"}}

// linkedImports is the union of dir's imports under every buildTags set, so
// a package only a tagged file imports is walked too.
func linkedImports(dir string) ([]string, error) {
	var imports []string
	var lastErr error
	ok := false
	for _, tags := range buildTags {
		ctx := build.Default
		ctx.BuildTags = tags
		bp, err := ctx.ImportDir(dir, 0)
		if err != nil {
			var noGo *build.NoGoError
			if errors.As(err, &noGo) {
				lastErr = err
				continue
			}
			return nil, err
		}
		ok = true
		imports = append(imports, bp.Imports...)
	}
	if !ok {
		return nil, lastErr
	}
	return imports, nil
}

// findLiterals lists each identity string literal in the non-test .go files
// of dir, with its position.
func findLiterals(dir, mod string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var found []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		imports := map[*ast.BasicLit]bool{}
		for _, is := range f.Imports {
			imports[is.Path] = true
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING || imports[lit] {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				s = lit.Value
			}
			if slices.Contains(allowedLiterals, s) {
				return true
			}
			s = strings.ReplaceAll(s, mod, "")
			for _, w := range awsLiterals {
				if strings.Contains(s, w) {
					found = append(found, fmt.Sprintf("%s: string literal contains %q", fset.Position(lit.Pos()), w))
				}
			}
			return true
		})
	}
	return found, nil
}

func modulePath(t *testing.T, root string) string {
	t.Helper()
	f, err := os.Open(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m, ok := strings.CutPrefix(sc.Text(), "module "); ok {
			return strings.TrimSpace(m)
		}
	}
	t.Fatal("go.mod has no module line")
	return ""
}

// TestLiteralGuardCatches: the scan flags a literal and skips what it must.
func TestLiteralGuardCatches(t *testing.T) {
	dir := t.TempDir()
	src := "package x\n\nimport _ \"example.com/m/terraform-provider-aws\"\n\n// hashicorp/aws in a comment\nvar a = \"aws_kms\"\nvar b = \"example.com/m\"\nvar c = `registry.terraform.io/hashicorp/aws`\n"
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	found, err := findLiterals(dir, "example.com/m")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || !strings.Contains(found[0], "x.go:8:") || !strings.Contains(found[0], `"hashicorp/aws"`) {
		t.Fatalf("findLiterals = %q, want only the var c literal", found)
	}
}

// TestLinkedImportsFollowsTags: an import only a conformance or ctftest file
// makes is walked, and an all-tagged package is not an error.
func TestLinkedImportsFollowsTags(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"a.go":           "package x\n\nimport _ \"example.com/m/plain\"\n",
		"b_conf.go":      "//go:build conformance\n\npackage x\n\nimport _ \"example.com/m/conf\"\n",
		"c_ctftest.go":   "//go:build ctftest\n\npackage x\n\nimport _ \"example.com/m/ctf\"\n",
		"tagged/only.go": "//go:build ctftest\n\npackage y\n\nimport _ \"example.com/m/only\"\n",
	}
	for name, src := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := linkedImports(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"example.com/m/plain", "example.com/m/conf", "example.com/m/ctf"} {
		if !slices.Contains(got, want) {
			t.Errorf("linkedImports = %q, missing %s", got, want)
		}
	}
	if got, err := linkedImports(filepath.Join(dir, "tagged")); err != nil || !slices.Contains(got, "example.com/m/only") {
		t.Errorf("all-tagged package: %q, %v", got, err)
	}
}
