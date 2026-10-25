package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Same pattern as CRYPTO_RE in scripts/protected-paths.sh.
const cryptoRE = `[Cc][Rr][Yy][Pp][Tt][Oo]|filippo\.io/|github\.com/sigstore/|github\.com/cloudflare/circl|github\.com/theupdateframework/|github\.com/secure-systems-lab/|minisign`

// base has every block type; the long exclude and retract blocks put an edit
// near their end far from the block opener, where a diff hunk header no
// longer names the block.
const base = `module github.com/bobthecorp/app

go 1.26.2

toolchain go1.26.2

godebug (
	default=go1.26
	panicnil=1
)

require (
	github.com/bobthecorp/lib v1.0.0
	golang.org/x/crypto v0.30.0
	github.com/bobthecorp/other v1.0.0 // indirect
)

replace (
	github.com/bobthecorp/a => ../a
	github.com/bobthecorp/b v1.0.0 => github.com/bobthecorp/b v1.0.1
)

exclude (
	github.com/bobthecorp/e1 v1.0.0
	github.com/bobthecorp/e2 v1.0.0
	github.com/bobthecorp/e3 v1.0.0
	github.com/bobthecorp/e4 v1.0.0
	github.com/bobthecorp/e5 v1.0.0
	github.com/bobthecorp/e6 v1.0.0
	github.com/bobthecorp/e7 v1.0.0
	github.com/bobthecorp/e8 v1.0.0
)

retract (
	v0.1.0
	v0.2.0
	v0.3.0
	v0.4.0
	v0.5.0
	v0.6.0
	v0.7.0 // broken
)

tool (
	github.com/bobthecorp/gen
)
`

func TestCompare(t *testing.T) {
	re := regexp.MustCompile(cryptoRE)
	edit := func(from, to string) string {
		if !strings.Contains(base, from) {
			t.Fatalf("fixture lacks %q", from)
		}
		return strings.Replace(base, from, to, 1)
	}
	tests := []struct {
		name, after, want string
	}{
		{"unchanged", base, ""},
		{"require block plain bump", edit("lib v1.0.0", "lib v1.1.0"), ""},
		{"require plain add", edit("require (\n", "require (\n\tgithub.com/bobthecorp/new v1.0.0\n"), ""},
		{"require plain remove", edit("\tgithub.com/bobthecorp/other v1.0.0 // indirect\n", ""), ""},
		{"require indirect marker only", edit("other v1.0.0 // indirect", "other v1.0.0"), ""},
		{"require single line plain add", base + "require github.com/bobthecorp/solo v1.0.0\n", ""},
		{"comment only", edit("v0.7.0 // broken", "v0.7.0 // very broken"), ""},
		{"block reorder", edit("\tgithub.com/bobthecorp/e1 v1.0.0\n\tgithub.com/bobthecorp/e2 v1.0.0\n",
			"\tgithub.com/bobthecorp/e2 v1.0.0\n\tgithub.com/bobthecorp/e1 v1.0.0\n"), ""},
		{"require block crypto bump", edit("crypto v0.30.0", "crypto v0.31.0"), "crypto dependency"},
		{"require crypto remove", edit("\tgolang.org/x/crypto v0.30.0\n", ""), "crypto dependency"},
		{"require crypto add", edit("require (\n", "require (\n\tfilippo.io/age v1.2.0\n"), "crypto dependency"},
		{"require quoted escaped crypto", edit("require (\n", "require (\n\t\"github.com/bobthecorp/cr\\x79pto\" v1.0.0\n"), "crypto dependency"},
		{"exclude block deep edit", edit("e8 v1.0.0", "e8 v1.0.1"), "directive other than require changed"},
		{"exclude block add", edit("\tgithub.com/bobthecorp/e8 v1.0.0\n", "\tgithub.com/bobthecorp/e8 v1.0.0\n\tgithub.com/bobthecorp/e9 v1.0.0\n"), "directive other than require changed"},
		{"retract block deep edit", edit("v0.7.0 // broken", "v0.7.1 // broken"), "directive other than require changed"},
		{"retract block remove", edit("\tv0.6.0\n", ""), "directive other than require changed"},
		{"replace block edit", edit("../a", "../a2"), "directive other than require changed"},
		{"replace single line add", base + "replace github.com/bobthecorp/lib => ../lib\n", "directive other than require changed"},
		{"exclude single line add", base + "exclude github.com/bobthecorp/lib v1.0.0\n", "directive other than require changed"},
		{"tool block edit", edit("bobthecorp/gen", "bobthecorp/gen2"), "directive other than require changed"},
		{"godebug block edit", edit("panicnil=1", "panicnil=0"), "directive other than require changed"},
		{"godebug duplicate key added", edit("\tpanicnil=1\n", "\tpanicnil=1\n\tpanicnil=0\n"), "duplicate godebug key"},
		{"godebug duplicate key single line", base + "godebug panicnil=1\n", "duplicate godebug key"},
		{"go version", edit("go 1.26.2\n", "go 1.27\n"), "directive other than require changed"},
		{"toolchain", edit("toolchain go1.26.2", "toolchain go1.27.0"), "directive other than require changed"},
		{"module path", edit("module github.com/bobthecorp/app", "module github.com/bobthecorp/app2"), "directive other than require changed"},
		{"malformed", edit("require (\n", "require (\n\tgithub.com/bobthecorp/x\n"), "go.mod does not parse"},
		{"unknown directive", base + "frobnicate x\n", "go.mod does not parse"},
		{"empty", "", "directive other than require changed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := compare([]byte(base), []byte(tt.after), re); got != tt.want {
				t.Errorf("compare = %q, want %q", got, tt.want)
			}
		})
	}
	// Sorted directives match, but the go command takes the last value.
	dupA := strings.Replace(base, "\tpanicnil=1\n", "\tpanicnil=1\n\tpanicnil=0\n", 1)
	dupB := strings.Replace(base, "\tpanicnil=1\n", "\tpanicnil=0\n\tpanicnil=1\n", 1)
	if got := compare([]byte(dupA), []byte(dupB), re); got != "duplicate godebug key" {
		t.Errorf("godebug duplicate reorder: compare = %q", got)
	}
	if got := compare([]byte("garbage ("), []byte(base), re); got != "old go.mod does not parse" {
		t.Errorf("malformed old: compare = %q", got)
	}
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.WriteFile(a, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte(strings.Replace(base, "crypto v0.30.0", "crypto v0.31.0", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name    string
		args    []string
		want    string
		wantErr bool
	}{
		{"clean", []string{"-crypto", cryptoRE, a, a}, "", false},
		{"protected", []string{"-crypto", cryptoRE, a, b}, "crypto dependency", false},
		{"missing file", []string{"-crypto", cryptoRE, a, filepath.Join(dir, "none")}, "", true},
		{"no regexp", []string{a, b}, "", true},
		{"bad regexp", []string{"-crypto", "(", a, b}, "", true},
		{"one file", []string{"-crypto", cryptoRE, a}, "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := run(tt.args)
			if got != tt.want || (err != nil) != tt.wantErr {
				t.Errorf("run = %q, %v; want %q, error %v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}
