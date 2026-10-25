// Command gomodcheck compares two versions of a go.mod for the protected-paths
// gate (scripts/protected-paths.sh). It parses both files with
// golang.org/x/mod/modfile, so an edit anywhere inside a replace, exclude,
// retract, tool or godebug block is seen no matter where a diff hunk starts.
//
// Usage: gomodcheck -crypto REGEX OLD NEW
//
// Protected (exit 1, reason on stdout): either file does not parse; any
// directive other than require differs (module, go, toolchain, godebug,
// replace, exclude, retract, tool, ignore); the new file repeats a godebug
// key (the last one wins, so a reorder would change it); a require of a
// module matching REGEX is added, removed or changes version. Adding,
// removing or bumping any other require is clean (exit 0). Exit 2: usage or
// I/O error.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/mod/modfile"
)

func main() {
	reason, err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "gomodcheck:", err)
		os.Exit(2)
	}
	if reason != "" {
		fmt.Println(reason)
		os.Exit(1)
	}
}

// run returns why the change between the two files is protected ("" if not).
func run(args []string) (string, error) {
	fs := flag.NewFlagSet("gomodcheck", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	crypto := fs.String("crypto", "", "regexp of protected module paths")
	if err := fs.Parse(args); err != nil || fs.NArg() != 2 || *crypto == "" {
		return "", errors.New("usage: gomodcheck -crypto REGEX OLD NEW")
	}
	re, err := regexp.Compile(*crypto)
	if err != nil {
		return "", fmt.Errorf("bad -crypto: %w", err)
	}
	var data [2][]byte
	for i, p := range fs.Args() {
		if data[i], err = os.ReadFile(p); err != nil {
			return "", err
		}
	}
	return compare(data[0], data[1], re), nil
}

// compare returns why the change from before to after is protected, or "" if it is not.
func compare(before, after []byte, crypto *regexp.Regexp) string {
	of, err := modfile.Parse("go.mod", before, nil)
	if err != nil {
		return "old go.mod does not parse"
	}
	nf, err := modfile.Parse("go.mod", after, nil)
	if err != nil {
		return "go.mod does not parse"
	}
	// The go command honors the last of repeated godebug keys, and sorting
	// hides a reorder, so a duplicate key at head is protected on its own.
	if dupGodebug(nf) {
		return "duplicate godebug key"
	}
	if !slices.Equal(directives(of), directives(nf)) {
		return "directive other than require changed"
	}
	// Requires by unquoted module path, so a quoted, escaped path cannot hide
	// a crypto module.
	ov, nv := requires(of), requires(nf)
	for p, v := range ov {
		if !slices.Equal(v, nv[p]) && crypto.MatchString(p) {
			return "crypto dependency"
		}
	}
	for p := range nv {
		if _, ok := ov[p]; !ok && crypto.MatchString(p) {
			return "crypto dependency"
		}
	}
	return ""
}

// directives lists every statement except require as its raw tokens, block
// verb included, sorted so reordering alone is not a change. Comments are not
// tokens and do not count.
func directives(f *modfile.File) []string {
	var out []string
	add := func(tok []string) {
		if len(tok) > 0 && tok[0] != "require" {
			out = append(out, strings.Join(tok, " "))
		}
	}
	for _, s := range f.Syntax.Stmt {
		switch x := s.(type) {
		case *modfile.Line:
			add(x.Token)
		case *modfile.LineBlock:
			for _, l := range x.Line {
				add(append(slices.Clone(x.Token), l.Token...))
			}
		}
	}
	slices.Sort(out)
	return out
}

// dupGodebug reports whether a godebug key appears more than once.
func dupGodebug(f *modfile.File) bool {
	seen := map[string]bool{}
	for _, g := range f.Godebug {
		if seen[g.Key] {
			return true
		}
		seen[g.Key] = true
	}
	return false
}

// requires maps each required module path to its sorted versions.
func requires(f *modfile.File) map[string][]string {
	m := map[string][]string{}
	for _, r := range f.Require {
		m[r.Mod.Path] = append(m[r.Mod.Path], r.Mod.Version)
	}
	for _, v := range m {
		slices.Sort(v)
	}
	return m
}
