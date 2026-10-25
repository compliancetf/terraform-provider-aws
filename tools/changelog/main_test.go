package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const repo = "bobthecorp/terraform-provider-aws"

func TestRender(t *testing.T) {
	date := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	heading, body := render("6.69.0-compliancetf.2", date, repo, []string{
		"feat(diagnostics): shorter control diagnostics with a docs link (#7)",
		"docs(examples): a README per example (#6)",
		"perf(upstream): share the verified upstream copy (#5)",
		"chore: pre-push history guard (#4)",
		"fix: storage_encrypted read at apply",
		"feat(engine)!: drop the v1 bundle format (#9)",
		"chore(pin): hashicorp/aws 6.69.0 (#1)",
		"Initial public release",
		"",
	})
	if want := "## 6.69.0-compliancetf.2 (October 25, 2026)"; heading != want {
		t.Errorf("heading %q, want %q", heading, want)
	}
	want := `BREAKING CHANGES:

* engine: Drop the v1 bundle format ([#9](https://github.com/bobthecorp/terraform-provider-aws/pull/9))

NOTES:

* pin: hashicorp/aws 6.69.0 ([#1](https://github.com/bobthecorp/terraform-provider-aws/pull/1))

FEATURES:

* diagnostics: Shorter control diagnostics with a docs link ([#7](https://github.com/bobthecorp/terraform-provider-aws/pull/7))

ENHANCEMENTS:

* upstream: Share the verified upstream copy ([#5](https://github.com/bobthecorp/terraform-provider-aws/pull/5))

BUG FIXES:

* provider: storage_encrypted read at apply

`
	if body != want {
		t.Errorf("body:\n%s\nwant:\n%s", body, want)
	}
	if _, body := render("6.70.0", date, repo, []string{"docs: typo (#3)"}); body != "NOTES:\n\n* provider: No user-facing changes\n\n" {
		t.Errorf("empty release body %q", body)
	}
}

func TestUpdateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "CHANGELOG.md")
	steps := []struct{ heading, body, want string }{
		{"## 6.69.0 (October 25, 2026)", "NOTES:\n\n* a\n\n", "## 6.69.0 (October 25, 2026)\n\nNOTES:\n\n* a\n"},
		{"## 6.69.0-compliancetf.1 (October 26, 2026)", "FEATURES:\n\n* b\n\n",
			"## 6.69.0-compliancetf.1 (October 26, 2026)\n\nFEATURES:\n\n* b\n\n## 6.69.0 (October 25, 2026)\n\nNOTES:\n\n* a\n"},
		// a version already in the file is left alone, whatever its date
		{"## 6.69.0 (October 27, 2026)", "NOTES:\n\n* c\n\n",
			"## 6.69.0-compliancetf.1 (October 26, 2026)\n\nFEATURES:\n\n* b\n\n## 6.69.0 (October 25, 2026)\n\nNOTES:\n\n* a\n"},
	}
	for i, s := range steps {
		if err := updateFile(path, s.heading, s.body); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != s.want {
			t.Errorf("step %d:\n%s\nwant:\n%s", i, got, s.want)
		}
	}
}

func TestVersion(t *testing.T) {
	for v, ok := range map[string]bool{"v6.69.0": true, "v6.69.0-compliancetf.2": true, "v6.70.0-beta.1": true,
		"6.69.0": false, "v6.69": false, "v6.69.0;rm": false, "": false} {
		if versionRE.MatchString(v) != ok {
			t.Errorf("%q: want %v", v, ok)
		}
	}
}
