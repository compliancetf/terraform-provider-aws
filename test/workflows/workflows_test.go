// Package workflows checks the GitHub workflows and release config: pinned
// actions, triggers and the release gates. Paths are relative to the repo root.
package workflows

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestMain runs the tests from the repo root, where the paths below start.
func TestMain(m *testing.M) {
	if err := os.Chdir("../.."); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

var (
	usesRe     = regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*(\S+)`)
	shaPinRe   = regexp.MustCompile(`@[0-9a-f]{40}$`)
	tagNoteRe  = regexp.MustCompile(`@[0-9a-f]{40} # v[0-9]+\.[0-9]+\.[0-9]+$`)
	floatingRe = regexp.MustCompile(`(?m)(@latest\b|^\s*[\w-]*version:\s*["']?latest["']?\s*(#.*)?$)`)
	// Events any workflow may use; anything else needs an owner-approved
	// entry in allowedTriggers (policy: no CI on pushes or PRs).
	anyTrigger = map[string]bool{"workflow_dispatch": true, "schedule": true}
	// The owner-approved exceptions as they stand: release on tag push,
	// test.yml for Dependabot PRs (other PRs skip every job), the protected
	// paths gate and the Dependabot merge and owner review hooks.
	allowedTriggers = map[string]bool{
		".github/workflows/release.yml push":                        true,
		".github/workflows/test.yml pull_request":                   true,
		".github/workflows/protected-paths.yml pull_request_target": true,
		".github/workflows/protected-paths.yml workflow_run":        true,
		".github/workflows/dependabot-merge.yml workflow_run":       true,
		".github/workflows/owner-review.yml pull_request_review":    true,
	}
)

type workflow struct {
	On          yaml.Node              `yaml:"on"`
	Permissions yaml.Node              `yaml:"permissions"`
	Jobs        map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Uses        string            `yaml:"uses"` // a reusable workflow call
	Needs       yaml.Node         `yaml:"needs"`
	If          string            `yaml:"if"`
	Permissions map[string]string `yaml:"permissions"`
	Steps       []struct {
		Uses string         `yaml:"uses"`
		With map[string]any `yaml:"with"`
	} `yaml:"steps"`
}

func parseWorkflow(t *testing.T, f string) ([]byte, workflow) {
	t.Helper()
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	var wf workflow
	if err := yaml.Unmarshal(b, &wf); err != nil {
		t.Fatalf("%s: %v", f, err)
	}
	return b, wf
}

// triggers lists the event names of an on: value in any of its forms
// (scalar, sequence or mapping).
func triggers(n yaml.Node) []string {
	switch n.Kind {
	case yaml.AliasNode:
		return triggers(*n.Alias)
	case yaml.ScalarNode:
		return []string{n.Value}
	case yaml.SequenceNode:
		var out []string
		for _, c := range n.Content {
			out = append(out, triggers(*c)...)
		}
		return out
	case yaml.MappingNode:
		var out []string
		for i := 0; i < len(n.Content); i += 2 {
			out = append(out, triggers(*n.Content[i])...)
		}
		return out
	}
	return nil
}

// TestWorkflowPins fails when any workflow uses an action by tag or without
// a "# vX.Y.Z" note, checks out with persisted credentials, downloads a tool
// at a floating version, leaves the token scope implicit, or runs on push or
// pull_request (policy: no CI on PRs or pushes).
func TestWorkflowPins(t *testing.T) {
	files, err := filepath.Glob(".github/workflows/*.y*ml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflows: %v", err)
	}
	for _, f := range files {
		b, wf := parseWorkflow(t, f)
		for _, line := range strings.Split(string(b), "\n") {
			if usesRe.MatchString(line) && !tagNoteRe.MatchString(strings.TrimSpace(line)) {
				t.Errorf("%s: %q is not pinned to a commit SHA with a \"# vX.Y.Z\" note", f, strings.TrimSpace(line))
			}
		}
		for name, job := range wf.Jobs {
			if job.Uses != "" && !shaPinRe.MatchString(job.Uses) {
				t.Errorf("%s: job %s: reusable workflow %s is not pinned to a commit SHA", f, name, job.Uses)
			}
			for _, st := range job.Steps {
				if st.Uses != "" && !shaPinRe.MatchString(st.Uses) {
					t.Errorf("%s: job %s: %s is not pinned to a commit SHA", f, name, st.Uses)
				}
				if strings.HasPrefix(strings.ToLower(st.Uses), "actions/checkout@") && st.With["persist-credentials"] != false {
					t.Errorf("%s: job %s: actions/checkout without persist-credentials: false", f, name)
				}
				for k, v := range st.With {
					if strings.HasSuffix(k, "version") && v == "latest" {
						t.Errorf("%s: job %s: %s: latest is a floating tool version", f, name, k)
					}
				}
			}
		}
		for _, m := range floatingRe.FindAll(b, -1) {
			t.Errorf("%s: floating tool version %q", f, m)
		}
		if wf.Permissions.Kind == 0 {
			t.Errorf("%s: no top-level permissions block", f)
		}
		ev := triggers(wf.On)
		if len(ev) == 0 {
			t.Errorf("%s: no on: triggers", f)
		}
		for _, e := range ev {
			if !anyTrigger[e] && !allowedTriggers[f+" "+e] {
				t.Errorf("%s: %s trigger is not owner-approved (no CI on pushes or PRs)", f, e)
			}
		}
	}
}

// TestActionPins: every uses: in a composite action (action.yml) is pinned
// to a commit SHA with a "# vX.Y.Z" note, as in the workflows. The repo has
// none today; the test covers the first one added.
func TestActionPins(t *testing.T) {
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata" || d.Name() == "vendor") {
			return filepath.SkipDir
		}
		if d.IsDir() || (d.Name() != "action.yml" && d.Name() != "action.yaml") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(b), "\n") {
			if usesRe.MatchString(line) && !tagNoteRe.MatchString(strings.TrimSpace(line)) {
				t.Errorf("%s: %q is not pinned to a commit SHA with a \"# vX.Y.Z\" note", path, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestProtectedPathsGateHardening pins the gate hardening fixes, in order where order matters.
func TestProtectedPathsGateHardening(t *testing.T) {
	wf, err := os.ReadFile(".github/workflows/protected-paths.yml")
	if err != nil {
		t.Fatal(err)
	}
	q := regexp.QuoteMeta
	steps := []struct{ name, re string }{
		// Same group for both events, so a fork PR's two runs never overlap.
		{"concurrency by head SHA", `(?m)^  group: ` + q(`protected-paths-${{ github.event.pull_request.head.sha || github.event.workflow_run.head_sha }}`) + `$`},
		// Pending is the first step, before checkout, self-test and lookups.
		{"pending before checkout", `(?m)^    steps:\n(\s*#[^\n]*\n)*\s*- name: Mark owner-approval pending\n\s*run: \|\n\s*set -euo pipefail\n[^\n]*bad head SHA[^\n]*\n\s*` +
			q(`gh api --silent "repos/$REPO/statuses/$EVENT_HEAD_SHA" -f state=pending -f context=owner-approval \`) + `\n\s*` +
			q(`-f description="checking protected paths" -f target_url="$RUN_URL"`) + `\n\n(\s*#[^\n]*\n)*\s*- name: Check out the default branch tip`},
		// Go for tools/gomodcheck, without a cache a write-token job could poison.
		{"go without cache", `(?m)^\s*uses: actions/setup-go@[0-9a-f]{40} # v[0-9.]+\n\s*with:\n\s*go-version-file: go.mod\n\s*cache: false\n\n\s*- name: Self-test`},
		// Several open PRs on one head: pending for both events, then stop.
		{"shared head lookup", `(?m)^\s*open=\$\(gh api --paginate "repos/\$REPO/pulls\?state=open&per_page=100" \\$`},
		{"pending helper", q(`gh api --silent "repos/$REPO/statuses/$EVENT_HEAD_SHA" -f state=pending -f context=owner-approval`)},
		{"shared head pending", q(`if [ -n "$open" ] && [ "$(wc -l <<<"$open")" -ne 1 ]; then`) + `\s*` + q(`pending "several open PRs share this head"`)},
		{"shared head auto-merge off", q(`for n in $open; do`) + `\s*` +
			q(`auto=$(gh pr view "$n" -R "$REPO" --json autoMergeRequest --jq '.autoMergeRequest != null')`) + `\s*` +
			q(`if [ "$auto" = true ]; then gh pr merge "$n" -R "$REPO" --disable-auto; fi`) + `\s*done\s*\n[^\n]*\n\s*exit 0\n\s*fi\n`},
		// Commits and files come from a compare pinned to the event head
		// SHA, never the PR's live lists (A->B->A force-push).
		{"base is the default branch", q(`'.base.ref == $ref and .base.repo.full_name == $repo' "$RUNNER_TEMP/pr.json" >/dev/null; then`) + `\s*` +
			q(`pending "PR base is not $DEFAULT_BRANCH"`)},
		{"base SHA checked", q(`[[ $base =~ ^[0-9a-f]{40}$ ]] || { echo "::error::bad base SHA: $base"; exit 1; }`)},
		{"commits pinned", q(`gh api "repos/$REPO/compare/$base...$head" >"$RUNNER_TEMP/compare.json"`)},
		// Owner pass needs the full commit list (the API stops at 250).
		{"commit count", q(`listed=$(wc -l <"$RUNNER_TEMP/commits.tsv")`)},
		{"commit total", q(`total=$(jq -r .total_commits "$RUNNER_TEMP/compare.json")`) + `\s*` +
			q(`[[ $total =~ ^[0-9]+$ ]] || { echo "::error::bad commit count: $total"; exit 1; }`)},
		{"owner pass", q(`if [ "$listed" -eq "$total" ] && [ -z "$others" ]; then owner_author=true; fi`)},
		{"files pinned", q(`scripts/protected-paths.sh --compare "$REPO" "$BASE" "$HEAD" >"$RUNNER_TEMP/hits.txt"`)},
		// Head re-check, then pending before any side effect.
		{"head re-check", q(`cur=$(gh api "repos/$REPO/pulls/$PR" --jq .head.sha)`) + `\s*` + q(`if [ "$cur" != "$HEAD" ]; then`)},
		{"backticks stripped", q("tr -d '`' <\"$RUNNER_TEMP/hits.txt\"")},
		{"pending first", q(`status pending "needs owner approval of $short"`)},
		// A failed probe fails the step instead of reading as no auto-merge.
		{"probe assigned", `(?m)^\s*auto=\$\(gh pr view "\$PR" -R "\$REPO" --json autoMergeRequest`},
		{"disable auto-merge", q(`gh pr merge "$PR" -R "$REPO" --disable-auto`)},
		{"label", q(`-f 'labels[]=needs-owner'`)},
		{"final status", `(?m)^\s*status "\$state" "\$desc"$`},
	}
	at := 0
	for _, s := range steps {
		loc := regexp.MustCompile(s.re).FindIndex(wf[at:])
		if loc == nil {
			t.Errorf("protected-paths.yml: %s missing, or out of order", s.name)
			continue
		}
		at += loc[1]
	}
	for _, live := range []string{"/files?", "/commits?", "--pr "} {
		if bytes.Contains(wf, []byte(live)) {
			t.Errorf("protected-paths.yml: reads the PR's live list (%q); classify the head SHA", live)
		}
	}
	if bytes.Contains(wf, []byte(`cat "$RUNNER_TEMP/hits.txt"`)) {
		t.Error("protected-paths.yml: hits printed with backticks intact")
	}
}

// TestDependabotMergeGate: the Dependabot merge classifies the tested SHA
// with protected-paths.sh --compare (--pr was removed, so the old call exited
// 2 and never merged) and sets up Go, without a cache, for tools/gomodcheck.
// Its commit and go.mod checks read one compare pinned to the
// tested SHA (all commits listed),
// and it re-checks the PR head right before the merge.
func TestDependabotMergeGate(t *testing.T) {
	wf, err := os.ReadFile(".github/workflows/dependabot-merge.yml")
	if err != nil {
		t.Fatal(err)
	}
	q := regexp.QuoteMeta
	steps := []struct{ name, re string }{
		{"checkout default branch", `(?m)^\s*- name: Check out the default branch tip \(never the PR\)$`},
		{"go without cache", `(?m)^\s*uses: actions/setup-go@[0-9a-f]{40} # v[0-9.]+\n\s*with:\n\s*go-version-file: go.mod\n\s*cache: false\n\n\s*- name: Check eligibility`},
		{"base repo checked", q(`and .base.repo.full_name == $repo`)},
		{"base SHA checked", q(`[[ $base =~ ^[0-9a-f]{40}$ ]] || { echo "::error::bad base SHA: $base"; exit 1; }`)},
		{"compare pinned", q(`gh api "repos/$REPO/compare/$base...$SHA" >"$RUNNER_TEMP/compare.json"`)},
		{"commit count", q(`listed=$(jq '.commits | length' "$RUNNER_TEMP/compare.json")`)},
		{"commit total", q(`total=$(jq -r .total_commits "$RUNNER_TEMP/compare.json")`) + `\s*` +
			q(`[[ $total =~ ^[0-9]+$ ]] || { echo "::error::bad commit count: $total"; exit 1; }`) + `\s*` +
			q(`[ "$listed" -eq "$total" ] || skip`)},
		{"commits pinned", q(`others=$(jq -r '.commits[] | select(.author.login != "dependabot[bot]" or .commit.verification.verified != true) | .sha'`) + `\s*\\\s*` +
			q(`"$RUNNER_TEMP/compare.json")`)},
		{"go.mod files pinned", q(`jq -c '.files[]' "$RUNNER_TEMP/compare.json" >"$RUNNER_TEMP/files.jsonl"`)},
		{"files pinned", q(`scripts/protected-paths.sh --compare "$REPO" "$base" "$SHA" >"$RUNNER_TEMP/hits.txt"`)},
		{"protected skips", q(`1) skip "PR #$pr touches protected paths`)},
		{"script error fails", q(`*) echo "::error::protected-paths.sh failed with exit $rc"; exit 1 ;;`)},
		{"head re-check", q(`cur=$(gh api "repos/$REPO/pulls/$pr" --jq .head.sha)`) + `\s*` +
			q(`[ "$cur" = "$SHA" ] || skip "PR #$pr head moved to $cur after the checks"`)},
		{"merge pinned", q(`gh api --silent -X PUT "repos/$REPO/pulls/$pr/merge" -f merge_method=squash -f sha="$SHA"`)},
	}
	at := 0
	for _, s := range steps {
		loc := regexp.MustCompile(s.re).FindIndex(wf[at:])
		if loc == nil {
			t.Errorf("dependabot-merge.yml: %s missing, or out of order", s.name)
			continue
		}
		at += loc[1]
	}
	if bytes.Contains(wf, []byte("protected-paths.sh --pr")) {
		t.Error("dependabot-merge.yml: calls the removed protected-paths.sh --pr option")
	}
	for _, live := range []string{"/files?", "/commits?"} {
		if bytes.Contains(wf, []byte(live)) {
			t.Errorf("dependabot-merge.yml: reads the PR's live list (%q); use the compare pinned to $SHA", live)
		}
	}
}

// TestProtoDriftAlerts: a red scheduled proto-drift run opens (or comments
// on) one tracking issue, from a job that alone holds issues: write, holds
// nothing else and checks out nothing.
func TestProtoDriftAlerts(t *testing.T) {
	_, wf := parseWorkflow(t, ".github/workflows/proto-drift.yml")
	var top map[string]string
	if err := wf.Permissions.Decode(&top); err != nil || len(top) != 1 || top["contents"] != "read" {
		t.Errorf("proto-drift.yml: top-level permissions must be exactly contents: read (%v)", err)
	}
	job, ok := wf.Jobs["alert"]
	if !ok {
		t.Fatal("proto-drift.yml: no alert job")
	}
	if job.Needs.Value != "live" || job.If != "failure() && github.event_name == 'schedule'" {
		t.Errorf("proto-drift.yml alert job: needs %q, if %q", job.Needs.Value, job.If)
	}
	if len(job.Permissions) != 1 || job.Permissions["issues"] != "write" {
		t.Errorf("proto-drift.yml alert job: permissions %v, want only issues: write", job.Permissions)
	}
	for _, st := range job.Steps {
		if st.Uses != "" {
			t.Errorf("proto-drift.yml alert job: uses %s; it runs no actions and checks out nothing", st.Uses)
		}
	}
	for name, j := range wf.Jobs {
		if name != "alert" && j.Permissions["issues"] != "" {
			t.Errorf("proto-drift.yml: job %s holds issues permission", name)
		}
	}
}

// TestReleaseVerifiesAndGates: release.yml installs goreleaser fail closed
// (pinned sha256 check, then cosign verify-blob with goreleaser's identity)
// before it runs `goreleaser release`, never through goreleaser-action, which
// skips the signature when the bundle download fails. Every
// goreleaser build runs tools/releasegate as a build hook, which
// --skip=before cannot drop.
func TestReleaseVerifiesAndGates(t *testing.T) {
	wf, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	order := []string{
		`(?m)^\s*-?\s*uses:\s*sigstore/cosign-installer@`,
		`(?m)^\s*echo "\$GORELEASER_SHA256  goreleaser_Linux_x86_64\.tar\.gz" \| sha256sum -c -$`,
		`(?m)^\s*cosign verify-blob \\$`,
		`(?m)^\s*--certificate-identity "https://github\.com/goreleaser/goreleaser/\.github/workflows/release\.yml@refs/tags/\$GORELEASER_VERSION" \\$`,
		`(?m)^\s*--certificate-oidc-issuer https://token\.actions\.githubusercontent\.com \\$`,
		`(?m)^\s*run: goreleaser release --clean --release-notes "\$RUNNER_TEMP/notes\.md"$`,
	}
	at := 0
	for _, re := range order {
		loc := regexp.MustCompile(re).FindIndex(wf[at:])
		if loc == nil {
			t.Fatalf("release.yml: missing, or out of order: %s", re)
		}
		at += loc[1]
	}
	if bytes.Contains(wf, []byte("goreleaser/goreleaser-action")) || bytes.Contains(wf, []byte("set +e")) {
		t.Error("release.yml: run goreleaser only from the verified install")
	}
	gr, err := os.ReadFile(".goreleaser.yml")
	if err != nil {
		t.Fatal(err)
	}
	hook := regexp.MustCompile(`(?m)^    hooks:\n      post:\n        - cmd: go run \./tools/releasegate -snapshot=\{\{ \.IsSnapshot \}\} \{\{ \.Path \}\}$`)
	builds := strings.Count(string(gr[:strings.Index(string(gr), "\narchives:")]), "\n  - id: ")
	if builds != 1 || !hook.Match(gr) {
		t.Errorf(".goreleaser.yml: want exactly one build, carrying the tools/releasegate post hook (builds: %d)", builds)
	}
}
