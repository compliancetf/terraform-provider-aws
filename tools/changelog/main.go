// Command changelog renders the CHANGELOG.md section of a release from the
// conventional commit subjects since the previous v* tag, in the layout of
// the hashicorp/aws CHANGELOG: "## X.Y.Z (Month D, YYYY)", then BREAKING
// CHANGES, NOTES, FEATURES, ENHANCEMENTS and BUG FIXES, one sorted item
// per commit with its pull request link. feat is a feature, perf and
// refactor an enhancement, fix a bug fix, a "!" after the type a breaking
// change and chore(pin) a note; docs, test, ci and other chores are left out.
//
// Run it from the repository root (release.yml does):
//
//	go run ./tools/changelog -version v6.69.0-compliancetf.2           # the section
//	go run ./tools/changelog -version v6.69.0-compliancetf.2 -notes    # without its heading
//	go run ./tools/changelog -version v6.69.0-compliancetf.2 -update CHANGELOG.md
//
// -update puts the section at the top of the file and does nothing when the
// file already has a section for the version.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// sections are the headings in print order.
var sections = []string{"BREAKING CHANGES", "NOTES", "FEATURES", "ENHANCEMENTS", "BUG FIXES"}

// subjectRE is a conventional commit subject with an optional squash-merge
// pull request suffix: type(scope)!: text (#N).
var subjectRE = regexp.MustCompile(`^([a-z]+)(?:\(([^)]+)\))?(!)?: (.+?)(?: \(#([0-9]+)\))?$`)

// versionRE is a release tag: vX.Y.Z with an optional prerelease.
var versionRE = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.]+)?$`)

func main() {
	version := flag.String("version", "", "release tag, vX.Y.Z[-pre]")
	repo := flag.String("repo", "compliancetf/terraform-provider-aws", "GitHub owner/name for pull request links")
	notes := flag.Bool("notes", false, "print the section without its heading (GitHub release notes)")
	update := flag.String("update", "", "file to put the section at the top of, instead of printing it")
	flag.Parse()
	if err := run(*version, *repo, *notes, *update); err != nil {
		fmt.Fprintln(os.Stderr, "changelog:", err)
		os.Exit(1)
	}
}

func run(version, repo string, notes bool, update string) error {
	if !versionRE.MatchString(version) {
		return fmt.Errorf("-version %q: want vX.Y.Z or vX.Y.Z-pre", version)
	}
	rng := version
	if prev, err := git("describe", "--tags", "--abbrev=0", "--match", "v*", version+"^"); err == nil {
		rng = prev + ".." + version
	}
	log, err := git("log", "--format=%s", rng)
	if err != nil {
		return err
	}
	day, err := git("log", "-1", "--format=%cs", version)
	if err != nil {
		return err
	}
	date, err := time.Parse(time.DateOnly, day)
	if err != nil {
		return fmt.Errorf("commit date of %s: %w", version, err)
	}
	heading, body := render(strings.TrimPrefix(version, "v"), date, repo, strings.Split(log, "\n"))
	switch {
	case update != "":
		return updateFile(update, heading, body)
	case notes:
		fmt.Print(body)
	default:
		fmt.Print(heading + "\n\n" + body)
	}
	return nil
}

// git runs git with args and returns its trimmed stdout.
func git(args ...string) (string, error) {
	out, err := exec.Command("git", args...).Output() //nolint:gosec // fixed git subcommands; the tag matched versionRE
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(string(ee.Stderr)))
		}
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

// render is the heading and body of the version's section from commit
// subjects; a release with no listed change gets one note saying so.
func render(version string, date time.Time, repo string, subjects []string) (string, string) {
	items := map[string][]string{}
	for _, s := range subjects {
		if sec, item, ok := entry(s, repo); ok {
			items[sec] = append(items[sec], item)
		}
	}
	if len(items) == 0 {
		items["NOTES"] = []string{"* provider: No user-facing changes"}
	}
	var b strings.Builder
	for _, sec := range sections {
		if len(items[sec]) == 0 {
			continue
		}
		slices.Sort(items[sec])
		fmt.Fprintf(&b, "%s:\n\n%s\n\n", sec, strings.Join(items[sec], "\n"))
	}
	return fmt.Sprintf("## %s (%s)", version, date.Format("January 2, 2006")), b.String()
}

// entry is the section and list item of one commit subject; ok is false
// for a subject that is not listed.
func entry(subject, repo string) (string, string, bool) {
	m := subjectRE.FindStringSubmatch(strings.TrimSpace(subject))
	if m == nil {
		return "", "", false
	}
	typ, scope, bang, text, pr := m[1], m[2], m[3], m[4], m[5]
	var sec string
	switch {
	case bang != "":
		sec = "BREAKING CHANGES"
	case typ == "feat":
		sec = "FEATURES"
	case typ == "perf" || typ == "refactor":
		sec = "ENHANCEMENTS"
	case typ == "fix":
		sec = "BUG FIXES"
	case typ == "chore" && scope == "pin":
		sec = "NOTES"
	default:
		return "", "", false
	}
	if scope == "" {
		scope = "provider"
	}
	item := "* " + scope + ": " + capitalize(text)
	if pr != "" {
		item += fmt.Sprintf(" ([#%s](https://github.com/%s/pull/%s))", pr, repo, pr)
	}
	return sec, item, true
}

// capitalize upper-cases the first letter of text unless its first word is
// an identifier or path (hashicorp/aws, storage_encrypted, compliance.tf).
func capitalize(text string) string {
	first, _, _ := strings.Cut(text, " ")
	if strings.ContainsAny(first, "/_.`") {
		return text
	}
	r, n := utf8.DecodeRuneInString(text)
	return string(unicode.ToUpper(r)) + text[n:]
}

// updateFile puts the section at the top of path, which may not exist yet;
// a file that already has the version's heading is left unchanged.
func updateFile(path, heading, body string) error {
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	prefix, _, _ := strings.Cut(heading, " (")
	for line := range strings.SplitSeq(string(old), "\n") {
		if strings.HasPrefix(line, prefix+" (") {
			fmt.Fprintf(os.Stderr, "changelog: %s already has %s\n", path, prefix)
			return nil
		}
	}
	if len(old) == 0 {
		body = strings.TrimRight(body, "\n") + "\n" // no blank line at the end of a new file
	}
	return os.WriteFile(path, []byte(heading+"\n\n"+body+string(old)), 0o644) //nolint:gosec // a tracked text file
}
