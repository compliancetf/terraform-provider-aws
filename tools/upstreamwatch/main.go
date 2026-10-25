// Command upstreamwatch picks the hashicorp/aws version the next pin-bump PR
// pins (.github/workflows/upstream-watch.yml). It reads files only, no
// network:
//
//		go run ./tools/upstreamwatch -versions versions.json -branches b.txt -open o.txt [-version X.Y.Z]
//
//	  - -versions: the registry versions API response
//	    (registry.terraform.io/v1/providers/hashicorp/aws/versions); only
//	    X.Y.Z releases count, prereleases are ignored.
//	  - -branches: the repo's pin/hashicorp-aws-* branch names, one per line.
//	  - -open: the head branch names of the repo's open PRs, one per line.
//
// One pin PR at a time: each pin PR rewrites the same files (pins.json, the
// schema subset, the CIS manifest digest that the owner re-signs), so a
// second PR opened beside it conflicts once the first merges. With a pin
// branch open, nothing is picked. Otherwise the pick is the oldest release
// newer than pins.json (forward only, none skipped), or -version (the owner's
// choice, still newer than the pin). A pin branch without an open PR fails
// the run, so a half-finished run is never skipped silently; a leftover
// branch of a release already pinned is ignored.
//
// Output, for $GITHUB_OUTPUT: pinned=, next= (empty: nothing to do),
// branch=, queued= (newer releases after next, space separated).
package main

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
)

// BranchPrefix names the pin branches: pin/hashicorp-aws-X.Y.Z.
const BranchPrefix = "pin/hashicorp-aws-"

var releaseRe = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// plan is what the workflow acts on.
type plan struct {
	pinned, next string
	queued       []string
	note         string
}

func main() {
	var versions, pins, branches, open, want string
	flag.StringVar(&versions, "versions", "", "registry versions API response (required)")
	flag.StringVar(&pins, "pins", "pins.json", "pins.json")
	flag.StringVar(&branches, "branches", "", "pin branch names, one per line (required)")
	flag.StringVar(&open, "open", "", "head branches of open PRs, one per line (required)")
	flag.StringVar(&want, "version", "", "pin this release instead of the oldest newer one")
	flag.Parse()
	if err := run(os.Stdout, os.Stderr, versions, pins, branches, open, want); err != nil {
		fmt.Fprintln(os.Stderr, "upstreamwatch:", err)
		os.Exit(1)
	}
}

func run(stdout, stderr io.Writer, versions, pins, branches, open, want string) error {
	if versions == "" || branches == "" || open == "" {
		return errors.New("-versions, -branches and -open are required")
	}
	pinned, err := pinnedVersion(pins)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(versions)
	if err != nil {
		return err
	}
	bs, err := readLines(branches)
	if err != nil {
		return err
	}
	heads, err := readLines(open)
	if err != nil {
		return err
	}
	p, err := decide(data, pinned, bs, heads, want)
	if err != nil {
		return err
	}
	if p.note != "" {
		if _, err := fmt.Fprintln(stderr, "upstreamwatch:", p.note); err != nil {
			return err
		}
	}
	branch := ""
	if p.next != "" {
		branch = BranchPrefix + p.next
	}
	_, err = fmt.Fprintf(stdout, "pinned=%s\nnext=%s\nbranch=%s\nqueued=%s\n", p.pinned, p.next, branch, strings.Join(p.queued, " "))
	return err
}

// decide applies the rules in the package comment.
func decide(versionsJSON []byte, pinned string, branches, openHeads []string, want string) (plan, error) {
	if !releaseRe.MatchString(pinned) {
		return plan{}, fmt.Errorf("pins.json version %q is not X.Y.Z", pinned)
	}
	newer, err := releasesAfter(versionsJSON, pinned)
	if err != nil {
		return plan{}, err
	}
	p := plan{pinned: pinned}
	var pending []string
	for _, b := range branches {
		v, ok := strings.CutPrefix(b, BranchPrefix)
		if !ok || (releaseRe.MatchString(v) && compare(v, pinned) <= 0) {
			continue // not a pin branch, or a leftover of a release already pinned
		}
		if !slices.Contains(openHeads, b) {
			return plan{}, fmt.Errorf("branch %s has no open pull request: open one for it, or delete the branch", b)
		}
		pending = append(pending, b)
	}
	if len(pending) > 0 {
		p.queued = newer
		p.note = fmt.Sprintf("pin PR open on %s; one pin PR at a time, newer releases wait: %v", strings.Join(pending, ", "), newer)
		return p, nil
	}
	if want != "" {
		i := slices.Index(newer, want)
		if i < 0 {
			return plan{}, fmt.Errorf("-version %q is not a hashicorp/aws release newer than the pinned %s (newer: %v)", want, pinned, newer)
		}
		p.next, p.queued = want, newer[i+1:]
		return p, nil
	}
	if len(newer) == 0 {
		p.note = "pins.json " + pinned + " is the latest hashicorp/aws release"
		return p, nil
	}
	p.next, p.queued = newer[0], newer[1:]
	return p, nil
}

// releasesAfter lists the X.Y.Z releases in a registry versions response
// newer than pinned, oldest first.
func releasesAfter(versionsJSON []byte, pinned string) ([]string, error) {
	var resp struct {
		Versions []struct {
			Version string `json:"version"`
		} `json:"versions"`
	}
	dec := json.NewDecoder(bytes.NewReader(versionsJSON))
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("versions: %w", err)
	}
	if len(resp.Versions) == 0 {
		return nil, errors.New("versions: no versions listed")
	}
	var out []string
	for _, v := range resp.Versions {
		if releaseRe.MatchString(v.Version) && compare(v.Version, pinned) > 0 && !slices.Contains(out, v.Version) {
			out = append(out, v.Version)
		}
	}
	slices.SortFunc(out, compare)
	return out, nil
}

// compare orders two X.Y.Z strings that matched releaseRe.
func compare(a, b string) int {
	pa, pb := releaseRe.FindStringSubmatch(a), releaseRe.FindStringSubmatch(b)
	for i := 1; i <= 3; i++ {
		// No leading zeros: the longer number is larger, equal lengths compare as text.
		if c := cmp.Or(cmp.Compare(len(pa[i]), len(pb[i])), strings.Compare(pa[i], pb[i])); c != 0 {
			return c
		}
	}
	return 0
}

func pinnedVersion(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var p struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return p.Version, nil
}

func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out, nil
}
