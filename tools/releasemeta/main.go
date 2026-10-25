// Command releasemeta gates a release (goreleaser before hook, run from the
// repo root): pins.json (embedded in the binary) must be a real pin
// (the placeholder fails) and capabilities.json must be well formed and list
// only known capabilities, each at most once. It checks consistency only: a
// capability is claimed in capabilities.json when the provider performs it.
// bundle_signature_verification is not claimed until the v2 trust path is wired into
// Configure. Both files ship as release assets next to
// SHA256SUMS; ctfkit migrate refuses releases without that capability.
//
// -version is the release tag. compliancetf/aws X.Y.Z proxies exactly
// hashicorp/aws X.Y.Z, so the tag must be the pins.json version, optionally
// followed by -beta.N or -compliancetf.N. -snapshot=true skips the tag check.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"slices"

	"github.com/compliancetf/terraform-provider-aws/internal/upstream"
)

const (
	capsFormat   = "compliancetf.release-capabilities/v1"
	capsFilePath = "capabilities.json"
	pinsFilePath = "pins.json"
)

// upstreamAddress is the upstream pins.json must pin.
// shortcut: a literal until the upstream is read from wrapper.json.
const upstreamAddress = "registry.terraform.io/hashicorp/aws"

// knownCaps are the capability names the format defines.
var knownCaps = []string{"bundle_signature_verification"}

type capabilities struct {
	Format       string   `json:"format"`
	Capabilities []string `json:"capabilities"`
}

// checkVersion fails unless version (a leading "v" is allowed) is pinned, or
// pinned plus -beta.N or -compliancetf.N.
func checkVersion(version, pinned string) error {
	re := regexp.MustCompile(`^v?` + regexp.QuoteMeta(pinned) + `(-(beta|compliancetf)\.(0|[1-9][0-9]*))?$`)
	if !re.MatchString(version) {
		return fmt.Errorf("release version %q must be %s, %s-beta.N or %s-compliancetf.N (the %s version)", version, pinned, pinned, pinned, pinsFilePath)
	}
	return nil
}

// check validates pins and caps; with snapshot false, version must match the
// pinned upstream version.
func check(pins, caps []byte, version string, snapshot bool) error {
	src, err := upstream.ParseSource(upstreamAddress)
	if err != nil {
		return err
	}
	p, err := upstream.ParsePins(pins, src, upstream.HashiCorpFingerprint)
	if err != nil {
		return fmt.Errorf("%s: %w (run tools/pinupstream before releasing)", pinsFilePath, err)
	}
	if !snapshot {
		if err := checkVersion(version, p.Version); err != nil {
			return err
		}
	}
	dec := json.NewDecoder(bytes.NewReader(caps))
	dec.DisallowUnknownFields()
	var c capabilities
	if err := dec.Decode(&c); err != nil {
		return fmt.Errorf("%s: %w", capsFilePath, err)
	}
	if dec.More() {
		return fmt.Errorf("%s: trailing data", capsFilePath)
	}
	if c.Format != capsFormat {
		return fmt.Errorf("%s: format %q", capsFilePath, c.Format)
	}
	sorted := slices.Clone(c.Capabilities)
	slices.Sort(sorted)
	if len(slices.Compact(sorted)) != len(c.Capabilities) {
		return fmt.Errorf("%s: duplicate capability", capsFilePath)
	}
	if c.Capabilities == nil {
		return fmt.Errorf("%s: capabilities must be a list", capsFilePath)
	}
	for _, name := range c.Capabilities {
		if !slices.Contains(knownCaps, name) {
			return fmt.Errorf("%s: unknown capability %q", capsFilePath, name)
		}
	}
	return nil
}

func main() {
	version := flag.String("version", "", "release tag, e.g. v6.67.0")
	snapshot := flag.Bool("snapshot", false, "snapshot build: skip the release version check")
	flag.Parse()
	pins, err := os.ReadFile(pinsFilePath)
	if err == nil {
		var caps []byte
		if caps, err = os.ReadFile(capsFilePath); err == nil {
			err = check(pins, caps, *version, *snapshot)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "releasemeta:", err)
		os.Exit(1)
	}
}
