// Command cispin regenerates the pin-dependent parts of the embedded CIS
// bundle source from the captured upstream schema (run from the repo root,
// after tools/pinupstream and scripts/capture-aws-schema.sh; make pin does
// all steps):
//
//   - internal/embedded/testdata/schema_compat.tsv, the type table: one line
//     "<type>\t<read>\t<cty type JSON>\t<computed|->" per control read;
//   - internal/embedded/cis/manifest.json schema_compat_digest, sha256 of the
//     first three columns joined by "\n" (bundlegen.SchemaCompatDigest).
//
// It fails, writing nothing, when the inputs need an owner decision: the
// captured schema is not of the pinned version, the pin is outside the
// manifest provider or upstream version_range, a read is gone from the
// schema, or a read became Computed while its control checks the effective
// value (presence_mode must be configured).
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/bundlegen"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/upstream"
)

// upstreamAddress is the upstream pins.json must pin.
// shortcut: a literal until the upstream is read from wrapper.json.
const upstreamAddress = "registry.terraform.io/hashicorp/aws"

type config struct {
	pins, provenance, schema, controls, manifest, tsv string
}

func main() {
	cfg := config{}
	flag.StringVar(&cfg.pins, "pins", "pins.json", "pins.json")
	flag.StringVar(&cfg.provenance, "provenance", "testdata/schemas/aws-subset.provenance.json", "schema capture provenance")
	flag.StringVar(&cfg.schema, "schema", "testdata/schemas/aws-subset.json", "captured upstream schema")
	flag.StringVar(&cfg.controls, "controls", "internal/embedded/cis/controls.json", "CIS controls")
	flag.StringVar(&cfg.manifest, "manifest", "internal/embedded/cis/manifest.json", "CIS manifest")
	flag.StringVar(&cfg.tsv, "tsv", "internal/embedded/testdata/schema_compat.tsv", "type table")
	flag.Parse()
	changed, err := run(cfg)
	if err != nil {
		var od ownerDecision
		if errors.As(err, &od) {
			// The upstream watch workflow opens a draft PR on this exact prefix.
			fmt.Fprintln(os.Stderr, "cispin: owner decision:", err)
		} else {
			fmt.Fprintln(os.Stderr, "cispin:", err)
		}
		os.Exit(1)
	}
	if changed {
		fmt.Println("cispin: CIS manifest changed: cis.tar.gz must be re-signed (scripts/owner-sign-cis.sh)")
	}
}

// ownerDecision marks a failure the owner resolves (version_range, a read
// gone or Computed), as opposed to a broken input or tool.
type ownerDecision struct{ error }

func (e ownerDecision) Unwrap() error { return e.error }

// run regenerates cfg.tsv and the manifest digest; changed reports whether
// the manifest (signed content) changed.
func run(cfg config) (changed bool, err error) {
	version, err := pinnedVersion(cfg.pins)
	if err != nil {
		return false, err
	}
	var prov struct {
		Version string `json:"version"`
	}
	if err := readJSON(cfg.provenance, &prov); err != nil {
		return false, err
	}
	if prov.Version != version {
		return false, fmt.Errorf("%s is hashicorp/aws %q, pins.json pins %s: run scripts/capture-aws-schema.sh %s", cfg.schema, prov.Version, version, version)
	}
	manifest, err := os.ReadFile(cfg.manifest)
	if err != nil {
		return false, err
	}
	if err := checkRanges(manifest, version); err != nil {
		// %w keeps checkRanges' ownerDecision; a manifest that does not parse is not one.
		return false, fmt.Errorf("%s: %w; the owner reviews the controls against hashicorp/aws %s and widens version_range", cfg.manifest, err, version)
	}
	data, err := os.ReadFile(cfg.controls)
	if err != nil {
		return false, err
	}
	cs, err := bundle.ParseControls(data)
	if err != nil {
		return false, fmt.Errorf("%s: %w", cfg.controls, err)
	}
	s, err := bundlegen.LoadSchemas(cfg.schema)
	if err != nil {
		return false, err
	}
	tsv, digest, err := compatTable(cs, s)
	if err != nil {
		return false, ownerDecision{fmt.Errorf("hashicorp/aws %s: %w", version, err)}
	}
	newManifest, err := setDigest(manifest, digest)
	if err != nil {
		return false, fmt.Errorf("%s: %w", cfg.manifest, err)
	}
	if err := writeIfChanged(cfg.tsv, tsv); err != nil {
		return false, err
	}
	changed = !bytes.Equal(newManifest, manifest)
	if changed {
		return true, os.WriteFile(cfg.manifest, newManifest, 0o644) //nolint:gosec // public source file
	}
	return false, nil
}

func pinnedVersion(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	src, err := upstream.ParseSource(upstreamAddress)
	if err != nil {
		return "", err
	}
	p, err := upstream.ParsePins(data, src, upstream.HashiCorpFingerprint)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return p.Version, nil
}

// compatTable is the type table and its schema_compat_digest. The computed
// column is bundlegen.ReadComputed of the read. A Computed read must be
// bound with presence_mode configured, or the control would judge a
// provider-filled value (an owner decision, so bundlegen.CheckSchema fails
// here).
func compatTable(cs []bundle.Control, s bundlegen.Schemas) (tsv []byte, digest string, err error) {
	if err := bundlegen.CheckSchema(cs, s, bundlegen.Schemas{}); err != nil {
		return nil, "", err
	}
	lines, err := bundlegen.SchemaCompatLines(cs, s)
	if err != nil {
		return nil, "", err
	}
	digest, err = bundlegen.SchemaCompatDigest(cs, s)
	if err != nil {
		return nil, "", err
	}
	computed := map[string]bool{}
	for _, c := range cs {
		sc, _ := s.Lookup(c.Kind, c.ResourceType)
		for _, r := range c.Reads {
			computed[c.ResourceType+"\t"+r] = bundlegen.ReadComputed(sc, r)
		}
	}
	var b bytes.Buffer
	for _, l := range lines {
		f := strings.SplitN(l, "\t", 3)
		flagCol := "-"
		if computed[f[0]+"\t"+f[1]] {
			flagCol = "computed"
		}
		b.WriteString(l + "\t" + flagCol + "\n")
	}
	return b.Bytes(), digest, nil
}

// checkRanges fails unless version meets the manifest provider and upstream
// version_range (comma-separated ">= x" / "< y", as the provider checks).
func checkRanges(manifest []byte, version string) error {
	var m bundle.Manifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		return err
	}
	for _, x := range [][2]string{{"provider", m.Provider.VersionRange}, {"upstream", m.Upstream.VersionRange}} {
		if !inRange(version, x[1]) {
			return ownerDecision{fmt.Errorf("%s version_range %q does not admit %s", x[0], x[1], version)}
		}
	}
	return nil
}

func inRange(v, r string) bool {
	if strings.TrimSpace(r) == "" {
		return false
	}
	for _, c := range strings.Split(r, ",") {
		op, bound, _ := strings.Cut(strings.TrimSpace(c), " ")
		bound = strings.TrimSpace(bound)
		if bound == "" || strings.Contains(bound, "-") || trust.CheckWrapper(bound, bound) != nil {
			return false
		}
		below := trust.CheckWrapper(v, bound) != nil
		switch {
		case op == ">=" && !below, op == "<" && below:
		default:
			return false
		}
	}
	return true
}

var digestRe = regexp.MustCompile(`("schema_compat_digest":\s*")sha256:[0-9a-f]{64}(")`)

// setDigest replaces the digest in the manifest text, keeping its layout.
func setDigest(manifest []byte, digest string) ([]byte, error) {
	if n := len(digestRe.FindAllIndex(manifest, -1)); n != 1 {
		return nil, fmt.Errorf("%d schema_compat_digest fields, want 1", n)
	}
	return digestRe.ReplaceAll(manifest, []byte("${1}"+digest+"${2}")), nil
}

func writeIfChanged(path string, data []byte) error {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return nil
	}
	return os.WriteFile(path, data, 0o644) //nolint:gosec // public test data
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
