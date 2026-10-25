// Command ctf-bundlegen generates bundle 2.0 controls from a catalog export and
// content intents. `generate` writes the bundles,
// the coverage report and the review queue and sheet, and prints one
// E_REVIEW_PENDING line per queued id; `coverage --ledger FILE` runs the same generation
// in memory and writes the generation_status column of the disposition
// ledger in place. Both verify the generated output and fail on a finding.
// `verify --schema FILE --dir DIR` (verify.go) replays a written output's
// cases. `diffcheck` (diffcheck.go) compares a written output's controls
// with the content postconditions; generate and coverage run the same check
// (generate step 5) and need --policy-fixtures unless --no-diffcheck is
// given. `prune-schema` and `schemadiff` (schema.go) are the section 9
// schema-diff contract test.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/compliancetf/terraform-provider-aws/internal/bundlegen"
	"github.com/compliancetf/terraform-provider-aws/internal/upstream"
)

// Set with -ldflags "-X main.version=... -X main.commit=...".
// upstreamAddress is the upstream whose pins (--pins) build.json derives from.
// shortcut: aws only, like internal/bundlegen; per-wrapper generation is not implemented.
const upstreamAddress = "registry.terraform.io/hashicorp/aws"

var (
	version = "dev"
	commit  = "none"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ctf-bundlegen:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 && schemaCmds[args[0]] != nil {
		return schemaCmds[args[0]](args[1:])
	}
	if len(args) > 0 && args[0] == "verify" {
		return verifyCmd(args[1:])
	}
	if len(args) > 0 && args[0] == "diffcheck" {
		return diffcheckCmd(args[1:])
	}
	const usage = "usage: ctf-bundlegen verify --schema FILE --dir DIR | " + diffcheckUsage + " | generate|coverage --catalog DIR --intents FILE --schema FILE --lock FILE (--policy-fixtures FILE [--diffcheck-allow FILE] | --no-diffcheck) [--bumps FILE] [--authored DIR] [--iam-actions FILE] [--pins FILE] [--releases FILE] [--supported-schemas DIR] (generate: --out DIR; coverage: --ledger FILE)"
	if len(args) == 0 || args[0] != "generate" && args[0] != "coverage" {
		return fmt.Errorf("%s", usage)
	}
	cmd := args[0]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	catalog := fs.String("catalog", "", "catalog provider export directory (controls.json, provider_dispositions.json, frameworks_metadata.json, manifest.json)")
	intents := fs.String("intents", "", "content provider-intents.json")
	schema := fs.String("schema", "", "pruned `terraform providers schema -json` output")
	authored := fs.String("authored", "", "provider/controls directory of <id>.yaml authored controls")
	iam := fs.String("iam-actions", "", "iam-actions.json (cmd/iamcatalog), required when a bundle has an iam.* control")
	lock := fs.String("lock", "", "previous content-lock.json (a file holding {} for a fresh lock)")
	bumps := fs.String("bumps", "", "version_bump declarations (bumps.yaml)")
	out := fs.String("out", "dist/bundles", "generate: output directory")
	ledger := fs.String("ledger", "", "coverage: disposition ledger JSON, rewritten with generation_status")
	fixtures := fs.String("policy-fixtures", "", "content policy fixture export (content.policy-fixtures/1); required unless --no-diffcheck")
	allow := fs.String("diffcheck-allow", "", "diffcheck-allow.yaml accepted differences (absent: none)")
	pinsFile := fs.String("pins", "pins.json", "the provider's pins.json (repo root), the pinned hashicorp/aws version")
	releasesFile := fs.String("releases", "releases.json", "the provider's releases.json (repo root): the release floor, source of build.json provider and upstream version_range, and the supported releases")
	supported := fs.String("supported-schemas", "testdata/schemas/aws", "directory of <version>.json, the pruned schema of each supported release below the pin")
	noDiffcheck := fs.Bool("no-diffcheck", false, "skip diffcheck (no diffcheck.json; postcondition disagreements are not checked)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *catalog == "" || *intents == "" || *schema == "" || *lock == "" || cmd == "coverage" && *ledger == "" ||
		*noDiffcheck == (*fixtures != "") || *noDiffcheck && *allow != "" {
		return fmt.Errorf("%s", usage)
	}
	foreign := map[string]string{"generate": "ledger", "coverage": "out"}[cmd]
	var bad error
	fs.Visit(func(f *flag.Flag) {
		if f.Name == foreign {
			bad = fmt.Errorf("%s: --%s is not a %s flag; %s", cmd, foreign, cmd, usage)
		}
	})
	if bad != nil {
		return bad
	}
	in, err := bundlegen.LoadInputs(*catalog, *intents, *schema)
	if err != nil {
		return err
	}
	if in.Lock, err = bundlegen.LoadLock(*lock); err != nil {
		return err
	}
	if *bumps != "" {
		if in.Bumps, err = bundlegen.LoadBumps(*bumps); err != nil {
			return err
		}
	}
	if *authored != "" {
		a, err := bundlegen.LoadAuthored(*authored)
		if err != nil {
			return err
		}
		in.SetAuthored(a)
	}
	if *iam != "" {
		if in.IAMActions, err = bundlegen.LoadIAMActions(*iam); err != nil {
			return err
		}
	}
	if !*noDiffcheck {
		if in.PolicyFixtures, in.DiffAllow, err = loadDiffcheck(*fixtures, *allow); err != nil {
			return err
		}
	}
	// The pin is the one the provider embeds (repo root pins.json), checked
	// as the provider checks it; build.json version_range starts at the
	// releases.json floor.
	src, err := upstream.ParseSource(upstreamAddress)
	if err != nil {
		return err
	}
	rawPins, err := os.ReadFile(*pinsFile)
	if err != nil {
		return fmt.Errorf("%w (run from the repo root or pass --pins)", err)
	}
	pins, err := upstream.ParsePins(rawPins, src, upstream.HashiCorpFingerprint)
	if err != nil {
		return fmt.Errorf("%s: %w", *pinsFile, err)
	}
	releases, err := bundlegen.LoadReleases(*releasesFile)
	if err != nil {
		return err
	}
	older, err := releases.Older(pins.Version)
	if err != nil {
		return fmt.Errorf("%s: %w", *releasesFile, err)
	}
	if in.SupportedSchemas, err = bundlegen.LoadSupportedSchemas(*supported, older); err != nil {
		return err
	}
	// Cases name the schema as given: pass --schema relative to the replay
	// root so they do not depend on the machine.
	res, err := bundlegen.Generate(in, bundlegen.Options{GeneratorVersion: version, GeneratorCommit: commit,
		UpstreamPin: pins.Version, Releases: releases, CaseSchema: filepath.ToSlash(*schema)})
	if err != nil {
		return err
	}
	if res.Diffcheck != nil {
		printFindings(res.Diffcheck.Findings)
	}
	if cmd == "generate" {
		// Pending ids ship as a coverage gap; generate still succeeds.
		for _, r := range res.ReviewQueue {
			fmt.Fprintln(os.Stderr, r.PendingLine())
		}
		return res.WriteDir(*out)
	}
	return bundlegen.WriteLedger(in, res, *ledger)
}
