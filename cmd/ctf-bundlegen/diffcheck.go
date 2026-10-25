package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/compliancetf/terraform-provider-aws/internal/bundlegen"
)

const diffcheckUsage = "diffcheck --schema FILE --dir DIR --intents FILE --policy-fixtures FILE [--diffcheck-allow FILE]"

// diffcheckCmd compares the controls of a generated output directory with
// the content postconditions of their intents (bundlegen.Diffcheck): it
// prints one line per finding to stderr and fails when any is E_. A
// directory written by generate has no E_DIFFCHECK_MISMATCH: generate moves
// such an id to the review queue.
func diffcheckCmd(args []string) error {
	const usage = "usage: ctf-bundlegen " + diffcheckUsage
	fs := flag.NewFlagSet("diffcheck", flag.ContinueOnError)
	schema := fs.String("schema", "", "pruned `terraform providers schema -json` output the bundles were generated against")
	dir := fs.String("dir", "", "generated output directory (ctf-bundlegen generate --out)")
	intents := fs.String("intents", "", "content provider-intents.json the bundles were generated from")
	fixtures := fs.String("policy-fixtures", "", "content policy fixture export (content.policy-fixtures/1)")
	allow := fs.String("diffcheck-allow", "", "diffcheck-allow.yaml accepted differences (absent: none)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *schema == "" || *dir == "" || *intents == "" || *fixtures == "" || fs.NArg() > 0 {
		return errors.New(usage)
	}
	s, err := bundlegen.LoadSchemas(*schema)
	if err != nil {
		return err
	}
	in, err := bundlegen.LoadIntents(*intents)
	if err != nil {
		return err
	}
	pf, al, err := loadDiffcheck(*fixtures, *allow)
	if err != nil {
		return err
	}
	out, err := bundlegen.ReadOutputDir(*dir)
	if err != nil {
		return err
	}
	rep, err := bundlegen.Diffcheck(out, in, *pf, al, s, bundlegen.VerifyEngine())
	if err != nil {
		return err
	}
	printFindings(rep.Findings)
	if rep.Failed() {
		return fmt.Errorf("diffcheck: E_ findings (see above)")
	}
	return nil
}

// loadDiffcheck loads the policy fixtures and, when allow is set, the
// allow entries.
func loadDiffcheck(fixtures, allow string) (*bundlegen.PolicyFixtures, []bundlegen.DiffAllow, error) {
	pf, err := bundlegen.LoadPolicyFixtures(fixtures)
	if err != nil {
		return nil, nil, err
	}
	var al []bundlegen.DiffAllow
	if allow != "" {
		if al, err = bundlegen.LoadDiffAllow(allow); err != nil {
			return nil, nil, err
		}
	}
	return &pf, al, nil
}

func printFindings(fs []bundlegen.Finding) {
	for _, f := range fs {
		if f.Bundle == "" {
			fmt.Fprintln(os.Stderr, f) // an allow entry, not a bundle's
			continue
		}
		fmt.Fprintf(os.Stderr, "bundle %s: %s\n", f.Bundle, f)
	}
}
