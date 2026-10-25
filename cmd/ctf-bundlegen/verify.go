package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/compliancetf/terraform-provider-aws/internal/bundlegen"
)

// verifyCmd replays the cases of a generated output directory against the
// pruned schema (bundlegen.Verify): it prints one line per finding to stderr
// and fails when there is any.
func verifyCmd(args []string) error {
	const usage = "usage: ctf-bundlegen verify --schema FILE --dir DIR"
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	schema := fs.String("schema", "", "pruned `terraform providers schema -json` output the bundles were generated against")
	dir := fs.String("dir", "", "generated output directory (ctf-bundlegen generate --out)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *schema == "" || *dir == "" || fs.NArg() > 0 {
		return errors.New(usage)
	}
	s, err := bundlegen.LoadSchemas(*schema)
	if err != nil {
		return err
	}
	out, err := bundlegen.ReadOutputDir(*dir)
	if err != nil {
		return err
	}
	rep, err := bundlegen.Verify(out, s, bundlegen.VerifyEngine())
	if err != nil {
		return err
	}
	for _, f := range rep.Findings {
		fmt.Fprintf(os.Stderr, "bundle %s: %s\n", f.Bundle, f)
	}
	if n := len(rep.Findings); n > 0 {
		return fmt.Errorf("verify: %d findings", n)
	}
	return nil
}
