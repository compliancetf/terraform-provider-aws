package main

import (
	"flag"
	"fmt"

	"github.com/compliancetf/terraform-provider-aws/internal/bundlegen"
	"github.com/compliancetf/terraform-provider-aws/internal/schemadiff"
)

// schemaCmds are the schema subcommands (prune-schema and friends).
var schemaCmds = map[string]func([]string) error{
	"prune-schema": pruneSchema,
	"schemadiff":   schemaDiff,
}

// pruneSchema writes the schema reduced to the content types plus every
// type name.
func pruneSchema(args []string) error {
	const usage = "usage: ctf-bundlegen prune-schema --content controls.json --schema FILE --out FILE"
	fs := flag.NewFlagSet("prune-schema", flag.ContinueOnError)
	content := fs.String("content", "", "controls.json whose types are kept (dist/bundles/all/controls.json)")
	schema := fs.String("schema", "", "`terraform providers schema -json` output")
	out := fs.String("out", "", "pruned schema file (testdata/schemas/aws/<version>.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *content == "" || *schema == "" || *out == "" || fs.NArg() > 0 {
		return fmt.Errorf("%s", usage)
	}
	cs, err := bundlegen.LoadControls(*content)
	if err != nil {
		return err
	}
	raw, err := bundlegen.ReadRegular(*schema)
	if err != nil {
		return err
	}
	data, err := bundlegen.PruneSchema(raw, cs)
	if err != nil {
		return err
	}
	return bundlegen.WriteFileAtomic(*out, data)
}

// schemaDiff writes schemadiff-report.json and fails on any fail check.
func schemaDiff(args []string) error {
	const usage = "usage: ctf-bundlegen schemadiff --content controls.json --base FILE --schema FILE [--out schemadiff-report.json]"
	fs := flag.NewFlagSet("schemadiff", flag.ContinueOnError)
	content := fs.String("content", "", "controls.json to check (dist/bundles/all/controls.json)")
	base := fs.String("base", "", "pruned schema the content was generated against")
	schema := fs.String("schema", "", "pruned schema of the new upstream version")
	out := fs.String("out", "schemadiff-report.json", "report file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *content == "" || *base == "" || *schema == "" || *out == "" || fs.NArg() > 0 {
		return fmt.Errorf("%s", usage)
	}
	cs, err := bundlegen.LoadControls(*content)
	if err != nil {
		return err
	}
	bs, err := bundlegen.LoadSchemas(*base)
	if err != nil {
		return err
	}
	ns, err := bundlegen.LoadSchemas(*schema)
	if err != nil {
		return err
	}
	r, err := schemadiff.Diff(cs, bs, ns)
	if err != nil {
		return err
	}
	data, err := r.JSON()
	if err != nil {
		return err
	}
	if err := bundlegen.WriteFileAtomic(*out, data); err != nil {
		return err
	}
	if r.Failed() {
		return fmt.Errorf("schemadiff: %s has failing checks", *out)
	}
	return nil
}
