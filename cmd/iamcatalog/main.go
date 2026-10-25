// Command iamcatalog builds the IAM action catalog iam-actions.json from a
// downloaded snapshot of the AWS service reference: a
// directory holding one service document per *.json file, each
// {"Name": "<service prefix>", "Actions": [{"Name": "<action>"}, ...], ...}.
// The documents are the ones the index at
// https://servicereference.us-east-1.amazonaws.com/ links (field names
// checked against it on 2026-10-10; the documents also carry ConditionKeys,
// Operations, Resources and Version). Other files and other fields are
// ignored. Run by the bundle pipeline, never by the provider:
//
//	go run ./cmd/iamcatalog -source <dir> -retrieved 2026-10-01 -out iam-actions.json
//
// The output records -retrieved and the snapshot digest, sha256 over the
// sorted `sha256sum` lines ("<hex>  <file>\n") of the *.json files, so a
// rebuild from the same snapshot is byte-identical.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
)

func main() {
	if err := run(os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "iamcatalog:", err)
		os.Exit(1)
	}
}

func run(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("iamcatalog", flag.ContinueOnError)
	fs.SetOutput(stderr)
	source := fs.String("source", "", "directory with the service reference snapshot (*.json)")
	retrieved := fs.String("retrieved", "", "snapshot download date, YYYY-MM-DD")
	out := fs.String("out", iampolicy.CatalogFile, "output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *source == "" || *retrieved == "" || fs.NArg() > 0 {
		return errors.New("usage: iamcatalog -source <dir> -retrieved YYYY-MM-DD [-out iam-actions.json]")
	}
	b, err := build(*source, *retrieved)
	if err != nil {
		return err
	}
	return os.WriteFile(*out, b, 0o644)
}

type serviceDoc struct {
	Name    string `json:"Name"`
	Actions []struct {
		Name string `json:"Name"`
	} `json:"Actions"`
}

func build(dir, retrieved string) ([]byte, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no *.json files in %s", dir)
	}
	var sums bytes.Buffer
	services := map[string][]string{}
	for _, f := range files { // Glob returns sorted names
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(sum[:]), filepath.Base(f))
		var d serviceDoc
		if err := json.Unmarshal(b, &d); err != nil || d.Name == "" || len(d.Actions) == 0 {
			return nil, fmt.Errorf("%s: not a service reference document", filepath.Base(f))
		}
		svc := strings.ToLower(d.Name)
		if _, dup := services[svc]; dup {
			return nil, fmt.Errorf("%s: duplicate service %q", filepath.Base(f), svc)
		}
		for _, a := range d.Actions {
			services[svc] = append(services[svc], a.Name)
		}
	}
	snap := sha256.Sum256(sums.Bytes())
	b, err := iampolicy.EncodeCatalog(retrieved, "sha256:"+hex.EncodeToString(snap[:]), services)
	if err != nil {
		return nil, fmt.Errorf("snapshot does not fit %s (date, or a name outside [a-z0-9_-]): %w", iampolicy.CatalogFormat, err)
	}
	return b, nil
}
