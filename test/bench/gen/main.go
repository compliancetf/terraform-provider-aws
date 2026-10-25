// Command gen builds the benchmark fixture: n resource instances round-robin
// over the resource types of the
// captured hashicorp/aws schema subset, drawn from a seed.
//
//	go run ./test/bench/gen -seed 1 -n 500 -o instances.json
//
// The output is a compliancetf.bench-instances/v1 document; its sha256 digest
// goes to stderr. The same seed and schema give the same bytes.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	seed := flag.Uint64("seed", 1, "random seed")
	n := flag.Int("n", 500, "number of instances")
	schema := flag.String("schema", "testdata/schemas/aws-subset.json", "terraform providers schema -json file")
	out := flag.String("o", "", "output file (default stdout)")
	flag.Parse()
	raw, digest, err := build(*schema, *seed, *n)
	if err == nil && *out != "" {
		err = os.WriteFile(*out, raw, 0o644) //nolint:gosec // benchmark fixture, not a secret
	} else if err == nil {
		_, err = os.Stdout.Write(raw)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, digest)
}

// build returns the document for seed and n over the schema file at path, and
// its sha256 digest.
func build(path string, seed uint64, n int) (raw []byte, digest string, err error) {
	if n <= 0 {
		return nil, "", fmt.Errorf("-n %d: want a positive count", n)
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied schema path
	if err != nil {
		return nil, "", err
	}
	s, err := ParseSchema(data)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	instances, err := Generate(s, seed, n)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	doc := Doc{Format: Format, Seed: seed, N: n, SchemaSHA256: "sha256:" + hex.EncodeToString(sum[:]), Instances: instances}
	if raw, err = json.Marshal(doc); err != nil {
		return nil, "", err
	}
	raw = append(raw, '\n')
	sum = sha256.Sum256(raw)
	return raw, "sha256:" + hex.EncodeToString(sum[:]), nil
}
