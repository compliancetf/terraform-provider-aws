package iampolicy

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// The benchmarks behind decodeCost and matchCost. Each reports the measured
// rate in the unit the constant charges:
//
//	go test ./internal/iampolicy -run NONE -bench Cost -count 6
//
// ns/byte: Normalize without a catalog (decode and statement normalization,
// what admitDecode charges per document byte). ns/unit: expandList time over
// scanCost(pat)/matchCost (every action scan visits, scaled by pattern
// length) against the release action catalog.

const releaseCatalog = "../../testdata/bundles/release-iam/iam-actions.json"

// costStatement is a customer-managed statement of about 450 bytes.
func costStatement(i int) string {
	return fmt.Sprintf(`{"Sid":"S%d","Effect":"Allow",`+
		`"Action":["s3:GetObject","s3:PutObject","s3:ListBucket","kms:Decrypt","kms:GenerateDataKey"],`+
		`"Resource":["arn:aws:s3:::bobthecorp-data-%d","arn:aws:s3:::bobthecorp-data-%d/*","arn:aws:kms:us-east-1:111122223333:key/%08d-1111-2222-3333-444455556666"],`+
		`"Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-bobthecorp1"},"Bool":{"aws:SecureTransport":"true"}}}`, i, i, i, i)
}

func costPolicy(n int) string {
	stmts := make([]string, n)
	for i := range stmts {
		stmts[i] = costStatement(i)
	}
	return policy(stmts...)
}

func BenchmarkDecodeCost(b *testing.B) {
	// dense is the most tokens per byte under MaxDocBytes: decoded in
	// full, then rejected (the top level is not an object).
	dense := "[" + strings.Repeat("0,", MaxDocBytes/2-2) + "0]"
	for _, tc := range []struct {
		name  string
		doc   string
		valid bool
	}{
		{"small", costPolicy(1), true},
		{"typical", costPolicy(13), true}, // about the 6,144-character managed policy quota
		{"max", costPolicy(MaxStatements), true},
		{"dense", dense, false},
	} {
		if len(tc.doc) > MaxDocBytes {
			b.Fatalf("%s: %d bytes over MaxDocBytes", tc.name, len(tc.doc))
		}
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(len(tc.doc)))
			for b.Loop() {
				if _, err := Normalize(tc.doc, Options{Partition: "aws"}); (err == nil) != tc.valid {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(tc.doc)+1), "ns/byte")
		})
	}
}

func BenchmarkMatchCost(b *testing.B) {
	raw, err := os.ReadFile(releaseCatalog)
	if err != nil {
		b.Fatal(err)
	}
	c, err := LoadCatalog(raw)
	if err != nil {
		b.Fatal(err)
	}
	for _, tc := range []struct{ name, pat string }{
		{"exact", "s3:getobject"},
		{"service-wildcard", "s3:*"},
		{"service-wildcard-ec2", "ec2:*"}, // the largest service
		{"partial-wildcard", "s3:get*"},
		{"cross-service", "*:get*"},
		// Worst cases of glob's single-star backtracking: after the last
		// star, k ?s restart at every name byte before "!" (never in a
		// name) fails. k sits just under each pattern-length step.
		{"backtrack-3", "*:*???!"},
		{"backtrack-11", "*:*" + strings.Repeat("?", 11) + "!"},
		{"backtrack-27", "*:*" + strings.Repeat("?", 27) + "!"},
		{"backtrack-64", "*:*" + strings.Repeat("?", 64) + "!"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			units := scanCost(c, tc.pat) / matchCost
			for b.Loop() {
				left := MaxExpandedActions
				if _, _, err := expandList(c, []string{tc.pat}, &left); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(units), "ns/unit")
		})
	}
}
