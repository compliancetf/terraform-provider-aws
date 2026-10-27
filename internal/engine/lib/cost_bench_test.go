package lib

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
)

// The benchmarks behind decodeCost here and in iampolicy, and the
// policyValue cache charge:
//
//	go test ./internal/engine/lib -run NONE -bench Cost -count 6
//
// ns/byte is the time per document byte (plus one, as admission charges).

// costPolicy is n customer-managed statements of about 450 bytes each.
func costPolicy(n int) string {
	stmts := make([]string, n)
	for i := range stmts {
		stmts[i] = fmt.Sprintf(`{"Sid":"S%d","Effect":"Allow",`+
			`"Action":["s3:GetObject","s3:PutObject","s3:ListBucket","kms:Decrypt","kms:GenerateDataKey"],`+
			`"Resource":["arn:aws:s3:::bobthecorp-data-%d","arn:aws:s3:::bobthecorp-data-%d/*","arn:aws:kms:us-east-1:111122223333:key/%08d-1111-2222-3333-444455556666"],`+
			`"Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-bobthecorp1"},"Bool":{"aws:SecureTransport":"true"}}}`, i, i, i, i)
	}
	return `{"Version":"2012-10-17","Statement":[` + strings.Join(stmts, ",") + `]}`
}

var costDocs = []struct{ name, doc string }{
	{"small", costPolicy(1)},
	{"typical", costPolicy(13)}, // about the 6,144-character managed policy quota
	{"max", costPolicy(iampolicy.MaxStatements)},
}

const releaseCatalogFile = "../../../testdata/bundles/release-iam/iam-actions.json"

func releaseCatalog(b *testing.B) *iampolicy.Catalog {
	raw, err := os.ReadFile(releaseCatalogFile)
	if err != nil {
		b.Fatal(err)
	}
	c, err := iampolicy.LoadCatalog(raw)
	if err != nil {
		b.Fatal(err)
	}
	return c
}

func perByte(b *testing.B, doc string) {
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(doc)+1), "ns/byte")
}

// BenchmarkJSONDecodeCost is json.path's decode; dense is the most tokens
// per byte under MaxDocBytes.
func BenchmarkJSONDecodeCost(b *testing.B) {
	docs := slices.Concat(costDocs, []struct{ name, doc string }{{"dense", "[" + strings.Repeat("0,", MaxDocBytes/2-2) + "0]"}})
	for _, tc := range docs {
		if len(tc.doc) > MaxDocBytes {
			b.Fatalf("%s: %d bytes over MaxDocBytes", tc.name, len(tc.doc))
		}
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(len(tc.doc)))
			for b.Loop() {
				if _, _, err := decode(tc.doc); err != nil {
					b.Fatal(err)
				}
			}
			perByte(b, tc.doc)
		})
	}
}

// BenchmarkIAMParseCost is an uncached iam.parse against the release
// catalog: key, Normalize (decode, statements, expansion) and policyValue.
// actual/charged is its time over the admission estimate (the smallest
// Budget Normalize admits); above 1 the estimate lets the call overrun.
func BenchmarkIAMParseCost(b *testing.B) {
	cat := releaseCatalog(b)
	stmt := func(action string) string {
		return `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":` + action + `,"Resource":"*"}}`
	}
	var f struct{ Services map[string][]string }
	if raw, err := os.ReadFile(releaseCatalogFile); err != nil || json.Unmarshal(raw, &f) != nil {
		b.Fatal("release catalog unreadable")
	}
	ec2 := make([]string, 50) // the first 50 actions of the largest service
	for i := range ec2 {
		ec2[i] = `"ec2:` + f.Services["ec2"][i] + `"`
	}
	docs := slices.Concat(costDocs, []struct{ name, doc string }{
		{"literals-ec2", stmt("[" + strings.Join(ec2, ",") + "]")},
		{"service-wildcard", stmt(`"s3:*"`)},
		{"service-wildcard-ec2", stmt(`"ec2:*"`)},
		{"partial-wildcard", stmt(`"s3:Get*"`)},
		{"cross-service", stmt(`"*:Get*"`)},
		{"backtrack", stmt(`"*:*???!"`)},
	})
	for _, tc := range docs {
		b.Run(tc.name, func(b *testing.B) {
			charged := admitted(b, tc.doc, cat)
			b.SetBytes(int64(len(tc.doc)))
			for b.Loop() {
				if _, err := newDocCache(DefaultDocCacheBytes).iam(tc.doc, cat, "sha256:bench", time.Hour); err != nil {
					b.Fatal(err)
				}
			}
			perByte(b, tc.doc)
			b.ReportMetric(float64(b.Elapsed())/float64(b.N)/float64(charged), "actual/charged")
		})
	}
}

// admitted is the smallest Budget Normalize admits doc under.
func admitted(b *testing.B, doc string, cat *iampolicy.Catalog) time.Duration {
	lo, hi := time.Duration(0), time.Hour
	for hi-lo > 1 {
		mid := lo + (hi-lo)/2
		_, err := iampolicy.Normalize(doc, iampolicy.Options{Partition: "aws", Catalog: cat, Budget: mid})
		switch {
		case err == nil:
			hi = mid
		case errors.Is(err, iampolicy.ErrLimit):
			lo = mid
		default:
			b.Fatal(err)
		}
	}
	return hi
}

// BenchmarkIAMValueCost reports the heap a cached iam.parse value keeps over
// the charge policyValue returns for it (retained/charged; at most 1 keeps
// the cache within its cap).
func BenchmarkIAMValueCost(b *testing.B) {
	cat := releaseCatalog(b)
	for _, tc := range costDocs {
		b.Run(tc.name, func(b *testing.B) {
			p, err := iampolicy.Normalize(tc.doc, iampolicy.Options{Partition: "aws", Catalog: cat})
			if err != nil {
				b.Fatal(err)
			}
			held := max(16, 64<<20/len(tc.doc)/8)
			keep := make([]any, 0, held)
			var ratio float64
			for b.Loop() {
				keep = keep[:0]
				var before, after runtime.MemStats
				runtime.GC()
				runtime.ReadMemStats(&before)
				charged := 0
				for range held {
					v, n, err := policyValue(p, cat)
					if err != nil {
						b.Fatal(err)
					}
					keep = append(keep, v)
					charged += n
				}
				runtime.GC()
				runtime.ReadMemStats(&after)
				ratio = max(ratio, float64(int64(after.HeapAlloc)-int64(before.HeapAlloc))/float64(charged))
				runtime.KeepAlive(keep)
			}
			b.ReportMetric(ratio, "retained/charged")
		})
	}
}
