package iampolicy

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// defaultBudget is the engine's default per-resource budget (celeng).
const defaultBudget = 50 * time.Millisecond

// charged is the smallest Budget Normalize admits doc under.
func charged(t *testing.T, doc string, c *Catalog) time.Duration {
	t.Helper()
	lo, hi := time.Duration(0), time.Hour
	for hi-lo > time.Microsecond {
		mid := lo + (hi-lo)/2
		if _, err := Normalize(doc, Options{Partition: "aws", Catalog: c, Budget: mid}); err == nil {
			hi = mid
		} else if isReason(err, ErrLimit, rAdmission) {
			lo = mid
		} else {
			t.Fatal(err)
		}
	}
	return hi
}

// literals is n catalog actions, round-robin over svcs.
func literals(c *Catalog, n int, svcs ...string) []string {
	l := make([]string, n)
	for i := range l {
		svc := svcs[i%len(svcs)]
		names := c.services[svc]
		l[i] = svc + ":" + names[(i/len(svcs))%len(names)]
	}
	return l
}

func quoted(l []string) string { return `"` + strings.Join(l, `","`) + `"` }

// nearQuota fills quota bytes with statements of six literal actions,
// resources and a condition, after one statement holding wildcards.
func nearQuota(t *testing.T, c *Catalog, quota int, principal bool, wildcards ...string) string {
	t.Helper()
	acts := literals(c, 6*MaxStatements, "ec2", "s3", "kms", "iam", "lambda", "dynamodb")
	who := ""
	if principal {
		who = `"Principal":{"AWS":"arn:aws:iam::111122223333:root"},`
	}
	stmts := []string{`{"Sid":"Wild","Effect":"Allow",` + who + `"Action":[` + quoted(wildcards) + `],"Resource":"*"}`}
	for i := 0; ; i++ {
		st := fmt.Sprintf(`{"Sid":"S%d","Effect":"Allow",%s"Action":[%s],`+
			`"Resource":["arn:aws:s3:::bobthecorp-data-%d","arn:aws:s3:::bobthecorp-data-%d/*"],`+
			`"Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-bobthecorp1"}}}`, i, who, quoted(acts[6*i:6*i+6]), i, i)
		if len(policy(append(stmts, st)...)) > quota {
			break
		}
		stmts = append(stmts, st)
	}
	doc := policy(stmts...)
	if len(doc) < quota-700 {
		t.Fatalf("%d bytes, want near %d", len(doc), quota)
	}
	return doc
}

// TestAdmissionRealistic: policies within the AWS size quotas are admitted
// under the default budget against the release catalog, with headroom for
// the controls evaluated before them; hostile shapes are limited.
func TestAdmissionRealistic(t *testing.T) {
	c := loadRelease(t)
	ec2 := make([]string, 50) // the first 50 actions of the largest service
	for i, n := range c.services["ec2"][:50] {
		ec2[i] = "ec2:" + n
	}
	admit := []struct{ name, doc string }{
		{"50 ec2 literals", policy(`{"Effect":"Allow","Action":[` + quoted(ec2) + `],"Resource":"*"}`)},
		{"managed 6 KB", nearQuota(t, c, 6144, false, "s3:Get*", "s3:List*")},
		{"inline role 10 KB", nearQuota(t, c, 10240, false, "ec2:Describe*", "logs:*")},
		{"bucket 20 KB", nearQuota(t, c, 20480, true, "s3:*")},
		{"key 32 KB", nearQuota(t, c, 32768, true, "kms:*", "kms:Describe*", "kms:Get*", "kms:List*")},
	}
	for _, tc := range admit {
		got := charged(t, tc.doc, c)
		t.Logf("%s: %d bytes, charged %v", tc.name, len(tc.doc), got)
		if got > defaultBudget/2 {
			t.Errorf("%s: charged %v, want at most half the default budget %v", tc.name, got, defaultBudget)
		}
		if _, err := Normalize(tc.doc, Options{Partition: "aws", Catalog: c, Budget: defaultBudget}); err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
	}

	backtrack := make([]string, 0, 10)
	for _, end := range "!#%&+=@^~|" {
		backtrack = append(backtrack, "*:*???"+string(end))
	}
	flood := make([]string, 0, MaxStatements)
	for len(policy(flood...)) < MaxDocBytes-4096 {
		flood = append(flood, `{"Effect":"Allow","Action":[`+quoted(ec2)+`],"Resource":"*"}`)
	}
	for _, tc := range []struct{ name, doc string }{
		{"dense 256 KB", "[" + strings.Repeat("0,", MaxDocBytes/2-2) + "0]"},
		{"literal flood", policy(flood...)},
		{"backtracking wildcards", policy(`{"Effect":"Allow","Action":[` + quoted(backtrack) + `],"Resource":"*"}`)},
		{"cross-service wildcards", policy(`{"Effect":"Allow","Action":["*:get*","*:list*","*:describe*","*:put*","*:create*","*:delete*"],"Resource":"*"}`)},
	} {
		if _, err := Normalize(tc.doc, Options{Partition: "aws", Catalog: c, Budget: defaultBudget}); !isReason(err, ErrLimit, rAdmission) {
			t.Errorf("%s (%d bytes): %v, want admission limit", tc.name, len(tc.doc), err)
		}
	}
}
