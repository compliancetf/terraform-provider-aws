package iampolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

const fixtureCatalog = "../../testdata/iam/actions-fixture.json"

func loadFixture(t testing.TB) *Catalog {
	t.Helper()
	b, err := os.ReadFile(fixtureCatalog)
	if err != nil {
		t.Fatal(err)
	}
	c, err := LoadCatalog(b)
	if err != nil {
		t.Fatalf("fixture catalog: %v", err)
	}
	sum := sha256.Sum256(b)
	if c.Digest() != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("digest %s is not sha256 of the file bytes", c.Digest())
	}
	return c
}

// genCatalog is a canonical catalog with one service "svc" of n actions.
func genCatalog(t testing.TB, n int) *Catalog {
	t.Helper()
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf(`"a%05d"`, i)
	}
	b := `{"format":"compliancetf.iam-actions/v1","retrieved":"2026-10-01","services":{"svc":[` +
		strings.Join(names, ",") + `]},"snapshot":"sha256:` + strings.Repeat("0", 64) + `","source":"aws-service-reference"}`
	c, err := LoadCatalog([]byte(b))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func policy(stmts ...string) string {
	return `{"Version":"2012-10-17","Statement":[` + strings.Join(stmts, ",") + `]}`
}

func TestExpand(t *testing.T) {
	c := loadFixture(t)
	for _, tc := range []struct {
		name                  string
		stmt                  string
		expanded, notExpanded []string
		unresolved            []string
	}{
		{"wildcard", `{"Effect":"Allow","Action":"kms:Create*","Resource":"*"}`,
			[]string{"kms:createalias", "kms:creategrant", "kms:createkey"}, nil, nil},
		{"question_mark", `{"Effect":"Allow","Action":["s3:?etObject","S3:PutObject"],"Resource":"*"}`,
			[]string{"s3:getobject", "s3:putobject"}, nil, nil},
		{"service_wildcard", `{"Effect":"Allow","Action":"*:Describe*","Resource":"*"}`,
			[]string{"ec2:describeinstances", "ec2:describevolumes"}, nil, nil},
		{"overlap_deduped", `{"Effect":"Allow","Action":["kms:*crypt","kms:Decrypt"],"Resource":"*"}`,
			[]string{"kms:decrypt", "kms:encrypt"}, nil, nil},
		{"star_is_flag", `{"Effect":"Allow","Action":"*","Resource":"*"}`, nil, nil, nil},
		{"not_action", `{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}`,
			nil, []string{"iam:attachrolepolicy", "iam:createrole", "iam:getrole", "iam:passrole"}, nil},
		{"not_action_star_is_flag", `{"Effect":"Deny","NotAction":"*","Resource":"*"}`, nil, nil, nil},
		{"unknown_service", `{"Effect":"Allow","Action":["kms:Decrypt","bobthecorp:Get*"],"Resource":"*"}`,
			[]string{"kms:decrypt"}, nil, []string{"bobthecorp:get*"}},
		{"unknown_action", `{"Effect":"Allow","Action":"kms:NoSuchAction","Resource":"*"}`,
			nil, nil, []string{"kms:nosuchaction"}},
		{"empty_wildcard", `{"Effect":"Allow","NotAction":"s3:Zzz*","Resource":"*"}`,
			nil, nil, []string{"s3:zzz*"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Normalize(policy(tc.stmt), Options{Partition: "aws", Catalog: c})
			if err != nil {
				t.Fatal(err)
			}
			if p.Catalog != c.Digest() {
				t.Fatalf("catalog %q, want %q", p.Catalog, c.Digest())
			}
			st := p.Statements[0]
			for _, f := range []struct {
				name      string
				got, want []string
			}{
				{"actions_expanded", st.ActionsExpanded, tc.expanded},
				{"not_actions_expanded", st.NotActionsExpanded, tc.notExpanded},
				{"unresolved_actions", st.UnresolvedActions, tc.unresolved},
			} {
				if f.want == nil {
					f.want = []string{}
				}
				if !slices.Equal(f.got, f.want) {
					t.Errorf("%s = %v, want %v", f.name, f.got, f.want)
				}
			}
		})
	}
}

func TestExpandLimit(t *testing.T) {
	over, at := genCatalog(t, MaxExpandedActions+1), genCatalog(t, MaxExpandedActions)
	all := `{"Effect":"Allow","Action":"svc:*","Resource":"*"}`
	if _, err := Normalize(policy(all), Options{Catalog: over}); !isReason(err, ErrLimit, rExpanded) {
		t.Fatalf("10,001 expanded actions: %v, want limit %s", err, rExpanded)
	}
	p, err := Normalize(policy(all), Options{Catalog: at})
	if err != nil || len(p.Statements[0].ActionsExpanded) != MaxExpandedActions {
		t.Fatalf("10,000 expanded actions: %v", err)
	}
	// The bound is summed over the document, Action and NotAction alike.
	half := genCatalog(t, MaxExpandedActions/2+1)
	not := `{"Effect":"Deny","NotAction":"svc:a*","Resource":"*"}`
	if _, err := Normalize(policy(all, not), Options{Catalog: half}); !isReason(err, ErrLimit, rExpanded) {
		t.Fatalf("two statements over the bound: %v", err)
	}
	// * is a flag and never counts against the bound; beside it
	// actions_expanded stays empty while misses still report unresolved.
	p, err = Normalize(policy(`{"Effect":"Allow","Action":["*","svc:*","nope:x"],"Resource":"*"}`), Options{Catalog: over})
	if err != nil || len(p.Statements[0].ActionsExpanded) != 0 || !slices.Equal(p.Statements[0].UnresolvedActions, []string{"nope:x"}) {
		t.Fatalf("Action * with other patterns: %v %+v", err, p)
	}
	if _, err := Normalize(policy(`{"Effect":"Allow","Action":"*","Resource":"*"}`), Options{Catalog: over}); err != nil {
		t.Fatalf("Action *: %v", err)
	}
}

func TestExpandAdmission(t *testing.T) {
	c := genCatalog(t, MaxExpandedActions)
	// Over budget before decode: limit without decoding (the invalid JSON
	// would otherwise be type_error).
	if _, err := Normalize(`{"Statement":`, Options{Catalog: c, Budget: time.Nanosecond}); !isReason(err, ErrLimit, rAdmission) {
		t.Fatalf("pre-decode admission: %v", err)
	}
	// Decode fits, the expansion scan does not: limit before expanding.
	doc := policy(`{"Effect":"Allow","Action":["svc:a1*","svc:a2*","svc:a3*"],"Resource":"*"}`)
	decodeOnly := time.Duration(len(doc)+1) * decodeCost
	if _, err := Normalize(doc, Options{Catalog: c, Budget: decodeOnly + matchCost}); !isReason(err, ErrLimit, rAdmission) {
		t.Fatalf("pre-expansion admission: %v", err)
	}
	// Charged per scanned action, not per scanned service: one service of
	// 10,000 actions costs far more than 100 actions' worth.
	wild := policy(`{"Effect":"Allow","Action":"*:a1*","Resource":"*"}`)
	if _, err := Normalize(wild, Options{Catalog: c, Budget: time.Duration(len(wild)+1)*decodeCost + 100*matchCost}); !isReason(err, ErrLimit, rAdmission) {
		t.Fatalf("scan charged per service: %v", err)
	}
	// Longer patterns cost more per action (glob is linear in the pattern).
	if scanCost(c, "svc:a*"+strings.Repeat("?", 64)) <= scanCost(c, "svc:a*") {
		t.Fatal("pattern length not charged")
	}
	// expandCost is charged per action a pattern can add: one for a literal
	// (found or not), every scanned action for a wildcard, none for "*".
	for pat, want := range map[string]int{"svc:a00001": 1, "svc:a1*": MaxExpandedActions, "*:a?": MaxExpandedActions, "nope:x": 1, "*": 0} {
		if got := addBound(c, pat); got != want {
			t.Errorf("addBound(%q) = %d, want %d", pat, got, want)
		}
	}
	// Literal-service patterns are charged that service only, so a Resource
	// wildcard or a large catalog elsewhere does not false-limit.
	if _, err := Normalize(doc, Options{Catalog: c, Budget: 50 * time.Millisecond}); err != nil {
		t.Fatalf("within budget: %v", err)
	}
}

func TestGrants(t *testing.T) {
	c := loadFixture(t)
	stmt := func(s string, cat *Catalog) Statement {
		t.Helper()
		p, err := Normalize(policy(s), Options{Partition: "aws", Catalog: cat})
		if err != nil {
			t.Fatal(err)
		}
		return p.Statements[0]
	}
	allow := stmt(`{"Effect":"Allow","Action":["kms:Create*","s3:GetObject"],"Resource":"*"}`, c)
	not := stmt(`{"Effect":"Allow","NotAction":"kms:*","Resource":"*"}`, c)
	star := stmt(`{"Effect":"Allow","Action":"*","Resource":"*"}`, c)
	notStar := stmt(`{"Effect":"Allow","NotAction":"*","Resource":"*"}`, c)
	for _, tc := range []struct {
		name   string
		st     Statement
		action string
		want   bool
	}{
		{"glob_match", allow, "kms:CreateKey", true},
		{"glob_no_match", allow, "kms:decrypt", false},
		{"concrete", allow, "s3:getobject", true},
		{"action_all", star, "iam:passrole", true},
		{"not_action_excludes", not, "kms:decrypt", false},
		{"not_action_grants", not, "iam:passrole", true},
		{"not_action_star", notStar, "iam:passrole", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Grants(tc.st, c, tc.action)
			if err != nil || got != tc.want {
				t.Fatalf("Grants = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		st     Statement
		cat    *Catalog
		action string
	}{
		{"catalog_miss", allow, c, "kms:nosuchaction"},
		{"catalog_miss_action_all", star, c, "bobthecorp:getthing"},
		{"unresolved_pattern", stmt(`{"Effect":"Allow","Action":["kms:Decrypt","kms:Zzz*"],"Resource":"*"}`, c), c, "kms:decrypt"},
		{"no_catalog_at_parse", stmt(`{"Effect":"Allow","Action":"kms:Decrypt","Resource":"*"}`, nil), c, "kms:decrypt"},
		{"other_catalog", stmt(`{"Effect":"Allow","Action":"svc:*","Resource":"*"}`, genCatalog(t, 3)), c, "kms:decrypt"},
		{"nil_catalog", allow, nil, "kms:decrypt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Grants(tc.st, tc.cat, tc.action); !isReason(err, ErrUnresolved, "") {
				t.Fatalf("Grants error %v, want unresolved", err)
			}
		})
	}

	all := stmt(`{"Effect":"Allow","Action":"kms:*","Resource":"*"}`, c)
	if ok, err := GrantsAll(all, c, "kms"); !ok || err != nil {
		t.Fatalf("GrantsAll kms:* = %v %v", ok, err)
	}
	if ok, err := GrantsAll(allow, c, "kms"); ok || err != nil {
		t.Fatalf("GrantsAll kms:Create* = %v %v", ok, err)
	}
	if ok, err := GrantsAll(not, c, "iam"); !ok || err != nil {
		t.Fatalf("GrantsAll NotAction kms:* over iam = %v %v", ok, err)
	}
	if _, err := GrantsAll(star, c, "bobthecorp"); !isReason(err, ErrUnresolved, "") {
		t.Fatalf("GrantsAll unknown service: %v", err)
	}
	var e *Error
	if _, err := Grants(allow, c, "kms:nosuchaction"); !errors.As(err, &e) || e.Class() != "unresolved" {
		t.Fatalf("catalog miss class: %v", err)
	}
}

func TestLoadCatalog(t *testing.T) {
	good, err := os.ReadFile(fixtureCatalog)
	if err != nil {
		t.Fatal(err)
	}
	sub := func(old, new string) []byte { return []byte(strings.Replace(string(good), old, new, 1)) }
	for name, b := range map[string][]byte{
		"not_json":         []byte("{"),
		"trailing_newline": append(slices.Clone(good), '\n'),
		"pretty":           sub(`{"format"`, "{\n  \"format\""),
		"unknown_key":      sub(`"source":`, `"x":"y","source":`),
		"format":           sub(`iam-actions/v1`, `iam-actions/v2`),
		"source":           sub(`"aws-service-reference"`, `"other"`),
		"retrieved":        sub(`2026-10-01`, `2026-13-01`),
		"snapshot":         sub(`sha256:0000`, `sha256:zz00`),
		"unsorted_actions": sub(`"getrole","passrole"`, `"passrole","getrole"`),
		"duplicate_action": sub(`"getrole","passrole"`, `"getrole","getrole"`),
		"upper_case":       sub(`"getrole"`, `"GetRole"`),
		"bad_charset":      sub(`"getrole"`, `"get:role"`),
		"empty_service":    sub(`"ec2":["describeinstances","describevolumes","runinstances","terminateinstances"]`, `"ec2":[]`),
		"no_services":      []byte(`{"format":"compliancetf.iam-actions/v1","retrieved":"2026-10-01","services":{},"snapshot":"sha256:` + strings.Repeat("0", 64) + `","source":"aws-service-reference"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadCatalog(b); !isReason(err, ErrInvalid, rCatalog) {
				t.Fatalf("LoadCatalog: %v, want invalid %s", err, rCatalog)
			}
		})
	}
}

func isReason(err, class error, reason string) bool {
	var e *Error
	return errors.As(err, &e) && errors.Is(err, class) && (reason == "" || e.Reason == reason)
}
