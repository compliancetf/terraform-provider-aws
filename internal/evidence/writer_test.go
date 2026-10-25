package evidence

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite testdata goldens")

const chainID = "c_1791201600000_0101010101010101"

func ptr[T any](v T) *T { return &v }

func digest(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

func testOpen(t *testing.T) (*Writer, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "evidence")
	clock := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	w, err := Open(Options{
		Dir:      dir,
		Run:      Run{ID: "bobthecorp-run-1", IDSource: "compliancetf", ClassClaimed: ptr("ci")},
		Provider: Provider{Address: "registry.compliance.tf/compliancetf/aws", Version: "2.0.0", UpstreamVersion: "6.0.0"},
		Now: func() time.Time {
			now := clock
			clock = clock.Add(time.Millisecond)
			return now
		},
		Rand: bytes.NewReader(bytes.Repeat([]byte{1}, 8)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return w, filepath.Join(dir, "bobthecorp-run-1")
}

func digests() *Digests {
	return &Digests{Bundle: ptr(digest('a')), Bundles: []string{digest('a')}, Profile: ptr(digest('b')),
		SchemaCompat: ptr(digest('c')), ControlVersions: ptr(digest('d'))}
}

func scope() *Scope {
	return &Scope{
		Workspace:   &Sourced{Source: "profile", Value: "bobthecorp-prod"},
		Environment: &Sourced{Source: "local", Value: "prod"},
		AccountID:   &Sourced{Source: "provider_config", Value: "111122223333"},
		Region:      &Sourced{Source: "provider_config", Value: "eu-west-1"},
	}
}

func configure() Record {
	return Record{Kind: KindConfigure, Event: "bundle_loaded", Mode: "hard_fail", Digests: digests(), Scope: scope(),
		Provider:      &Provider{Address: "registry.compliance.tf/compliancetf/aws", Version: "2.0.0", UpstreamVersion: "6.0.0"},
		Terraform:     &Terraform{Version: "1.14.0"},
		BundleSources: []BundleSource{{Digest: digest('a'), Source: "cache"}},
		CacheSkipped:  &CacheSkipped{Count: 2, Reasons: []string{"digest_mismatch", "unverified"}}}
}

func evalRecord(id string, results ...Result) Record {
	return Record{Kind: KindEval, Stage: "plan", Mode: "hard_fail", Digests: digests(), Scope: scope(),
		Resource: &Resource{Type: "aws_db_instance", Op: "create", ID: ptr(id), IdentityKind: "id"}, Results: results}
}

var passResult = Result{Control: "rds_storage_encrypted", Version: "2.0.0", State: "pass", Decision: "logged", Paths: []string{"storage_encrypted"}}

var failResult = Result{Control: "rds_backup_retention", Version: "2.0.0", State: "fail", Decision: "excepted",
	Paths: []string{"backup_retention_period"},
	Exception: &Exception{Source: "grant", ID: "bobthecorp-ex-1", Digest: digest('e'), Status: "applied",
		Expires: "2026-12-31T00:00:00Z", Workspace: ptr("bobthecorp-prod")}}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if want := readFile(t, p); !bytes.Equal(got, want) {
		t.Errorf("%s differs from the writer output; run go test -run TestGoldens -update\n got: %s", name, got)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// failOnce fails the next Write, after writing half the line when partial.
type failOnce struct {
	segFile
	partial, done bool
}

func (f *failOnce) Write(p []byte) (int, error) {
	if f.done {
		return f.segFile.Write(p)
	}
	f.done = true
	if f.partial {
		n, _ := f.segFile.Write(p[:len(p)/2])
		return n, errors.New("no space left on device")
	}
	return 0, errors.New("no space left on device")
}

func wantClass(t *testing.T, err error, class string) {
	t.Helper()
	var we *WriteError
	if !errors.As(err, &we) || we.Class != class {
		t.Fatalf("error = %v, want class %s", err, class)
	}
}

// TestGoldens regenerates the chain goldens through the writer.
func TestGoldens(t *testing.T) {
	w, dir := testOpen(t)
	must(t, w.Append(configure()))
	must(t, w.Append(evalRecord("db-bobthecorp-1", passResult)))
	must(t, w.AppendSync(evalRecord("db-bobthecorp-2", failResult)))
	must(t, w.Close())
	good := readFile(t, filepath.Join(dir, chainID+".jsonl"))
	golden(t, "chain-good.jsonl", good)
	golden(t, "chain-edited.jsonl", bytes.Replace(good, []byte("db-bobthecorp-1"), []byte("db-bobthecorp-9"), 1))

	w, dir = testOpen(t)
	must(t, w.Append(evalRecord("db-bobthecorp-1", passResult)))
	w.f = &failOnce{segFile: w.f}
	wantClass(t, w.Append(evalRecord("db-bobthecorp-2")), ClassWrite)
	must(t, w.Append(evalRecord("db-bobthecorp-3")))
	must(t, w.Close())
	golden(t, "chain-break.jsonl", readFile(t, filepath.Join(dir, chainID+".jsonl")))

	w, dir = testOpen(t)
	must(t, w.Append(evalRecord("db-bobthecorp-1", passResult)))
	w.f = &failOnce{segFile: w.f, partial: true}
	wantClass(t, w.Append(evalRecord("db-bobthecorp-2")), ClassWrite)
	must(t, w.Append(evalRecord("db-bobthecorp-3")))
	must(t, w.Close())
	golden(t, "chain-truncated.jsonl", readFile(t, filepath.Join(dir, chainID+".jsonl")))
	golden(t, "chain-segment.jsonl", readFile(t, filepath.Join(dir, chainID+".1.jsonl")))
	if fi, err := os.Stat(filepath.Join(dir, chainID+".1.jsonl")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("segment file mode: %v %v", fi, err)
	}
}

// The first golden line, written out by hand: proves the canonical (JCS)
// form independently of the serializer.
func TestLiteralLine(t *testing.T) {
	want := `{"chain":"c_1791201600000_0101010101010101","kind":"chain_start","prev":null,` +
		`"provider":{"address":"registry.compliance.tf/compliancetf/aws","upstream_version":"6.0.0","version":"2.0.0"},` +
		`"run":{"class_claimed":"ci","id":"bobthecorp-run-1","id_source":"compliancetf"},"seq":0,"ts":"2026-10-05T12:00:00.001Z","v":1}`
	got, _, _ := bytes.Cut(goodLines(t)[0], []byte("\n"))
	if string(got) != want {
		t.Errorf("line 1:\n got %s\nwant %s", got, want)
	}
}

func TestRejectsValues(t *testing.T) {
	w, _ := testOpen(t)
	bad := map[string]Record{
		"quoted map key path": evalRecord("x", Result{Control: "c", Version: "1", State: "fail", Decision: "blocked", Paths: []string{`tags["password"]`}}),
		"value in err":        evalRecord("x", Result{Control: "c", Version: "1", State: "fail", Decision: "blocked", Err: "secret-value"}),
		"quote in id":         evalRecord(`i-"x"`),
		"U+2028 in id":        evalRecord("i-\u2028"),
		"control char in id":  evalRecord("i-\x01"),
		"invalid utf8 in id":  evalRecord("i-\xff"),
		"identity key":        {Kind: KindEval, Stage: "plan", Mode: "hard_fail", Digests: digests(), Scope: scope(), Resource: &Resource{Type: "aws_s3_bucket", Op: "create", IdentityKind: "identity", Identity: map[string]string{"Bucket Name": "b"}}},
		"chain_end by caller": {Kind: KindChainEnd},
		"configure with results": func() Record {
			r := configure()
			r.Results = []Result{passResult}
			return r
		}(),
		"bundle_sources on eval": func() Record {
			r := evalRecord("x")
			r.BundleSources = []BundleSource{{Digest: digest('a'), Source: "cache"}}
			return r
		}(),
		"unknown bundle source": func() Record {
			r := configure()
			r.BundleSources[0].Source = "/home/bobthecorp/.cache"
			return r
		}(),
		"unknown skip reason": func() Record {
			r := configure()
			r.CacheSkipped.Reasons = []string{"sha256-x.tar.gz"}
			return r
		}(),
		"repeated skip reason": func() Record {
			r := configure()
			r.CacheSkipped.Reasons = []string{"unverified", "unverified"}
			return r
		}(),
		"skip count over the cap": func() Record {
			r := configure()
			r.CacheSkipped.Count = maxCount + 1
			return r
		}(),
		"unsorted skip reasons": func() Record {
			r := configure()
			r.CacheSkipped.Reasons = []string{"unverified", "digest_mismatch"}
			return r
		}(),
		"null skip reasons": func() Record {
			r := configure()
			r.CacheSkipped.Reasons = nil
			return r
		}(),
		"configure without terraform": func() Record {
			r := configure()
			r.Terraform = nil
			return r
		}(),
	}
	big := evalRecord("x")
	for range 20000 {
		big.Digests.Exceptions = append(big.Digests.Exceptions, digest('f'))
	}
	bad["oversize"] = big
	for name, r := range bad {
		t.Run(name, func(t *testing.T) { wantClass(t, w.Append(r), ClassInvalid) })
	}
	atCap := configure()
	atCap.CacheSkipped.Count = maxCount // the boundary itself is valid
	must(t, w.Append(atCap))
	must(t, w.Append(evalRecord("x"))) // an invalid record never dirties the chain
	must(t, w.Close())
	must(t, w.Close())
	wantClass(t, w.Append(evalRecord("x")), ClassClosed)
}

// failSync fails the next Sync.
type failSync struct {
	segFile
	done bool
}

func (f *failSync) Sync() error {
	if f.done {
		return f.segFile.Sync()
	}
	f.done = true
	return errors.New("i/o error")
}

// A sync failure leaves the record committed: no chain_break, chain valid.
func TestSyncFailureCommits(t *testing.T) {
	w, dir := testOpen(t)
	w.f = &failSync{segFile: w.f}
	wantClass(t, w.AppendSync(evalRecord("db-bobthecorp-1")), ClassSync)
	must(t, w.AppendSync(evalRecord("db-bobthecorp-2")))
	must(t, w.Close())
	sum, err := Verify(bytes.NewReader(readFile(t, filepath.Join(dir, chainID+".jsonl"))))
	if err != nil || sum.Records != 4 || sum.Breaks != 0 || !sum.Terminated {
		t.Fatalf("Verify = %+v, %v", sum, err)
	}
}

// A failed dir fsync on segment creation never drops or duplicates the
// record: it is written once and the durable write retries the fsync.
func TestSegmentDirSyncRetried(t *testing.T) {
	w, dir := testOpen(t)
	w.f = &failOnce{segFile: w.f, partial: true}
	wantClass(t, w.Append(evalRecord("db-bobthecorp-1")), ClassWrite)
	fails := 1
	w.dirSync = func(d *os.File) error {
		if fails > 0 {
			fails--
			return errors.New("i/o error")
		}
		return syncDir(d)
	}
	must(t, w.AppendSync(evalRecord("db-bobthecorp-2")))
	if w.dirPending || fails != 0 {
		t.Fatalf("dir fsync not retried: pending=%v", w.dirPending)
	}
	must(t, w.Close())
	b := readFile(t, filepath.Join(dir, chainID+".1.jsonl"))
	if n := bytes.Count(b, []byte("db-bobthecorp-2")); n != 1 {
		t.Fatalf("record written %d times", n)
	}
	if sum, err := Verify(bytes.NewReader(b)); err != nil || sum.Records != 3 || !sum.Segment {
		t.Fatalf("Verify = %+v, %v", sum, err)
	}
}

func TestOpenRejects(t *testing.T) {
	if _, err := Open(Options{Dir: t.TempDir(), Run: Run{ID: "../escape"}}); err == nil {
		t.Error("unsafe run id accepted")
	}
	if runtime.GOOS == "windows" {
		return
	}
	dir := t.TempDir()
	must(t, os.Chmod(dir, 0o777))
	if _, err := Open(Options{Dir: dir, Run: Run{ID: "r1"}}); err == nil {
		t.Error("world-writable evidence dir accepted")
	}
	dir = t.TempDir()
	must(t, os.Mkdir(filepath.Join(dir, "r1"), 0o755))
	if _, err := Open(Options{Dir: dir, Run: Run{ID: "r1"}}); err == nil {
		t.Error("run dir with group/other bits accepted")
	}
	dir = t.TempDir()
	must(t, os.Symlink(t.TempDir(), filepath.Join(dir, "r1")))
	if _, err := Open(Options{Dir: dir, Run: Run{ID: "r1"}}); err == nil {
		t.Error("run dir symlink leaving the evidence dir accepted")
	}
}

func TestRunFromEnv(t *testing.T) {
	env := func(kv ...string) func(string) string {
		return func(k string) string {
			for i := 0; i < len(kv); i += 2 {
				if kv[i] == k {
					return kv[i+1]
				}
			}
			return ""
		}
	}
	cases := []struct {
		env        func(string) string
		id, source string
	}{
		{env("COMPLIANCETF_RUN_ID", "../../etc", "GITHUB_RUN_ID", "42"), "42-1", "github"},
		{env("GITHUB_RUN_ID", "42", "GITHUB_RUN_ATTEMPT", "3", "TFC_RUN_ID", "run-x"), "42-3", "github"},
		{env("COMPLIANCETF_RUN_ID", "bobthecorp-1", "TFC_RUN_ID", "run-x"), "bobthecorp-1", "compliancetf"},
		{env("CI_PIPELINE_ID", "7"), "7", "gitlab"},
	}
	for _, tc := range cases {
		if r := RunFromEnv(tc.env); r.ID != tc.id || r.IDSource != tc.source {
			t.Errorf("RunFromEnv = %+v, want %s/%s", r, tc.id, tc.source)
		}
	}
	r := RunFromEnv(env("SPACELIFT_RUN_ID", "a/b", "COMPLIANCETF_RUN_CLASS", "ci prod"))
	if r.IDSource != "random" || !reRunToken.MatchString(r.ID) || r.ClassClaimed != nil {
		t.Errorf("fallback = %+v", r)
	}
}
