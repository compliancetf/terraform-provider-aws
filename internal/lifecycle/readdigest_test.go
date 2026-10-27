package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/baseline"
	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/evidence"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

// readDigestPrior is a pre-existing instance that fails the encryption
// control: the shape ctfkit baseline generation observes.
const readDigestPrior = `{"storage_encrypted": false, "kms_key_id": null, "engine": "postgres", "deletion_protection": true, "id": "db-bobthecorp-1"}`

// planRecord runs one plan of aws_db_instance with the baseline read key
// key (nil: COMPLIANCETF_BASELINE_KEY_FILE unset) and returns its eval record.
func planRecord(t *testing.T, key []byte, prior, planned string) evidence.Record {
	t.Helper()
	l := New(Options{})
	l.testPerResource = 10 * time.Second
	l.cfg = &Configured{Table: profile.ModeTable{RunMode: profile.HardFail}, Controls: stageControlSet(t), Schemas: dbSchemas{}, readKey: key}
	dir := t.TempDir()
	w, err := evidence.Open(evidence.Options{Dir: dir, Run: evidence.Run{ID: "r1", IDSource: "compliancetf"}})
	if err != nil {
		t.Fatal(err)
	}
	l.ev = w
	req := &hook.Request{Stage: hook.StagePlan, Kind: hook.KindResource, TypeName: "aws_db_instance", Op: hook.OpUpdate,
		Config: dynValue(t, json.RawMessage(planned)), Prior: dynValue(t, json.RawMessage(prior)), Planned: dynValue(t, json.RawMessage(planned))}
	if prior == "" {
		req.Op = hook.OpCreate
	}
	if _, err := l.Evaluate(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	var evals []evidence.Record
	for _, r := range readChain(t, dir) {
		if r.Kind == evidence.KindEval {
			evals = append(evals, r)
		}
	}
	if len(evals) != 1 || evals[0].Stage != "plan" {
		t.Fatalf("want one plan eval record, got %+v", evals)
	}
	return evals[0]
}

// goldenResults are the results of an internal/evidence record golden.
func goldenResults(t *testing.T, name string) []evidence.Result {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "evidence", "testdata", "records", name))
	if err != nil {
		t.Fatal(err)
	}
	var r evidence.Record
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r.Results
}

// TestPlanReadDigest: with COMPLIANCETF_BASELINE_KEY_FILE loaded, every plan
// result of an instance with a prior state carries read_digest, the
// baseline read digest of the control's reads over the prior state, which
// is what the baseline matcher compares at apply; without the key, and for
// a create (no prior state), no result does. The results are the
// internal/evidence goldens plan_read_digest.json and
// plan_no_read_digest.json.
func TestPlanReadDigest(t *testing.T) {
	key := bytes.Repeat([]byte{0xab}, 32)
	with := planRecord(t, key, readDigestPrior, readDigestPrior)
	if with.Resource.Op != "no-op" {
		t.Fatalf("op %s, want no-op", with.Resource.Op)
	}
	prior := objValue(t, json.RawMessage(readDigestPrior))
	all := stageControlSet(t).All()
	for _, r := range with.Results {
		i := slices.IndexFunc(all, func(c bundle.Control) bool { return c.ID == r.Control })
		if i < 0 {
			t.Fatalf("control %s not loaded", r.Control)
		}
		want, ok := baseline.ReadDigest(key, all[i].Reads, prior)
		if !ok || r.ReadDigest != want {
			t.Errorf("%s: read_digest %q, want %q", r.Control, r.ReadDigest, want)
		}
	}
	without := planRecord(t, nil, readDigestPrior, readDigestPrior)
	for name, got := range map[string][]evidence.Result{"plan_read_digest.json": with.Results, "plan_no_read_digest.json": without.Results} {
		g, _ := json.Marshal(got)
		w, _ := json.Marshal(goldenResults(t, name))
		if !bytes.Equal(g, w) {
			t.Errorf("%s results\n got %s\nwant %s", name, g, w)
		}
	}
	created := planRecord(t, key, "", readDigestPrior)
	if created.Resource.Op != "create" || len(created.Results) == 0 {
		t.Fatalf("create record %+v", created)
	}
	for _, r := range created.Results {
		if r.ReadDigest != "" {
			t.Errorf("create: %s carries read_digest", r.Control)
		}
	}
}

// TestBaselineReadKey: the key file is read only when
// COMPLIANCETF_BASELINE_KEY_FILE is set; a file that is not a usable key
// warns and no read_digest is written.
func TestBaselineReadKey(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "baseline.key")
	if err := os.WriteFile(good, []byte(strings.Repeat("ab", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "short.key")
	if err := os.WriteFile(bad, []byte("abab\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		path    string
		key     bool
		warning bool
	}{
		"unset": {"", false, false},
		"good":  {good, true, false},
		"bad":   {bad, false, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(baseline.EnvKeyFile, c.path)
			key, warns := baselineReadKey()
			if (key != nil) != c.key || (len(warns) > 0) != c.warning {
				t.Errorf("key %x, warnings %q", key, warns)
			}
			if c.key && !bytes.Equal(key, bytes.Repeat([]byte{0xab}, 32)) {
				t.Errorf("key %x", key)
			}
		})
	}
}
