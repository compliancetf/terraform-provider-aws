//go:build conformance

package verdict

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/baseline"
	"github.com/compliancetf/terraform-provider-aws/internal/lifecycle"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict/verdicttest"
	"github.com/compliancetf/terraform-provider-aws/test/conformance/harness"
)

// rotationTF creates one fake_thing that no control denies, so a verdict
// that loads lets the apply through and one that does not blocks it.
const rotationTF = `terraform {
  required_providers {
    fake = { source = "registry.compliance.tf/compliancetf/aws" }
  }
}

resource "fake_thing" "r" {
  name = "rotation"
  size = 5
}
`

// rotKey is a generated key of use valid from nb to na. Every rotation key
// is generated here, never read from a key file.
func rotKey(t *testing.T, use string, nb, na time.Time) verdicttest.Key {
	t.Helper()
	k := verdicttest.NewKey(t, nb)
	k.Signer.Use, k.Signer.NotAfter = use, na
	return k
}

func signers(ks ...verdicttest.Key) []profile.SignerKey {
	out := make([]profile.SignerKey, len(ks))
	for i, k := range ks {
		out[i] = k.Signer
	}
	return out
}

// flat drops Terraform's diagnostic border and line wrapping.
func flat(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "\u2502", " ")), " ")
}

// applied reports whether r's state holds fake_thing.r.
func applied(r *run) bool {
	rs, _ := r.State()["resources"].([]any)
	for _, x := range rs {
		if m, _ := x.(map[string]any); m["type"] == "fake_thing" && m["name"] == "r" {
			return true
		}
	}
	return false
}

// TestRotationVerdictKeys: a verdict verifies only against the
// verdict keys of the floor-validated profile at apply time. During a
// rotation overlap both kids verify; a kid rotated out of the profile, a
// kid revoked by the profile or the bundle revocations.json, a kid outside its window and a kid listed for another use
// block the apply, which is never forwarded.
func TestRotationVerdictKeys(t *testing.T) {
	now := time.Now().UTC()
	old := rotKey(t, verdict.UseVerdict, now.Add(-48*time.Hour), now.Add(48*time.Hour))
	cur := rotKey(t, verdict.UseVerdict, now.Add(-time.Hour), now.Add(48*time.Hour))
	closed := rotKey(t, verdict.UseVerdict, now.Add(-48*time.Hour), now.Add(-time.Hour))
	future := rotKey(t, verdict.UseVerdict, now.Add(time.Hour), now.Add(48*time.Hour))
	bl := rotKey(t, verdict.UseBaseline, now.Add(-time.Hour), now.Add(48*time.Hour))
	for _, c := range []struct {
		name    string
		listed  []verdicttest.Key
		revoked []string       // profile revoked_kids
		bundle  []string       // revoked_keys of the bundle revocations.json
		other   map[string]any // more profile members
		signer  verdicttest.Key
		block   string // "" applies
	}{
		{name: "overlap_old_kid", listed: []verdicttest.Key{old, cur}, signer: old},
		{name: "overlap_new_kid", listed: []verdicttest.Key{old, cur}, signer: cur},
		{name: "rotated_out", listed: []verdicttest.Key{cur}, signer: old, block: "Verdict signature invalid: kid unknown"},
		{name: "revoked", listed: []verdicttest.Key{old, cur}, revoked: []string{old.Signer.KID}, signer: old, block: "Verdict signature invalid: kid revoked"},
		{name: "revoked_other_kid", listed: []verdicttest.Key{old, cur}, revoked: []string{old.Signer.KID}, signer: cur},
		{name: "bundle_revoked", listed: []verdicttest.Key{old, cur}, bundle: []string{old.Signer.KID}, signer: old, block: "Verdict signature invalid: kid revoked"},
		{name: "bundle_revoked_other_kid", listed: []verdicttest.Key{old, cur}, bundle: []string{old.Signer.KID}, signer: cur},
		{name: "window_closed", listed: []verdicttest.Key{closed, cur}, signer: closed, block: "Verdict signature invalid: key not valid at this time"},
		{name: "window_not_open", listed: []verdicttest.Key{future, cur}, signer: future, block: "Verdict signature invalid: key not valid at this time"},
		{name: "baseline_kid_signs_verdict", listed: []verdicttest.Key{cur}, signer: bl, block: "Verdict signature invalid: kid unknown",
			other: map[string]any{"baseline": map[string]any{"public_keys": signers(bl), "max_days": 90}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			prof := map[string]any{"verdict": map[string]any{"public_keys": signers(c.listed...)}}
			if c.revoked != nil {
				prof["revoked_kids"] = c.revoked
			}
			for k, v := range c.other {
				prof[k] = v
			}
			r := newRun(t, rotationTF, runOpt{Profile: prof})
			revokeInBundle(t, r, c.bundle)
			r.Must("plan", "-no-color", "-input=false")
			b := r.loaded()
			b.IssuedAt = time.Now().UTC().Add(-time.Minute)
			r.Sign(c.signer, b)
			res := r.TF("apply", "-auto-approve", "-no-color", "-input=false")
			out, done := flat(res.Stdout+res.Stderr), applied(r)
			switch {
			case c.block == "" && (res.Exit != 0 || !done):
				t.Fatalf("exit %d, applied %v; want the apply through\n%s", res.Exit, done, out)
			case c.block != "" && (res.Exit == 0 || done || !strings.Contains(out, c.block)):
				t.Fatalf("exit %d, applied %v; want blocked with %q\n%s", res.Exit, done, c.block, out)
			}
		})
	}
}

// TestRotationBaselineAndReceiptKeys: a baseline verifies only
// against baseline keys, its approver statement only against receipt keys
// of the profile, both at Configure. Overlapping kids verify; a rotated-out
// kid, or one revoked by the profile or the bundle revocations.json, fails
// Configure, so the plan never runs.
func TestRotationBaselineAndReceiptKeys(t *testing.T) {
	now := time.Now().UTC()
	nb, na := now.Add(-48*time.Hour), now.Add(48*time.Hour)
	blOld, blCur := rotKey(t, verdict.UseBaseline, nb, na), rotKey(t, verdict.UseBaseline, nb, na)
	rcOld, rcCur := rotKey(t, verdict.UseReceipt, nb, na), rotKey(t, verdict.UseReceipt, nb, na)
	for _, c := range []struct {
		name           string
		bl, rc         []verdicttest.Key
		revoked        []string // profile revoked_kids
		bundle         []string // revoked_keys of the bundle revocations.json
		blSign, rcSign verdicttest.Key
		fail           string // "" plans
	}{
		{name: "overlap_old_kids", bl: []verdicttest.Key{blOld, blCur}, rc: []verdicttest.Key{rcOld, rcCur}, blSign: blOld, rcSign: rcOld},
		{name: "overlap_new_kids", bl: []verdicttest.Key{blOld, blCur}, rc: []verdicttest.Key{rcOld, rcCur}, blSign: blCur, rcSign: rcCur},
		{name: "baseline_rotated_out", bl: []verdicttest.Key{blCur}, rc: []verdicttest.Key{rcCur}, blSign: blOld, rcSign: rcCur,
			fail: "baseline signature invalid: kid unknown"},
		{name: "baseline_revoked", bl: []verdicttest.Key{blOld, blCur}, rc: []verdicttest.Key{rcCur}, revoked: []string{blOld.Signer.KID}, blSign: blOld, rcSign: rcCur,
			fail: "baseline signature invalid: kid revoked"},
		{name: "receipt_rotated_out", bl: []verdicttest.Key{blCur}, rc: []verdicttest.Key{rcCur}, blSign: blCur, rcSign: rcOld,
			fail: "approver_statement signature invalid"},
		{name: "receipt_revoked", bl: []verdicttest.Key{blCur}, rc: []verdicttest.Key{rcOld, rcCur}, revoked: []string{rcOld.Signer.KID}, blSign: blCur, rcSign: rcOld,
			fail: "approver_statement signature invalid"},
		{name: "baseline_bundle_revoked", bl: []verdicttest.Key{blOld, blCur}, rc: []verdicttest.Key{rcCur}, bundle: []string{blOld.Signer.KID}, blSign: blOld, rcSign: rcCur,
			fail: "baseline signature invalid: kid revoked"},
		{name: "receipt_bundle_revoked", bl: []verdicttest.Key{blCur}, rc: []verdicttest.Key{rcOld, rcCur}, bundle: []string{rcOld.Signer.KID}, blSign: blCur, rcSign: rcOld,
			fail: "approver_statement signature invalid"},
	} {
		t.Run(c.name, func(t *testing.T) {
			prof := map[string]any{"baseline": map[string]any{"public_keys": signers(c.bl...), "max_days": 90},
				"break_glass": map[string]any{"enabled": false, "receipt_keys": signers(c.rc...)}}
			if c.revoked != nil {
				prof["revoked_kids"] = c.revoked
			}
			r := newRun(t, rotationTF, runOpt{Profile: prof})
			revokeInBundle(t, r, c.bundle)
			writeBaseline(t, r, c.blSign, c.rcSign, now)
			res := r.TF("plan", "-no-color", "-input=false")
			out := flat(res.Stdout + res.Stderr)
			switch {
			case c.fail == "" && res.Exit != 0:
				t.Fatalf("exit %d; want the plan to run\n%s", res.Exit, out)
			case c.fail != "" && (res.Exit == 0 || !strings.Contains(out, c.fail)):
				t.Fatalf("exit %d; want Configure to fail with %q\n%s", res.Exit, c.fail, out)
			}
		})
	}
}

// revokeInBundle rebuilds r's signed bundle with a revocations.json that
// revokes kids; none leaves the bundle as built.
func revokeInBundle(t *testing.T, r *run, kids []string) {
	t.Helper()
	if len(kids) == 0 {
		return
	}
	keys := make([]map[string]string, len(kids))
	for i, k := range kids {
		keys[i] = map[string]string{"kid": k, "revoked_at": time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)}
	}
	b, err := json.Marshal(map[string]any{"format": "compliancetf.revocations/v1", "epoch": 1,
		"revoked_keys": keys, "revoked_bundles": []any{}, "revoked_controls": []any{}})
	src := filepath.Join(r.Work, "bundle-src")
	if err == nil {
		err = os.WriteFile(filepath.Join(src, "revocations.json"), b, 0o600)
	}
	if err != nil {
		t.Fatal(err)
	}
	harness.Ctfbundle(t, "build", "-src", src, "-key", "test:bundle", "-out", filepath.Join(r.Work, "bundle.tar.gz"))
}

// writeBaseline signs a one-entry baseline with bl, its approver statement
// with rc, and points the run at it and a generated baseline key file.
func writeBaseline(t *testing.T, r *run, bl, rc verdicttest.Key, now time.Time) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "internal", "baseline", "testdata", "entry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var e baseline.Entry
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("c", 64)
	e.ControlManifestDigest, e.ReadDigest, e.Expires = digest, digest, now.Add(30*24*time.Hour).Format(time.RFC3339)
	issued := now.Add(-time.Hour).Format(time.RFC3339)
	st := baseline.Statement{Format: baseline.StatementFormat, OrgID: "bobthecorp", Role: baseline.RoleApprover, Subject: e.Approver,
		Workspace: e.Workspace, Scope: e.Scope, RunID: "run-obs-1", PlanDigest: "sha256:" + strings.Repeat("d", 64), ContentDigest: digest, IssuedAt: issued}
	if err := json.Unmarshal(signed(t, rc, st), &e.ApproverStatement); err != nil {
		t.Fatal(err)
	}
	doc := baseline.Document{Format: baseline.Format, OrgID: "bobthecorp", IssuedAt: issued, ContentDigest: digest, Entries: []baseline.Entry{e}}
	file, key := filepath.Join(r.Work, "baseline.json"), filepath.Join(r.Work, "baseline.key")
	if err := os.WriteFile(file, signed(t, bl, doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte(strings.Repeat("ab", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.Env = append(r.Env, baseline.EnvFile+"="+file, baseline.EnvKeyFile+"="+key)
}

// signed returns v signed by k (its signature member replaced).
func signed(t *testing.T, k verdicttest.Key, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	var m map[string]json.RawMessage
	if err == nil {
		err = json.Unmarshal(b, &m)
	}
	if err != nil {
		t.Fatal(err)
	}
	delete(m, "signature")
	sig, err := json.Marshal(verdicttest.Signature(t, k.Priv, k.Signer.KID, m))
	if err != nil {
		t.Fatal(err)
	}
	m["signature"] = sig
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRotationVerdictRequiredPreview: until the GA flag is set, a
// profile with verdict_required gets the preview warning at Configure; a
// profile without it does not.
func TestRotationVerdictRequiredPreview(t *testing.T) {
	const want = "Profile sets verdict_required, which is in preview"
	if !strings.HasPrefix(lifecycle.PreviewVerdictRequired, want) {
		t.Fatalf("preview text changed: %q", lifecycle.PreviewVerdictRequired)
	}
	for _, required := range []bool{true, false} {
		r := newRun(t, rotationTF, runOpt{Required: required})
		// -json: the human view folds Configure warnings of one summary.
		res := r.TF("plan", "-json", "-input=false")
		out := res.Stdout + res.Stderr
		if res.Exit != 0 || strings.Contains(out, want) != required {
			t.Fatalf("verdict_required %v: exit %d, preview warning %v\n%s", required, res.Exit, strings.Contains(out, want), out)
		}
	}
}
