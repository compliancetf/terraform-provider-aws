//go:build unix

// Verdict files load only on unix (internal/verdict file_other.go).

package lifecycle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/breakglass"
	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict"
)

// signedReceipt is a consume receipt for the verdict verdicttest writes
// (verdictBinding), covering control on key, signed by a fresh receipt key
// the returned profile entry pins. It returns the receipt and its digest.
func signedReceipt(t *testing.T, l *Lifecycle, id, control, key string) (json.RawMessage, string, profile.SignerKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pin := profile.SignerKey{KID: trust.KIDFromSPKI(der), Alg: trust.AlgES256, Use: verdict.UseReceipt,
		SPKIB64: base64.StdEncoding.EncodeToString(der), NotBefore: verdictIssued.Add(-24 * time.Hour), NotAfter: verdictIssued.Add(24 * time.Hour)}
	d := &verdict.Document{OrgID: "bobthecorp", Workspace: "prod", Environment: "production", FloorEpoch: "3", ContentDigest: l.cfg.Content,
		PlanDigest: "sha256:4444444444444444444444444444444444444444444444444444444444444444"}
	r := &breakglass.Receipt{OverrideID: id, Controls: []string{control}, InstanceKeys: []string{key}}
	m := map[string]any{"format": breakglass.Format, "override_id": r.OverrideID, "org_id": d.OrgID, "run_id": "run-1",
		"override_digest": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
		"request_digest":  breakglass.RequestDigest(d, r), "controls": r.Controls, "instance_keys": r.InstanceKeys, "plan_digest": d.PlanDigest,
		"consumed_at": verdictIssued.Add(-10 * time.Minute).UTC().Format(time.RFC3339), "expires_at": verdictIssued.Add(6 * time.Hour).UTC().Format(time.RFC3339)}
	jcs := func() []byte {
		b, err := json.Marshal(m)
		if err == nil {
			b, err = bundle.CanonicalJSON(b)
		}
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	sum := sha256.Sum256(jcs())
	sig, err := ecdsa.SignASN1(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	m["signature"] = map[string]string{"kid": pin.KID, "alg": trust.AlgES256, "value": base64.RawURLEncoding.EncodeToString(sig)}
	raw := jcs()
	dg := sha256.Sum256(raw)
	return raw, "sha256:" + hex.EncodeToString(dg[:]), pin
}

// TestVerdictBreakGlassApply: an honored receipt downgrades exactly
// the covered graph fail from block to warning with results[].break_glass_id;
// a receipt the entry does not list, a disabled policy or an uncovered
// control keeps the block.
func TestVerdictBreakGlassApply(t *testing.T) {
	block := [][2]string{{"error", "s3_bucket_public_access_block_present: S3 bucket has no public access block. (graph control, decided by ctfkit gate for aws_s3_bucket.a)"}}
	for name, tc := range map[string]struct {
		unlisted, disabled, uncovered bool
		want                          [][2]string
		bgID                          string
	}{
		"honored":   {want: [][2]string{{"warning", block[0][1] + "; overridden by approved break-glass ovr-01"}}, bgID: "ovr-01"},
		"unlisted":  {unlisted: true, want: block},
		"uncovered": {uncovered: true, want: block},
		"disabled":  {disabled: true, want: append([][2]string{{"warning", "Break-glass receipt not honored"}}, block...)},
	} {
		t.Run(name, func(t *testing.T) {
			r := newSituationRun(t, false, pabGraph)
			key := r.key(t, verdict.FormCreate, bucketCfg, "")
			raw, digest, pin := signedReceipt(t, r.l, "ovr-01", pabGraph.ID, key)
			p := r.l.cfg.Resolution.Profile
			p.FloorMode = profile.FloorOnline
			p.BreakGlass = &profile.BreakGlass{Enabled: !tc.disabled, ReceiptKeys: []profile.SignerKey{pin}}
			r.l.cfg.BreakGlass = breakglass.Policy{Profile: p, FloorMode: profile.FloorOnline, Revocations: trust.NoRevocations(),
				Coverable: func(id string) bool { return !tc.uncovered && id == pabGraph.ID }}
			listed := []string{digest}
			if tc.unlisted {
				listed = nil
			}
			b := verdictBinding(r.l)
			b.Receipts = json.RawMessage("[" + string(raw) + "]")
			r.signWith(t, b, verdict.Instance{Address: "aws_s3_bucket.a", Type: "aws_s3_bucket", Action: "create", PriorIdentityKind: verdict.KindNone,
				InstanceKey: key, BreakGlass: listed,
				Decisions: []verdict.Decision{{Control: pabGraph.ID, Version: pabGraph.Version, Result: verdict.ResultFail, Action: "deny"}}})
			diags := r.apply(t, "null", bucketCfg)
			if d := sevSummaries(diags); !slices.Equal(d, tc.want) {
				t.Fatalf("diagnostics %v, want %v", d, tc.want)
			}
			if tc.disabled && !strings.Contains(diags[0].Detail, "the profile does not enable break_glass") {
				t.Fatalf("disabled policy warning %q lacks its reason", diags[0].Detail)
			}
			res := r.lastEval(t).Results
			if len(res) != 1 || res[0].BreakGlassID != tc.bgID || tc.bgID != "" && res[0].Decision != "warning" {
				t.Fatalf("results %+v, want break_glass_id %q", res, tc.bgID)
			}
		})
	}
}

// TestVerdictBreakGlassOverlap: two honored receipts cover the same control
// and key, only the later one is listed on the entry; the listed one applies
// (an unlisted earlier receipt never shadows it), whatever their order.
func TestVerdictBreakGlassOverlap(t *testing.T) {
	for _, listedFirst := range []bool{false, true} {
		r := newSituationRun(t, false, pabGraph)
		key := r.key(t, verdict.FormCreate, bucketCfg, "")
		rawA, _, pinA := signedReceipt(t, r.l, "ovr-a", pabGraph.ID, key)
		rawB, digestB, pinB := signedReceipt(t, r.l, "ovr-b", pabGraph.ID, key)
		p := r.l.cfg.Resolution.Profile
		p.FloorMode = profile.FloorOnline
		p.BreakGlass = &profile.BreakGlass{Enabled: true, ReceiptKeys: []profile.SignerKey{pinA, pinB}}
		r.l.cfg.BreakGlass = breakglass.Policy{Profile: p, FloorMode: profile.FloorOnline, Revocations: trust.NoRevocations(), Coverable: func(id string) bool { return id == pabGraph.ID }}
		b := verdictBinding(r.l)
		b.Receipts = json.RawMessage("[" + string(rawA) + "," + string(rawB) + "]")
		if listedFirst {
			b.Receipts = json.RawMessage("[" + string(rawB) + "," + string(rawA) + "]")
		}
		r.signWith(t, b, verdict.Instance{Address: "aws_s3_bucket.a", Type: "aws_s3_bucket", Action: "create", PriorIdentityKind: verdict.KindNone,
			InstanceKey: key, BreakGlass: []string{digestB},
			Decisions: []verdict.Decision{{Control: pabGraph.ID, Version: pabGraph.Version, Result: verdict.ResultFail, Action: "deny"}}})
		d := sevSummaries(r.apply(t, "null", bucketCfg))
		if len(d) != 1 || d[0][0] != "warning" || !strings.HasSuffix(d[0][1], "overridden by approved break-glass ovr-b") {
			t.Fatalf("listed first %v: diagnostics %v", listedFirst, d)
		}
		if res := r.lastEval(t).Results; len(res) != 1 || res[0].BreakGlassID != "ovr-b" {
			t.Fatalf("listed first %v: results %+v", listedFirst, res)
		}
	}
}
