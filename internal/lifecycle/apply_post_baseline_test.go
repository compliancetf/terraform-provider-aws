//go:build unix

package lifecycle

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/baseline"
	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/evidence"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict"
)

const (
	gfControl  = "rds_gf_deletion_protection"
	gfIdentity = `{"identifier":"db-1"}`
)

// readBaseline stands in for the signed matcher: it grandfathers gfControl
// for a verdict-matched, refreshed instance whose planned deletion_protection
// equals the prior one, under an entry named after the planned engine; an
// identity-kind entry names the identity gfIdentity.
type readBaseline struct{}

func (readBaseline) Grandfathered(ctl *bundle.Control, in baseline.Instance) baseline.Decision {
	if ctl.ID != gfControl || in.OrgID != "bobthecorp" || in.Refreshed != "true" {
		return baseline.Decision{}
	}
	if in.IdentityKind == verdict.KindIdentity && string(in.PriorIdentity) != gfIdentity {
		return baseline.Decision{}
	}
	if attrOf(in.Prior, "deletion_protection") != attrOf(in.Planned, "deletion_protection") {
		return baseline.Decision{}
	}
	return baseline.Decision{Grandfathered: true, Entry: "sha256:e-" + attrOf(in.Planned, "engine")}
}

func attrOf(v tftypes.Value, name string) string {
	var attrs map[string]tftypes.Value
	if !v.IsKnown() || v.IsNull() || v.As(&attrs) != nil {
		return "<none>"
	}
	return attrs[name].String()
}

// TestApplyPostKeepsBaselineMatch: under mode grandfather an
// update apply_pre grandfathers stays non-blocking at apply_post only while
// the same baseline entry still matches with NewState as the planned state.
// The apply_pre match reaches apply_post through Result.Carry; without it,
// or once upstream changed a read or the entry, the post-apply update errors.
func TestApplyPostKeepsBaselineMatch(t *testing.T) {
	const (
		prior   = `{"id":"db-1","engine":"postgres","deletion_protection":false,"storage_encrypted":true,"kms_key_id":"k"}`
		planned = `{"id":"db-1","engine":"postgres","deletion_protection":false,"storage_encrypted":true,"kms_key_id":"k2"}`
	)
	ctls, err := bundle.ParseControls([]byte(`[{"id": "` + gfControl + `", "version": "1.0.0", "kind": "resource", "resource_type": "aws_db_instance",
   "reads": ["deletion_protection"], "presence_mode": "effective", "on": ["create", "update"],
   "expr": "resource.deletion_protection == true", "action": "deny", "severity": "high",
   "message": "Keep deletion protection on.", "exemption_coverable": ["baseline"]}]`))
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		newState    string
		noCarry     bool
		identity    bool           // the plan carried an identity-kind prior identity
		newIdentity map[string]any // NewIdentity at apply_post
		want        hook.Severity
	}{
		"applied reads unchanged":   {newState: planned, want: hook.SeverityWarning},
		"no apply_pre carry":        {newState: planned, noCarry: true, want: hook.SeverityError},
		"upstream changed the read": {newState: `{"id":"db-1","engine":"postgres","deletion_protection":null,"storage_encrypted":true,"kms_key_id":"k2"}`, want: hook.SeverityError},
		"same reads, another entry": {newState: `{"id":"db-1","engine":"mysql","deletion_protection":false,"storage_encrypted":true,"kms_key_id":"k2"}`, want: hook.SeverityError},
		"identity kept":             {newState: planned, identity: true, newIdentity: map[string]any{"identifier": "db-1"}, want: hook.SeverityWarning},
		"identity changed upstream": {newState: planned, identity: true, newIdentity: map[string]any{"identifier": "db-2"}, want: hook.SeverityError},
		"no applied identity":       {newState: planned, identity: true, want: hook.SeverityError},
	} {
		t.Run(name, func(t *testing.T) {
			r := newSituationRun(t, true, ctls...)
			r.l.cfg.Table.RunMode = profile.Grandfather
			r.l.cfg.Baseline = readBaseline{}
			kind, priorID := verdict.KindID, `{"id":"db-1"}`
			if tc.identity {
				kind, priorID = verdict.KindIdentity, gfIdentity
			}
			r.sign(t, verdict.Instance{Address: "aws_db_instance.a", Type: "aws_db_instance", Action: "update", PriorIdentityKind: kind,
				Refreshed: "true", InstanceKey: r.keyOf(t, "aws_db_instance", verdict.FormUpdate, planned, priorID)})
			env := &hook.EnvelopeHeader{V: 1}
			env.CTF.Op, env.CTF.PriorIdentityKind = hook.OpUpdate, kind
			if tc.identity {
				env.CTF.PriorIdentity = json.RawMessage(gfIdentity)
			}
			pre, err := r.l.Evaluate(context.Background(), &hook.Request{Stage: hook.StageApplyPre, Kind: hook.KindResource, TypeName: "aws_db_instance",
				Op: hook.OpUpdate, Envelope: env, Config: dynValue(t, json.RawMessage(planned)), Prior: dynValue(t, json.RawMessage(prior)),
				Planned: dynValue(t, json.RawMessage(planned))})
			if err != nil {
				t.Fatal(err)
			}
			if d, ok := diagOf(pre.Diagnostics, gfControl); !ok || d.Severity != hook.SeverityWarning {
				t.Fatalf("apply_pre: %v, want the grandfathered warning", pre.Diagnostics)
			}
			post := &hook.Request{Stage: hook.StageApplyPost, Kind: hook.KindResource, TypeName: "aws_db_instance", Op: hook.OpUpdate,
				New: dynValue(t, json.RawMessage(tc.newState)), Identity: tc.newIdentity, Carry: pre.Carry}
			if tc.noCarry {
				post.Carry = nil
			}
			res, err := r.l.Evaluate(context.Background(), post)
			if err != nil {
				t.Fatal(err)
			}
			d, ok := diagOf(res.Diagnostics, gfControl)
			if !ok || d.Severity != tc.want {
				t.Fatalf("apply_post: %v, want severity %v", res.Diagnostics, tc.want)
			}
			if s := d.Summary + d.Detail; strings.Contains(s, "postgres") || strings.Contains(s, "mysql") || strings.Contains(s, "db-1") {
				t.Errorf("diagnostic carries a resource value: %q", s)
			}
			var got evidence.Result
			for _, x := range r.lastEval(t).Results {
				if x.Control == gfControl {
					got = x
				}
			}
			if got.State != "fail" || got.Decision != "post_apply_violation" {
				t.Errorf("evidence %+v, want fail / post_apply_violation", got)
			}
		})
	}
}

func diagOf(ds []hook.Diagnostic, id string) (hook.Diagnostic, bool) {
	for _, d := range ds {
		if strings.HasPrefix(d.Summary, "["+id+"]") {
			return d, true
		}
	}
	return hook.Diagnostic{}, false
}
