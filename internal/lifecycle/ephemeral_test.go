package lifecycle

import (
	"context"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/evidence"
	"github.com/compliancetf/terraform-provider-aws/internal/exceptions"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
	"github.com/compliancetf/terraform-provider-aws/test/scrub/scrubtest"
)

const ephType = "aws_secretsmanager_random_password"

// ephObject is the request config type of ephType: two arguments and the
// Computed-only result, which no control may read.
var ephObject = tftypes.Object{AttributeTypes: map[string]tftypes.Type{
	"password_length":    tftypes.Number,
	"exclude_characters": tftypes.String,
	"random_password":    tftypes.String,
}}

// ephSchemas serves ephType as an ephemeral resource only.
type ephSchemas struct{}

func (ephSchemas) Resource(string) (*tfprotov5.Schema, bool)   { return nil, false }
func (ephSchemas) DataSource(string) (*tfprotov5.Schema, bool) { return nil, false }
func (ephSchemas) EphemeralResource(typ string) (*tfprotov5.Schema, bool) {
	if typ != ephType {
		return nil, false
	}
	return &tfprotov5.Schema{Block: &tfprotov5.SchemaBlock{Attributes: []*tfprotov5.SchemaAttribute{
		{Name: "exclude_characters", Type: tftypes.String, Optional: true},
		{Name: "password_length", Type: tftypes.Number, Optional: true},
		{Name: "random_password", Type: tftypes.String, Computed: true, Sensitive: true},
	}}}, true
}

// ephControls: a deny and a warn ephemeral control on ephType, and a
// resource control of the same type name that the open must never run.
const ephControls = `[
 {"id": "eph_min_length", "version": "1.0.0", "kind": "ephemeral", "resource_type": "aws_secretsmanager_random_password",
  "reads": ["password_length"], "expr": "config.password_length == null || config.password_length >= 14",
  "action": "deny", "severity": "high", "message": "Password length must be at least 14.", "fix": "Set password_length to 14 or more.",
  "exemption_coverable": []},
 {"id": "eph_no_excludes", "version": "1.0.0", "kind": "ephemeral", "resource_type": "aws_secretsmanager_random_password",
  "reads": ["exclude_characters"], "expr": "config.exclude_characters == null",
  "action": "warn", "severity": "low", "message": "Excluded characters weaken the password."},
 {"id": "res_same_name", "version": "1.0.0", "kind": "resource", "resource_type": "aws_secretsmanager_random_password",
  "reads": ["password_length"], "presence_mode": "configured", "on": ["create", "update"], "expr": "false",
  "action": "deny", "severity": "high", "message": "resource control"}
]`

func ephControlSet(t *testing.T) *bundle.ControlSet { return ephControlSetWith(t, ephControls) }

func ephControlSetWith(t *testing.T, controlsJSON string) *bundle.ControlSet {
	t.Helper()
	mraw, err := os.ReadFile("testdata/stages/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	m, err := bundle.DecodeManifest(mraw)
	if err != nil {
		t.Fatal(err)
	}
	controls, err := bundle.ParseControls([]byte(controlsJSON))
	if err != nil {
		t.Fatal(err)
	}
	b := &bundle.Bundle{Manifest: m, Digest: "sha256:" + strings.Repeat("ee", 32), Controls: controls, Revocations: trust.NoRevocations()}
	cs, _, err := bundle.NewControlSet("bobthecorp", time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC), trust.NoRevocations(), b)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// ephConfig is a request config value; length nil is null, -1 unknown.
func ephConfig(length int64, exclude string) *hook.Value {
	l := tftypes.NewValue(tftypes.Number, nil)
	switch {
	case length < 0:
		l = tftypes.NewValue(tftypes.Number, tftypes.UnknownValue)
	case length > 0:
		l = tftypes.NewValue(tftypes.Number, big.NewFloat(float64(length)))
	}
	e := tftypes.NewValue(tftypes.String, nil)
	if exclude != "" {
		e = tftypes.NewValue(tftypes.String, exclude)
	}
	v := tftypes.NewValue(ephObject, map[string]tftypes.Value{"password_length": l, "exclude_characters": e,
		"random_password": tftypes.NewValue(tftypes.String, nil)})
	dv, err := tfprotov5.NewDynamicValue(ephObject, v)
	if err != nil {
		panic(err)
	}
	return hook.NewValue(dv.MsgPack, nil, func() (tftypes.Type, error) { return ephObject, nil })
}

const ephBlocked = "Opening ephemeral aws_secretsmanager_random_password was blocked; the secret was not opened."

// TestEphemeralOpen: ephemeral_open evaluates the ephemeral
// controls of the type on the request config only, takes the apply_pre
// column of the severity matrix, writes one value-free ephemeral_open/open
// record and never runs a resource control of the same type name. A marker
// in the config never reaches a diagnostic or the evidence.
func TestEphemeralOpen(t *testing.T) {
	marker := scrubtest.Marker(1)
	cases := []struct {
		name      string
		mode      profile.Mode
		length    int64
		exclude   string
		schemas   bool // false: no upstream schema, every control not_evaluable
		diags     []string
		decisions []string // eph_min_length, eph_no_excludes
		states    []string
	}{
		{name: "hard_fail blocks", mode: profile.HardFail, length: 8, exclude: marker, schemas: true,
			diags:     []string{"error:[eph_min_length] Password length must be at least 14.", "warning:[eph_no_excludes] Excluded characters weaken the password."},
			decisions: []string{"blocked", "warning"}, states: []string{"fail", "fail"}},
		{name: "hard_fail pass", mode: profile.HardFail, length: 20, schemas: true,
			decisions: []string{"logged", "logged"}, states: []string{"pass", "pass"}},
		{name: "null length passes", mode: profile.HardFail, schemas: true,
			decisions: []string{"logged", "logged"}, states: []string{"pass", "pass"}},
		{name: "soft_fail warns", mode: profile.SoftFail, length: 8, schemas: true,
			diags:     []string{"warning:[eph_min_length] Password length must be at least 14."},
			decisions: []string{"warning", "logged"}, states: []string{"fail", "pass"}},
		{name: "advisory logs", mode: profile.Advisory, length: 8, exclude: marker, schemas: true,
			decisions: []string{"logged", "logged"}, states: []string{"fail", "fail"}},
		{name: "unknown blocks", mode: profile.HardFail, length: -1, schemas: true,
			diags:     []string{"error:[eph_min_length] Password length must be at least 14."},
			decisions: []string{"blocked", "logged"}, states: []string{"unknown", "pass"}},
		{name: "not_evaluable blocks", mode: profile.HardFail, length: 20, exclude: marker,
			diags:     []string{"error:[eph_min_length] Password length must be at least 14.", "warning:[eph_no_excludes] not evaluable (unresolved)"},
			decisions: []string{"blocked", "warning"}, states: []string{"not_evaluable", "not_evaluable"}},
	}
	cs := ephControlSet(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, evDir := ephLifecycle(t, cs, tc.mode)
			if !tc.schemas {
				l.cfg.Schemas = dbSchemas{}
			}
			res, err := l.Evaluate(context.Background(), &hook.Request{Stage: hook.StageEphemeralOpen, Kind: hook.KindEphemeral,
				TypeName: ephType, Config: ephConfig(tc.length, tc.exclude)})
			if err != nil {
				t.Fatal(err)
			}
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, d := range res.Diagnostics {
				sev := "error"
				if d.Severity == hook.SeverityWarning {
					sev = "warning"
				}
				got = append(got, sev+":"+d.Summary)
				scrubtest.NoMarker(t, "diagnostic", d.Summary+d.Detail)
				blocked := strings.HasPrefix(d.Detail, ephBlocked+"\n")
				if blocked != (d.Severity == hook.SeverityError) || blocked && !strings.Contains(d.Detail, "\nStage: ephemeral_open\n") {
					t.Errorf("detail of %q:\n%s", d.Summary, d.Detail)
				}
			}
			if !slices.Equal(got, tc.diags) {
				t.Errorf("diagnostics %q, want %q", got, tc.diags)
			}
			recs := readChain(t, evDir)
			want := &wantEvidence{Op: "open", Results: []wantResult{
				{Control: "eph_min_length", State: tc.states[0], Decision: tc.decisions[0]},
				{Control: "eph_no_excludes", State: tc.states[1], Decision: tc.decisions[1]}}}
			checkEvalRecord(t, recs, "ephemeral_open", ephType, want)
			// control_versions is the digest of the ephemeral controls, not the
			// res_same_name stamp of the managed resource type.
			wantVersions := cs.VersionsDigestOf(ephType, bundle.KindEphemeral)
			for _, r := range recs {
				if r.Resource != nil && (r.Resource.ID != nil || r.Resource.IdentityKind != "none") {
					t.Errorf("ephemeral record names an object: %+v", r.Resource)
				}
				if r.Stage == "ephemeral_open" && (r.Digests == nil || r.Digests.ControlVersions == nil || *r.Digests.ControlVersions != wantVersions) {
					t.Errorf("ephemeral_open control_versions = %+v, want %s", r.Digests, wantVersions)
				}
			}
			if err := filepath.WalkDir(evDir, func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return err
				}
				b, err := os.ReadFile(p)
				scrubtest.NoMarker(t, "evidence", string(b))
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func ephLifecycle(t *testing.T, cs *bundle.ControlSet, mode profile.Mode) (*Lifecycle, string) {
	t.Helper()
	l := New(Options{})
	l.testPerResource = 10 * time.Second
	l.cfg = &Configured{Table: profile.ModeTable{RunMode: mode}, Controls: cs,
		Block: Block{ExceptionsFile: "compliance-exceptions.hcl"}, Schemas: ephSchemas{}}
	evDir := t.TempDir()
	w, err := evidence.Open(evidence.Options{Dir: evDir, Run: evidence.Run{ID: "r1", IDSource: "compliancetf"}})
	if err != nil {
		t.Fatal(err)
	}
	l.ev = w
	return l, evDir
}

// TestEphemeralOpenFailsClosed: before Configure, without a config, or with
// evidence.required and no evidence chain, the open is blocked (an error or
// an error diagnostic), and no ephemeral_open record claims a decision.
func TestEphemeralOpenFailsClosed(t *testing.T) {
	cs := ephControlSet(t)
	req := func() *hook.Request {
		return &hook.Request{Stage: hook.StageEphemeralOpen, Kind: hook.KindEphemeral, TypeName: ephType, Config: ephConfig(20, "")}
	}
	if _, err := New(Options{}).Evaluate(context.Background(), req()); err == nil || !strings.Contains(err.Error(), "before Configure") {
		t.Errorf("unconfigured: %v", err)
	}
	l, _ := ephLifecycle(t, cs, profile.HardFail)
	r := req()
	r.Config = nil
	if _, err := l.Evaluate(context.Background(), r); err == nil || !strings.Contains(err.Error(), "without config") {
		t.Errorf("no config: %v", err)
	}
	_ = l.Close() //nolint:errcheck // test cleanup

	l, _ = ephLifecycle(t, cs, profile.HardFail)
	_ = l.ev.Close() //nolint:errcheck // the chain is unavailable
	l.ev, l.evClass = nil, evidence.ClassOpen
	l.cfg.Resolution.Profile = &profile.Profile{Evidence: profile.Evidence{Required: true}}
	res, err := l.Evaluate(context.Background(), req())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Diagnostics) != 1 || res.Diagnostics[0].Severity != hook.SeverityError || res.Diagnostics[0].Summary != "Evidence required" ||
		!strings.HasSuffix(res.Diagnostics[0].Detail, "profile requires evidence before opening an ephemeral resource") {
		t.Errorf("evidence required, chain unavailable: %+v, want one Evidence required error", res.Diagnostics)
	}
}

// TestWantsEphemeral: an unconfigured Lifecycle wants every ephemeral type
// (Evaluate then fails closed); a configured one only types with an
// ephemeral control, and a resource control of the same name does not count.
func TestWantsEphemeral(t *testing.T) {
	l := New(Options{})
	if !l.Wants(hook.KindEphemeral, "aws_anything") {
		t.Error("unconfigured Lifecycle must want every ephemeral type")
	}
	l.cfg = &Configured{Controls: ephControlSet(t)}
	if !l.Wants(hook.KindEphemeral, ephType) || l.Wants(hook.KindEphemeral, "aws_kms_secrets") {
		t.Error("configured Wants(ephemeral) must follow the ephemeral controls")
	}
	l.cfg = &Configured{Controls: stageControlSet(t)}
	if l.Wants(hook.KindEphemeral, "aws_db_instance") {
		t.Error("a resource control must not make its type wanted as ephemeral")
	}
}

// TestEphemeralOpenNotCoverable: a verified signed grant and a self-service
// sidecar entry that both name eph_min_length, whose exemption_coverable is
// empty, waive nothing: the open is still blocked and recorded blocked. The
// same entries on the control made coverable waive it (excepted), so the
// entries do resolve and match an ephemeral control.
func TestEphemeralOpenNotCoverable(t *testing.T) {
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	sel := "type == 'aws_secretsmanager_random_password'"
	coverable := strings.Replace(ephControls, `"exemption_coverable": []`, `"exemption_coverable": ["grant", "self_service"]`, 1)
	if coverable == ephControls {
		t.Fatal("ephControls lost its empty exemption_coverable")
	}
	setups := map[string]func(*testing.T, *Configured){
		"grant": func(t *testing.T, c *Configured) {
			c.Table.Exceptions = &profile.Exceptions{GrantKeys: []profile.GrantKey{customerGrantKey(t)}}
			cov, _ := exceptions.NewCoverability(c.Controls.Coverable(), c.Table.Exceptions)
			p := grantPayload([]string{"eph_min_length"}, sel, "2026-10-20T00:00:00Z")
			p["content_digest"] = c.Controls.ContentDigest(cov.Kinds())
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "g.dsse.json"), grantEnvelope(t, p, testkeys.CustomerKMS()), 0o600); err != nil {
				t.Fatal(err)
			}
			c.Block.GrantsDir = dir
			grants, _, err := loadGrants(c.Block, c.Table, c.Controls, cov, "bobthecorp", now, exceptions.Clock{}, 0)
			if err != nil {
				t.Fatal(err)
			}
			c.Grants = grants
		},
		"self_service": func(t *testing.T, c *Configured) {
			// The profile widens nothing: only the bundle declares coverability.
			c.Table.Exceptions = &profile.Exceptions{SelfService: []string{"eph_min_length"}, MaxLifetimeDays: 180, Coverable: map[string][]string{}}
			c.Table.SidecarControls = []string{"eph_min_length"}
			f := filepath.Join(t.TempDir(), "exceptions.hcl")
			hcl := "exception \"eph-length\" {\n  controls  = [\"eph_min_length\"]\n  match     = \"" + sel +
				"\"\n  workspace = \"bobthecorp-reporting-prod\"\n  reason    = \"Rotation in progress, OPS-4411\"\n  expires   = \"2027-01-01\"\n}\n"
			if err := os.WriteFile(f, []byte(hcl), 0o600); err != nil {
				t.Fatal(err)
			}
			c.Block.ExceptionsFile = f
			cov, _ := exceptions.NewCoverability(c.Controls.Coverable(), c.Table.Exceptions)
			side, _, err := loadSidecar(c.Block, c.Table, c.Controls, cov, now, exceptions.Clock{})
			if err != nil {
				t.Fatal(err)
			}
			c.Sidecar = side
		},
	}
	for _, tc := range []struct {
		name, controls, decision string
	}{
		{"grant", ephControls, "blocked"}, {"self_service", ephControls, "blocked"},
		{"grant", coverable, "excepted"}, {"self_service", coverable, "excepted"},
	} {
		name, setup := tc.name, setups[tc.name]
		t.Run(name+"/"+tc.decision, func(t *testing.T) {
			cs := ephControlSetWith(t, tc.controls)
			l, evDir := ephLifecycle(t, cs, profile.HardFail)
			l.opt.Now = func() time.Time { return now }
			c := *l.cfg
			c.Table.Workspace = profile.Dim{Value: "bobthecorp-reporting-prod", Source: "profile"}
			setup(t, &c)
			l.cfg = &c
			res, err := l.Evaluate(context.Background(), &hook.Request{Stage: hook.StageEphemeralOpen, Kind: hook.KindEphemeral,
				TypeName: ephType, Config: ephConfig(8, "")})
			if err != nil {
				t.Fatal(err)
			}
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
			blocked := slices.ContainsFunc(res.Diagnostics, func(d hook.Diagnostic) bool {
				return d.Severity == hook.SeverityError && d.Summary == "[eph_min_length] Password length must be at least 14."
			})
			if blocked != (tc.decision == "blocked") || hasError(res.Diagnostics) != blocked {
				t.Errorf("diagnostics %+v, want blocked %v", res.Diagnostics, tc.decision == "blocked")
			}
			checkEvalRecord(t, readChain(t, evDir), "ephemeral_open", ephType, &wantEvidence{Op: "open", Results: []wantResult{
				{Control: "eph_min_length", State: "fail", Decision: tc.decision},
				{Control: "eph_no_excludes", State: "pass", Decision: "logged"}}})
		})
	}
}

func hasError(ds []hook.Diagnostic) bool {
	return slices.ContainsFunc(ds, func(d hook.Diagnostic) bool { return d.Severity == hook.SeverityError })
}
