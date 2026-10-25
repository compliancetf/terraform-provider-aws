//go:build ctftest

package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/bundle/bundletest"
	"github.com/compliancetf/terraform-provider-aws/internal/lifecycle"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
	"github.com/compliancetf/terraform-provider-aws/test/scrub/scrubtest"
)

// secretSentinel is in every result the fake upstream opens; it must never
// reach a diagnostic, a log line or the evidence chain.
const secretSentinel = "BOBTHECORP-SECRET-SENTINEL"

var passwordType = tftypes.Object{AttributeTypes: map[string]tftypes.Type{
	"password_length": tftypes.Number, "exclude_characters": tftypes.String, "random_password": tftypes.String,
}}

// secretUpstream opens aws_secretsmanager_random_password with the
// sentinel as the Computed result, and renews and closes it.
type secretUpstream struct{ *fakeUpstream5 }

func (u *secretUpstream) OpenEphemeralResource(context.Context, *tfplugin5.OpenEphemeralResource_Request) (*tfplugin5.OpenEphemeralResource_Response, error) {
	u.record("OpenEphemeralResource")
	return &tfplugin5.OpenEphemeralResource_Response{Result: password(nil, 20, secretSentinel), Private: []byte(secretSentinel)}, nil
}

func (u *secretUpstream) RenewEphemeralResource(context.Context, *tfplugin5.RenewEphemeralResource_Request) (*tfplugin5.RenewEphemeralResource_Response, error) {
	u.record("RenewEphemeralResource")
	return &tfplugin5.RenewEphemeralResource_Response{Private: []byte(secretSentinel)}, nil
}

func (u *secretUpstream) CloseEphemeralResource(context.Context, *tfplugin5.CloseEphemeralResource_Request) (*tfplugin5.CloseEphemeralResource_Response, error) {
	u.record("CloseEphemeralResource")
	return &tfplugin5.CloseEphemeralResource_Response{}, nil
}

func (u *secretUpstream) called(name string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	n := 0
	for _, c := range u.calls {
		if c == name {
			n++
		}
	}
	return n
}

func password(t *testing.T, length int64, result string) *tfplugin5.DynamicValue {
	res := tftypes.NewValue(tftypes.String, nil)
	if result != "" {
		res = tftypes.NewValue(tftypes.String, result)
	}
	dv, err := tfprotov5.NewDynamicValue(passwordType, tftypes.NewValue(passwordType, map[string]tftypes.Value{
		"password_length":    tftypes.NewValue(tftypes.Number, big.NewFloat(float64(length))),
		"exclude_characters": tftypes.NewValue(tftypes.String, scrubtest.Marker(70)),
		"random_password":    res,
	}))
	if err != nil {
		if t == nil {
			panic(err)
		}
		t.Fatal(err)
	}
	return &tfplugin5.DynamicValue{Msgpack: dv.MsgPack}
}

// ephemeralBundle is the release-iam test bundle with one deny ephemeral
// control, re-signed with the ctftest bundle key.
func ephemeralBundle(t *testing.T, dir string) string {
	t.Helper()
	archive, err := os.ReadFile("../../testdata/bundles/release-iam.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	controls := `[{"id": "eph_min_length", "version": "1.0.0", "kind": "ephemeral", "resource_type": "aws_secretsmanager_random_password",
  "reads": ["password_length"], "expr": "config.password_length == null || config.password_length >= 14",
  "action": "deny", "severity": "high", "message": "Password length must be at least 14."}]`
	signed, err := bundletest.WithFile(archive, bundle.ControlsFile, []byte(controls), testkeys.Bundle())
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "bundle.tar.gz")
	if err := os.WriteFile(p, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestEphemeralOpenLifecycle: through the proxy with the lifecycle
// and a signed bundle holding a deny ephemeral control under hard_fail, an
// open that fails the control returns the block diagnostic and never
// reaches upstream; a compliant open forwards and returns the result bytes
// untouched; renew and close pass through without evaluation. The sentinel
// in every upstream result and private, and the marker in the config,
// appear in no diagnostic, log line or evidence file. Each open writes one
// ephemeral_open record.
func TestEphemeralOpenLifecycle(t *testing.T) {
	logs := scrubtest.CaptureLogs(t)
	dir := t.TempDir()
	for _, k := range []string{"COMPLIANCETF_ENFORCEMENT_MODE", "COMPLIANCETF_GOVERNED", "COMPLIANCETF_TOKEN",
		"COMPLIANCETF_PROFILE_PATH", "COMPLIANCETF_FLOOR_PATH", "COMPLIANCETF_ENVIRONMENT", "COMPLIANCETF_WORKSPACE",
		"COMPLIANCETF_EXCEPTIONS_FILE", "COMPLIANCETF_EXCEPTION_GRANTS", "COMPLIANCETF_MIN_BUNDLE_VERSION",
		"COMPLIANCETF_MIN_PROFILE_VERSION", "COMPLIANCETF_BREAK_GLASS"} {
		t.Setenv(k, "")
	}
	os.Unsetenv("COMPLIANCETF_BREAK_GLASS") //nolint:errcheck,usetesting // set, even empty, fails Configure; t.Setenv above restores it
	t.Setenv("COMPLIANCETF_OFFLINE", "true")
	t.Setenv("COMPLIANCETF_ORG_ID", "bobthecorp")
	t.Setenv("COMPLIANCETF_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("COMPLIANCETF_CACHE_DIR", filepath.Join(dir, "cache"))
	t.Setenv("COMPLIANCETF_EVIDENCE_DIR", filepath.Join(dir, "evidence"))
	t.Setenv("COMPLIANCETF_BUNDLE_PATH", ephemeralBundle(t, t.TempDir()))

	schema := &tfplugin5.GetProviderSchema_Response{
		Provider:        &tfplugin5.Schema{Block: &tfplugin5.Schema_Block{Attributes: []*tfplugin5.Schema_Attribute{{Name: "region", Type: []byte(`"string"`), Optional: true}}}},
		ResourceSchemas: map[string]*tfplugin5.Schema{},
		EphemeralResourceSchemas: map[string]*tfplugin5.Schema{"aws_secretsmanager_random_password": {Block: &tfplugin5.Schema_Block{Attributes: []*tfplugin5.Schema_Attribute{
			{Name: "exclude_characters", Type: []byte(`"string"`), Optional: true},
			{Name: "password_length", Type: []byte(`"number"`), Optional: true},
			{Name: "random_password", Type: []byte(`"string"`), Computed: true, Sensitive: true},
		}}}},
	}
	l := lifecycle.New(lifecycle.Options{ProviderVersion: "6.40.0"})
	t.Cleanup(func() { _ = l.Close() })
	up := &secretUpstream{&fakeUpstream5{schema: schema}}
	client, _ := startProxy(t, up, Backends{Evaluator: lifecycle.Hook{Lifecycle: l}})
	ctx := context.Background()
	warmSchema(t, client)

	var all []*tfplugin5.Diagnostic
	cr, err := client.Configure(ctx, &tfplugin5.Configure_Request{TerraformVersion: "1.14.0", Config: combinedConfig(t, "hard_fail")})
	scrubtest.Must(t, "Configure error", err)
	if hasErrorDiag(cr.Diagnostics) || l.Configured() == nil {
		t.Fatalf("Configure: %v", cr.Diagnostics)
	}
	open := func(length int64) *tfplugin5.OpenEphemeralResource_Response {
		t.Helper()
		resp, err := client.OpenEphemeralResource(ctx, &tfplugin5.OpenEphemeralResource_Request{
			TypeName: "aws_secretsmanager_random_password", Config: password(t, length, "")})
		scrubtest.Must(t, "OpenEphemeralResource error", err)
		all = append(all, resp.Diagnostics...)
		return resp
	}

	blocked := open(8)
	if up.called("OpenEphemeralResource") != 0 {
		t.Fatal("a blocked open reached upstream")
	}
	if len(blocked.Diagnostics) != 1 || blocked.Diagnostics[0].Severity != tfplugin5.Diagnostic_ERROR ||
		blocked.Diagnostics[0].Summary != "[eph_min_length] Password length must be at least 14." ||
		!strings.HasPrefix(blocked.Diagnostics[0].Detail, "Opening ephemeral aws_secretsmanager_random_password was blocked; the secret was not opened.\n") ||
		blocked.Result != nil || blocked.Private != nil {
		t.Errorf("blocked open: %s", scrubtest.Mask(fmt.Sprint(blocked)))
	}

	allowed := open(20)
	if up.called("OpenEphemeralResource") != 1 || hasErrorDiag(allowed.Diagnostics) {
		t.Fatalf("compliant open: upstream calls %d, diagnostics %s", up.called("OpenEphemeralResource"), scrubtest.Mask(fmt.Sprint(allowed.Diagnostics)))
	}
	if !bytes.Equal(allowed.Result.GetMsgpack(), password(t, 20, secretSentinel).Msgpack) || string(allowed.Private) != secretSentinel {
		t.Error("the open result or private was not passed through as upstream sent it")
	}
	if _, err := client.RenewEphemeralResource(ctx, &tfplugin5.RenewEphemeralResource_Request{TypeName: "aws_secretsmanager_random_password", Private: allowed.Private}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CloseEphemeralResource(ctx, &tfplugin5.CloseEphemeralResource_Request{TypeName: "aws_secretsmanager_random_password", Private: allowed.Private}); err != nil {
		t.Fatal(err)
	}
	if up.called("RenewEphemeralResource") != 1 || up.called("CloseEphemeralResource") != 1 {
		t.Errorf("renew/close did not pass through: %v", up.calls)
	}

	scan := func(stream, s string) {
		t.Helper()
		scrubtest.NoMarker(t, stream, s)
		if strings.Contains(s, secretSentinel) {
			t.Errorf("LEAK: %s holds the ephemeral result sentinel", stream)
		}
	}
	scan("diagnostics", fmt.Sprintf("%v", all))
	scan("log", logs())
	if err := l.Close(); err != nil {
		scrubtest.Must(t, "Close", err)
	}
	var chain strings.Builder
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		scan(p, string(b))
		if filepath.Ext(p) == ".jsonl" {
			chain.Write(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var stages []string
	for _, line := range strings.Split(chain.String(), "\n") {
		if !strings.Contains(line, `"kind":"eval"`) {
			continue
		}
		i := strings.Index(line, `"stage":"`)
		if i < 0 {
			t.Fatalf("eval record without a stage: %s", scrubtest.Mask(line))
		}
		stage, _, _ := strings.Cut(line[i+len(`"stage":"`):], `"`)
		stages = append(stages, stage)
	}
	if want := []string{"ephemeral_open", "ephemeral_open"}; !slices.Equal(stages, want) {
		t.Errorf("eval records %q, want two ephemeral_open records (renew and close write none)", stages)
	}
}
