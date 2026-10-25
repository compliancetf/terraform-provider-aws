package upstream

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

var (
	fakeOnce sync.Once
	fakeDir  string
	fakeErr  error
)

// syncBuffer is a bytes.Buffer safe for go-plugin's logging goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestMain(m *testing.M) {
	code := m.Run()
	if fakeDir != "" {
		_ = os.RemoveAll(fakeDir)
	}
	os.Exit(code)
}

// launchFake builds test/fakeupstream/v5 once, wraps it in a shell script that
// appends the child environment to $FAKE_ENV_DUMP on every start, and launches
// the wrapper.
func launchFake(t *testing.T, stderr *syncBuffer) (*Upstream, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell wrapper needs a POSIX sh")
	}
	fakeOnce.Do(func() {
		fakeDir, fakeErr = os.MkdirTemp("", "launch-test")
		if fakeErr != nil {
			return
		}
		build := exec.Command("go", "build", "-o", filepath.Join(fakeDir, "fakeupstream"), "./v5")
		build.Dir = filepath.Join("..", "..", "test", "fakeupstream")
		if out, err := build.CombinedOutput(); err != nil {
			fakeErr = errors.New(err.Error() + ": " + string(out))
			return
		}
		script := "#!/bin/sh\nenv >> \"$FAKE_ENV_DUMP\"\nexec \"" + filepath.Join(fakeDir, "fakeupstream") + "\" \"$@\"\n"
		fakeErr = os.WriteFile(filepath.Join(fakeDir, "wrapper"), []byte(script), 0o700)
	})
	if fakeErr != nil {
		t.Fatalf("build fake upstream: %v", fakeErr)
	}

	dump := filepath.Join(t.TempDir(), "env")
	t.Setenv("FAKE_ENV_DUMP", dump)
	t.Setenv("COMPLIANCETF_LAUNCH_TEST_SECRET", "bobthecorp-secret")
	t.Setenv("COMPLIANCETF_UPSTREAM_PATH", "/nonexistent")

	bin := VerifiedBinary{path: filepath.Join(fakeDir, "wrapper"), protocol: 5, version: "6.0.0-fake", name: "hashicorp/aws"}
	u, err := Launch(context.Background(), bin, NewLogger(stderr, "hashicorp/aws"))
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	t.Cleanup(u.Close)
	return u, dump
}

func TestLaunchEnvFilter(t *testing.T) {
	var stderr syncBuffer
	u, dump := launchFake(t, &stderr)

	if u.Protocol != 5 || u.Version != "6.0.0-fake" || u.Conn == nil {
		t.Fatalf("Upstream = %+v", u)
	}
	if _, err := tfplugin5.NewProviderClient(u.Conn).GetMetadata(context.Background(), &tfplugin5.GetMetadata_Request{}); err != nil {
		t.Fatalf("GetMetadata over raw conn: %v", err)
	}

	env, err := os.ReadFile(dump)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(env), "\n") {
		if strings.HasPrefix(line, "COMPLIANCETF_") {
			t.Errorf("child env carries %q", line)
		}
	}
	for _, want := range []string{"FAKE_ENV_DUMP=", "TF_PLUGIN_MAGIC_COOKIE="} {
		if !strings.Contains(string(env), want) {
			t.Errorf("child env lacks %s", want)
		}
	}
}

func TestLaunchCrashExitStatusNoRetry(t *testing.T) {
	var stderr syncBuffer
	u, dump := launchFake(t, &stderr)
	client := tfplugin5.NewProviderClient(u.Conn)

	if exited, _ := u.Exited(); exited {
		t.Fatal("Exited before any call")
	}

	typ := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"name": tftypes.String, "id": tftypes.String, "crash": tftypes.Bool}}
	dv, err := tfprotov5.NewDynamicValue(typ, tftypes.NewValue(typ, map[string]tftypes.Value{
		"name":  tftypes.NewValue(tftypes.String, "bobthecorp"),
		"id":    tftypes.NewValue(tftypes.String, nil),
		"crash": tftypes.NewValue(tftypes.Bool, true),
	}))
	if err != nil {
		t.Fatal(err)
	}
	req := &tfplugin5.ReadDataSource_Request{TypeName: "fake_lookup", Config: &tfplugin5.DynamicValue{Msgpack: dv.MsgPack}}
	const method = "/tfplugin5.Provider/ReadDataSource"

	_, callErr := client.ReadDataSource(context.Background(), req)
	if callErr == nil {
		t.Fatal("crash call succeeded")
	}
	err = u.TransportErr(method, callErr)

	exited, code := u.Exited()
	if !exited || code != 2 {
		t.Fatalf("Exited() = %v, %d; want true, 2 (Go panic)", exited, code)
	}
	var ee *ExitedError
	if !errors.As(err, &ee) || ee.Status != 2 {
		t.Fatalf("TransportErr = %v; want *ExitedError with status 2", err)
	}
	if !strings.HasPrefix(err.Error(), ExitedSummary+": ") || !strings.HasPrefix(ee.Detail(), "hashicorp/aws ") {
		t.Errorf("error %q lacks summary prefix or detail", err)
	}
	want := "hashicorp/aws 6.0.0-fake exited with status 2 during ReadDataSource. The request was not retried."
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error %q lacks %q", err, want)
	}
	if st := status.Convert(err); st.Code() != codes.Unavailable || st.Message() != err.Error() {
		t.Errorf("gRPC status = %v %q; want Unavailable with the same text", st.Code(), st.Message())
	}

	// Stderr of the child reaches the logger as JSON under "upstream".
	out := stderr.String()
	if !strings.Contains(out, `"@module":"upstream.`) || !strings.Contains(out, "fakeupstream: crash = true") {
		t.Errorf("stderr not forwarded under upstream prefix:\n%s", out)
	}

	// Terraform blames the plugin whose log message starts with
	// "panic: ", so the upstream panic must not reach our stderr that way.
	if strings.Contains(out, `"@message":"panic: `) {
		t.Errorf("upstream panic forwarded as our own panic:\n%s", out)
	}
	if !strings.Contains(out, `"@message":"`+crashed+`panic: fakeupstream: crash = true"`) {
		t.Errorf("upstream panic not attributed:\n%s", out)
	}
	// the panic value and trace may carry config values, so
	// they stay in the log; the diagnostic only says that it crashed.
	for name, text := range map[string]string{"detail": ee.Detail(), "error": err.Error(), "status": status.Convert(err).Message()} {
		if !strings.Contains(text, crashed) {
			t.Errorf("%s lacks %q:\n%s", name, crashed, text)
		}
		for _, leak := range []string{"fakeupstream: crash = true", "goroutine"} {
			if strings.Contains(text, leak) {
				t.Errorf("%s leaks upstream output %q:\n%s", name, leak, text)
			}
		}
	}

	// No retry: a second call fails and the process was started exactly once.
	if _, err := client.ReadDataSource(context.Background(), req); err == nil {
		t.Error("call after crash succeeded")
	}
	env, err := os.ReadFile(dump)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(env), "FAKE_ENV_DUMP="); n != 1 {
		t.Errorf("upstream started %d times; want 1", n)
	}
}

func TestLaunchTransportErrWhileRunning(t *testing.T) {
	var stderr syncBuffer
	u, _ := launchFake(t, &stderr)
	in := errors.New("boom")
	if got := u.TransportErr("/tfplugin5.Provider/GetMetadata", in); got != in {
		t.Errorf("TransportErr on live upstream = %v; want the input error", got)
	}
}

func TestLaunchFilterEnv(t *testing.T) {
	got := filterEnv([]string{"PATH=/bin", "COMPLIANCETF_X=1", "ComplianceTf_Y=2", "COMPLIANCE=3", "A"})
	if strings.Join(got, ",") != "PATH=/bin,COMPLIANCE=3,A" {
		t.Errorf("filterEnv = %q", got)
	}
}

func TestCrashWatchSeesBannerOnly(t *testing.T) {
	var c crashWatch
	_, _ = c.Write([]byte("noise fatal error: x"))
	if c.seen.Load() {
		t.Error("banner mid-line counted as a crash")
	}
	_, _ = c.Write([]byte("fatal error: x"))
	if !c.seen.Load() {
		t.Error("fatal error banner not seen")
	}
}

func TestNewLoggerRenamesFatalError(t *testing.T) {
	var out syncBuffer
	NewLogger(&out, "hashicorp/aws").Error("fatal error: concurrent map writes")
	if s := out.String(); !strings.Contains(s, `"@message":"`+crashed+`fatal error: concurrent map writes"`) {
		t.Errorf("fatal error not attributed: %s", s)
	}
}

func TestLaunchCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Launch(ctx, VerifiedBinary{path: "/nonexistent"}, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("Launch with canceled ctx = %v", err)
	}
}

// crashed is the aws CrashedPrefix, spelled out so its text stays byte-identical.
const crashed = "upstream hashicorp/aws provider crashed: "

func TestDiagnosticsNameTheSource(t *testing.T) {
	if got := CrashedPrefix("hashicorp/aws"); got != crashed {
		t.Errorf("CrashedPrefix = %q, want %q", got, crashed)
	}
	e := &ExitedError{Upstream: "hashicorp/azurerm", Version: "5.8.0", Status: 2, RPC: "PlanResourceChange", Crashed: true}
	want := "hashicorp/azurerm 5.8.0 exited with status 2 during PlanResourceChange. The request was not retried. Upstream output is in the Terraform log under \"upstream\".\n\nupstream hashicorp/azurerm provider crashed: Go panic."
	if !strings.HasPrefix(e.Detail(), want) || strings.Contains(e.Detail(), "aws") {
		t.Errorf("Detail = %q", e.Detail())
	}
}
