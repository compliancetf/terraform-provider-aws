package upstream

// launch.go is the upstream execution contract: it execs a verified
// upstream binary through go-plugin and hands back the raw gRPC conn.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/compliancetf/terraform-provider-aws/internal/rawgrpc"
)

// exitGrace bounds how long TransportErr waits for go-plugin to reap a
// process whose conn already failed.
const exitGrace = 2 * time.Second

// Terraform go-plugin magic cookie for the provider handshake.
const (
	magicCookieKey   = "TF_PLUGIN_MAGIC_COOKIE"
	magicCookieValue = "d602bf8f470bc67ca7faa0386276bbdd4330efaf76d1a219cb4d6991ca9872b2"
)

// VerifiedBinary is an upstream binary whose bytes matched the pin. Only
// verify.go returns one; ctftest builds add NewTestVerifiedBinary.
type VerifiedBinary struct {
	path     string
	sha256   string // verified hex sha256 of the bytes at path
	protocol int
	version  string
	name     string // Source.Name, for diagnostics
	execDir  string // private exec child holding path; removed by Upstream.Close
	cacheDir string // shared entry holding path, for per-binary caches; "" for a private copy
	// retry makes a private copy when a shared entry fails to start; nil otherwise.
	retry func(context.Context) (VerifiedBinary, error)
}

// SHA256 is the verified hex sha256 of the binary at Path.
func (b VerifiedBinary) SHA256() string { return b.sha256 }

// Upstream is the running upstream provider process.
type Upstream struct {
	Conn     *grpc.ClientConn // raw conn: forwarder and typed clients share it
	Protocol int              // 5 or 6, from the pin
	Version  string           // pinned upstream version
	Name     string           // Source.Name, e.g. hashicorp/<type>
	SHA256   string           // verified sha256 of the launched binary
	CacheDir string           // owner-only dir for caches of this binary's output; "" when none

	client  *plugin.Client
	cmd     *exec.Cmd
	execDir string
	crash   *crashWatch
}

// NewLogger returns the logger the upstream's stderr is forwarded to: JSON at
// Trace under "upstream", so Terraform applies TF_LOG / TF_LOG_PROVIDER.
// Terraform treats a plugin log message starting with "panic: " or
// "fatal error: " as that plugin's crash, so those upstream lines get
// CrashedPrefix(name) and Terraform does not report the upstream panic as
// ours. name is the upstream Source.Name.
func NewLogger(w io.Writer, name string) hclog.Logger {
	return hclog.New(&hclog.LoggerOptions{Name: "upstream", JSONFormat: true, Level: hclog.Trace, Output: panicRenamer{w, CrashedPrefix(name)}})
}

// panicBanners start a Go runtime crash on stderr.
var panicBanners = []string{"panic: ", "fatal error: "}

// panicRenamer prefixes the @message of panic lines in hclog JSON output.
// hclog writes one entry per Write, keyed "@message" by json.Marshal.
type panicRenamer struct {
	w      io.Writer
	prefix string // CrashedPrefix of the upstream
}

func (p panicRenamer) Write(b []byte) (int, error) {
	out := b
	for _, banner := range panicBanners {
		out = bytes.ReplaceAll(out, []byte(`"@message":"`+banner), []byte(`"@message":"`+p.prefix+banner))
	}
	if _, err := p.w.Write(out); err != nil {
		return 0, err
	}
	return len(b), nil
}

// crashWatch records whether upstream stderr showed a panic banner. It keeps
// no bytes: a panic value or trace can carry config values, so they go to
// the log only. go-plugin writes it from its stderr goroutine.
type crashWatch struct{ seen atomic.Bool }

func (c *crashWatch) Write(b []byte) (int, error) {
	for _, banner := range panicBanners {
		if bytes.HasPrefix(b, []byte(banner)) {
			c.seen.Store(true)
		}
	}
	return len(b), nil
}

// Launch execs bin with no arguments and an environment without COMPLIANCETF_*
// keys, completes the go-plugin handshake and returns the raw conn. A nil
// logger means NewLogger(os.Stderr, bin's Source.Name). ctx only gates the start: the process
// lives until Close, so a canceled stop context cannot kill it before Stop
// is forwarded. Nothing here restarts the process.
func Launch(ctx context.Context, bin VerifiedBinary, logger hclog.Logger) (*Upstream, error) {
	if bin.path == "" {
		return nil, errors.New("upstream: launch of an unverified binary")
	}
	if err := ctx.Err(); err != nil {
		removeExecDir(bin.execDir)
		return nil, err
	}
	if logger == nil {
		logger = NewLogger(os.Stderr, bin.name)
	}
	cmd := exec.Command(bin.path) //nolint:gosec // bin.path is a VerifiedBinary
	cmd.Env = filterEnv(os.Environ())
	crash := &crashWatch{}

	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: plugin.HandshakeConfig{
			MagicCookieKey:   magicCookieKey,
			MagicCookieValue: magicCookieValue,
		},
		VersionedPlugins: map[int]plugin.PluginSet{bin.protocol: {"provider": rawPlugin{}}},
		Cmd:              cmd,
		SkipHostEnv:      true, // go-plugin would otherwise re-append os.Environ()
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		AutoMTLS:         true,
		Logger:           logger,
		Stderr:           crash, // raw upstream stderr, line by line
		GRPCDialOptions:  []grpc.DialOption{rawgrpc.CallSizes()},
	})
	fail := func(err error) (*Upstream, error) {
		client.Kill()
		removeExecDir(bin.execDir)
		return nil, err
	}
	rpc, err := client.Client()
	var pe *fs.PathError
	var ee *exec.Error                                                                  // Windows: exec's lookup fails for a removed entry before any start
	if err != nil && bin.retry != nil && (errors.As(err, &pe) || errors.As(err, &ee)) { // exec itself failed: entry removed, noexec, busy
		client.Kill()
		log.Printf("[upstream] %q did not start (%v); retrying with a private copy", bin.path, err)
		vb, rerr := bin.retry(ctx)
		if rerr != nil {
			return nil, rerr
		}
		return Launch(ctx, vb, logger)
	}
	if err != nil {
		return fail(fmt.Errorf("start upstream %s %s: %w", bin.name, bin.version, err))
	}
	raw, err := rpc.Dispense("provider")
	if err != nil {
		return fail(fmt.Errorf("dispense upstream provider: %w", err))
	}
	conn, ok := raw.(*grpc.ClientConn)
	if !ok {
		return fail(fmt.Errorf("dispensed upstream plugin is %T, not *grpc.ClientConn", raw))
	}
	return &Upstream{Conn: conn, Protocol: bin.protocol, Version: bin.version, Name: bin.name, SHA256: bin.sha256, CacheDir: bin.cacheDir, client: client, cmd: cmd, execDir: bin.execDir, crash: crash}, nil
}

// Exited reports whether the upstream process has ended and its exit status
// (-1 when it was killed by a signal).
func (u *Upstream) Exited() (exited bool, status int) {
	if !u.client.Exited() {
		return false, 0
	}
	// go-plugin sets exited under its lock after cmd.Wait returned, so
	// ProcessState is complete here.
	if u.cmd.ProcessState == nil {
		return true, -1
	}
	return true, u.cmd.ProcessState.ExitCode()
}

// Close kills the upstream process (go-plugin waits for it to exit) and
// removes its private exec directory.
func (u *Upstream) Close() {
	u.client.Kill()
	u.removeExecDir()
}

func (u *Upstream) removeExecDir() { removeExecDir(u.execDir) }

// TransportErr maps a failed call on Conn to an *ExitedError when the upstream
// process is gone, and returns err unchanged otherwise. Its signature matches
// the forwarder's onTransportErr callback.
func (u *Upstream) TransportErr(method string, err error) error {
	if status.Code(err) == codes.Unavailable {
		// shortcut: polls go-plugin's reaper; a done channel needs go-plugin to expose one.
		for deadline := time.Now().Add(exitGrace); !u.client.Exited() && time.Now().Before(deadline); {
			time.Sleep(10 * time.Millisecond)
		}
	}
	exited, st := u.Exited()
	if !exited {
		return err
	}
	return &ExitedError{Upstream: u.Name, Version: u.Version, Status: st, RPC: path.Base(method), Crashed: u.crash.seen.Load()}
}

// ExitedError is the "upstream provider exited" error. Intercepted RPCs turn
// it into a diagnostic; passthrough returns its gRPC status (Unavailable).
type ExitedError struct {
	Upstream string // Source.Name
	Version  string
	Status   int
	RPC      string
	Crashed  bool // upstream stderr showed a panic banner
}

// ExitedSummary is the diagnostic summary for an ExitedError.
const ExitedSummary = "upstream provider exited"

// CrashedPrefix starts the upstream panic line in our log and the crash line
// in the detail for the upstream named name (Source.Name). The detail never
// carries upstream output.
func CrashedPrefix(name string) string { return "upstream " + name + " provider crashed: " }

// Detail is the diagnostic detail.
func (e *ExitedError) Detail() string {
	d := fmt.Sprintf("%s %s exited with status %d during %s. The request was not retried. Upstream output is in the Terraform log under \"upstream\".", e.Upstream, e.Version, e.Status, e.RPC)
	if e.Crashed {
		d += "\n\n" + CrashedPrefix(e.Upstream) + "Go panic. The panic message and stack trace are in the Terraform log under \"upstream\"."
	}
	return d
}

func (e *ExitedError) Error() string { return ExitedSummary + ": " + e.Detail() }

// GRPCStatus lets status.FromError report Unavailable with the same text.
func (e *ExitedError) GRPCStatus() *status.Status { return status.New(codes.Unavailable, e.Error()) }

// filterEnv drops COMPLIANCETF_* keys, case-insensitively because Windows
// environment names are.
func filterEnv(env []string) []string {
	const prefix = "COMPLIANCETF_"
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if len(kv) < len(prefix) || !strings.EqualFold(kv[:len(prefix)], prefix) {
			out = append(out, kv)
		}
	}
	return out
}

// rawPlugin dispenses the go-plugin conn itself instead of a typed client.
type rawPlugin struct{ plugin.NetRPCUnsupportedPlugin }

func (rawPlugin) GRPCServer(*plugin.GRPCBroker, *grpc.Server) error {
	return errors.New("upstream: rawPlugin is client-only")
}

func (rawPlugin) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, conn *grpc.ClientConn) (any, error) {
	return conn, nil
}
