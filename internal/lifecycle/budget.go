package lifecycle

import (
	"context"
	"errors"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
)

// Interim budget caps; only the signed profile
// budgets change them, never env.
const (
	defaultPerResource = 50 * time.Millisecond
	defaultPerRun      = 60 * time.Second
)

type budgets struct{ perResource, perRun time.Duration }

// budgetsOf returns the selected profile's budgets (clamped when the profile
// loaded) or the interim defaults; c may be nil (before Configure).
func budgetsOf(c *Configured) budgets {
	b := budgets{defaultPerResource, defaultPerRun}
	if c == nil || c.Resolution.Profile == nil {
		return b
	}
	if ms := c.Resolution.Profile.Budgets.PerResourceMs; ms > 0 {
		b.perResource = time.Duration(ms) * time.Millisecond
	}
	if s := c.Resolution.Profile.Budgets.PerRunS; s > 0 {
		b.perRun = time.Duration(s) * time.Second
	}
	return b
}

// budgets is budgetsOf(c) with the test per-resource budget, when set.
func (l *Lifecycle) budgets(c *Configured) budgets {
	b := budgetsOf(c)
	if l.testPerResource > 0 {
		b.perResource = l.testPerResource
	}
	return b
}

// budgeted runs one control under the budgets. The per-resource deadline
// is on ctx (Evaluate). Once this process has spent per_run_s evaluating,
// every later control is not_evaluable/limit without running; past the
// deadline a control is not_evaluable/timeout, even one that returned a
// result after it ran over. A control that does not compile is
// not_evaluable with the class of its engine.CompileError (a type or read
// missing upstream: no_such_attribute), else unresolved (no upstream
// schemas, an iam.* control). All three take the fail row.
func (l *Lifecycle) budgeted(ctx context.Context, c *Configured, ctl *bundle.Control, a *engine.Activation) engine.Outcome {
	b := l.budgets(c)
	// Admission reserves the time left to the deadline, so
	// concurrent controls see each other's in-flight time and the run
	// overshoots per_run_s by at most one admission, for programs that stop
	// at the deadline. One that runs past it is charged its actual time on
	// return and its outcome is timeout (fail row); the bound cannot cover
	// work that ignores ctx. The actual time replaces the reservation.
	reserve := b.perResource
	if d, ok := ctx.Deadline(); ok {
		reserve = max(time.Until(d), 0)
	}
	for {
		s := l.spent.Load()
		if time.Duration(s) >= b.perRun {
			return engine.Outcome{State: engine.NotEvaluable, Err: engine.ErrLimit}
		}
		if l.spent.CompareAndSwap(s, s+int64(reserve)) {
			break
		}
	}
	// Compile and evaluation both count against the run; after Configure
	// precompiled the control set, compile is a cache lookup.
	start := time.Now()
	defer func() { l.spent.Add(int64(time.Since(start) - reserve)) }()
	timeout := engine.Outcome{State: engine.NotEvaluable, Err: engine.ErrTimeout}
	if expired(ctx) {
		return timeout
	}
	p, err := l.program(c, ctl, a.Resource.Type())
	if expired(ctx) {
		return timeout
	}
	if err != nil {
		class := engine.ErrUnresolved
		if ce := (*engine.CompileError)(nil); errors.As(err, &ce) && ce.Class != engine.ErrNone {
			class = ce.Class
		}
		return engine.Outcome{State: engine.NotEvaluable, Err: class}
	}
	out := p.Eval(ctx, a)
	if expired(ctx) {
		return timeout
	}
	return out
}

// expired reports the deadline passed. ctx.Err() alone can lag: the
// cancel runs from a timer callback after the deadline.
func expired(ctx context.Context) bool {
	if ctx.Err() != nil {
		return true
	}
	d, ok := ctx.Deadline()
	return ok && !time.Now().Before(d)
}

// progKey identifies one compiled control: the bundle digest covers the
// control content, the compiler the upstream schemas and content
// digest of one Configure; the schema type is checked on every hit.
type progKey struct {
	digest, resourceType, id string
	kind                     bundle.Kind
	compiler                 *celeng.Compiler // nil: the test compiler on the Lifecycle
}

type progEntry struct {
	schema tftypes.Type
	p      engine.Program
}

// program returns ctl compiled for schema, compiling once per (bundle
// digest, type, compiler). Programs are immutable and shared across
// goroutines. A hit whose schema differs recompiles and replaces the entry.
// Without a loaded control set (no digest), a schema or a compiler to key by
// (a Configured built by hand gets a fresh one per call) nothing is cached.
// c must be the snapshot ctl came from, so a program never lands under
// another bundle's digest. The key plus the full structural type is the
// whole compile input: engine.Compiler.Compile takes only the control and
// the type, and celeng also reads the upstream schemas and content digest,
// fixed per compiler. Widen the key if a compiler ever reads more. Errors
// are not stored here; celeng keeps them per compiler, so a failing control
// fails alike until the next Configure. Concurrent first misses may compile
// twice; both programs are equivalent and both are charged.
func (l *Lifecycle) program(c *Configured, ctl *bundle.Control, schema tftypes.Type) (engine.Program, error) {
	if c == nil || c.Controls == nil || schema == nil || (l.compiler == nil && c.compiler == nil) {
		return l.compilerFor(c).Compile(ctl, schema)
	}
	k := progKey{c.Controls.Digest(), ctl.ResourceType, ctl.ID, ctl.Kind, c.compiler}
	if l.compiler != nil {
		k.compiler = nil // compilerFor ignores c.compiler
	}
	if v, ok := l.progs.Load(k); ok {
		if e, ok := v.(progEntry); ok && e.schema.Equal(schema) {
			return e.p, nil
		}
	}
	p, err := l.compilerFor(c).Compile(ctl, schema)
	if err == nil {
		l.progs.Store(k, progEntry{schema, p})
	}
	return p, err
}

// pathCompiler is the celeng compiler that cuts c's declared reads: c's
// own, else one over c's schemas (a Configured built by hand in tests).
func (c *Configured) pathCompiler() *celeng.Compiler {
	if c.compiler != nil {
		return c.compiler
	}
	return celeng.NewCompiler(c.Schemas)
}

// compilerFor is the compiler of c: celeng over c's upstream schemas. A test
// compiler set on l takes every control.
func (l *Lifecycle) compilerFor(c *Configured) engine.Compiler {
	switch {
	case l.compiler != nil:
		return l.compiler
	case c == nil:
		return celeng.NewCompiler(nil) // before Configure: nothing compiles
	case c.compiler == nil: // a Configured built by hand in tests
		return celeng.NewCompiler(c.Schemas)
	}
	return c.compiler
}
