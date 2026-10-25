package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

// sleepProgram ignores ctx, sleeps d and passes: the slowest program a
// compiler could hand back.
type sleepProgram struct{ d time.Duration }

func (p sleepProgram) Eval(context.Context, *engine.Activation) engine.Outcome {
	time.Sleep(p.d)
	return engine.Outcome{State: engine.Pass}
}

type fakeCompiler struct {
	p engine.Program
	n *atomic.Int32
}

func (fakeCompiler) ID() string { return "fake" }

func (f fakeCompiler) Compile(*bundle.Control, tftypes.Type) (engine.Program, error) {
	f.n.Add(1)
	return f.p, nil
}

// budgetLifecycle is configured hard_fail over the stage controls with
// profile budgets and every control compiled to p; compiles counts calls.
func budgetLifecycle(t *testing.T, b profile.Budgets, p engine.Program, compiles *atomic.Int32) *Lifecycle {
	t.Helper()
	l := New(Options{})
	l.compiler = fakeCompiler{p, compiles}
	l.cfg = &Configured{Table: profile.ModeTable{RunMode: profile.HardFail}, Controls: stageControlSet(t),
		Resolution: profile.Resolution{Profile: &profile.Profile{Budgets: b}}}
	return l
}

func createPlan(t *testing.T) *hook.Request {
	t.Helper()
	v := json.RawMessage(`{"storage_encrypted": true, "kms_key_id": "k", "engine": "postgres", "deletion_protection": true}`)
	return &hook.Request{Stage: hook.StagePlan, Kind: hook.KindResource, TypeName: "aws_db_instance", Op: hook.OpCreate,
		Config: dynValue(t, v), Prior: dynValue(t, json.RawMessage(`null`)), Planned: dynValue(t, v)}
}

func summaries(t *testing.T) func(*hook.Result, error) string {
	return func(res *hook.Result, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, d := range res.Diagnostics {
			sev := "error"
			if d.Severity == hook.SeverityWarning {
				sev = "warning"
			}
			out = append(out, sev+" "+d.Summary)
		}
		return strings.Join(out, "; ")
	}
}

// TestBudgetSlowProgram: a program that overruns the
// per-resource deadline is not_evaluable/timeout, and so is every control
// after it; a deny control blocks.
func TestBudgetSlowProgram(t *testing.T) {
	var n atomic.Int32
	l := budgetLifecycle(t, profile.Budgets{PerResourceMs: 10}, sleepProgram{30 * time.Millisecond}, &n)
	got := summaries(t)(l.Evaluate(context.Background(), createPlan(t)))
	want := "error [rds_db_instance_encryption_at_rest_enabled] not evaluable (timeout); " +
		"error [rds_instance_kms_key_configured] not evaluable (timeout); " +
		"warning [rds_instance_engine_not_mysql] not evaluable (timeout); " +
		"error [rds_instance_deletion_protection_enabled] not evaluable (timeout)"
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// TestBudgetDefaults: without profile budgets the interim caps apply.
func TestBudgetDefaults(t *testing.T) {
	if b := budgetsOf(nil); b.perResource != 50*time.Millisecond || b.perRun != 60*time.Second {
		t.Fatalf("defaults %+v, want 50ms / 60s", b)
	}
	c := &Configured{Resolution: profile.Resolution{Profile: &profile.Profile{Budgets: profile.Budgets{PerResourceMs: 200, PerRunS: 30}}}}
	if b := budgetsOf(c); b.perResource != 200*time.Millisecond || b.perRun != 30*time.Second {
		t.Fatalf("profile budgets %+v, want 200ms / 30s", b)
	}
	// New leaves the test lever unset: Evaluate uses the profile budgets.
	l := New(Options{})
	if b := l.budgets(c); b != budgetsOf(c) {
		t.Fatalf("New: budgets %+v, want the profile's %+v", b, budgetsOf(c))
	}
	l.testPerResource = time.Second
	if b := l.budgets(c); b.perResource != time.Second || b.perRun != 30*time.Second {
		t.Fatalf("test lever: %+v, want 1s / 30s", b)
	}
}

// TestBudgetRunExhausted: once the per-process total passes per_run_s,
// every later control is not_evaluable/limit without running.
func TestBudgetRunExhausted(t *testing.T) {
	var n atomic.Int32
	l := budgetLifecycle(t, profile.Budgets{PerRunS: 10}, sleepProgram{}, &n)
	if got := summaries(t)(l.Evaluate(context.Background(), createPlan(t))); got != "" {
		t.Fatalf("within budget: %s", got)
	}
	l.spent.Add(int64(10 * time.Second))
	got := summaries(t)(l.Evaluate(context.Background(), createPlan(t)))
	if !strings.Contains(got, "error [rds_db_instance_encryption_at_rest_enabled] not evaluable (limit)") ||
		!strings.Contains(got, "warning [rds_instance_engine_not_mysql] not evaluable (limit)") {
		t.Fatalf("exhausted: %s", got)
	}
}

// TestProgramCache: a control compiles once per bundle digest
// and type, not on every call.
func TestProgramCache(t *testing.T) {
	var n atomic.Int32
	l := budgetLifecycle(t, profile.Budgets{}, sleepProgram{}, &n)
	for range 3 {
		summaries(t)(l.Evaluate(context.Background(), createPlan(t)))
	}
	if got := n.Load(); got != 4 { // four change controls
		t.Fatalf("%d compiles over three plans, want 4", got)
	}
}

// TestProgramCacheSnapshot: a control from one Configured snapshot is cached
// under that snapshot's bundle digest, never under the one loaded since
// (reconfigure race).
func TestProgramCacheSnapshot(t *testing.T) {
	var n atomic.Int32
	l := budgetLifecycle(t, profile.Budgets{}, sleepProgram{}, &n)
	old := &Configured{Controls: stageControlSetDigest(t, "cd")}
	ctl := old.Controls.For("aws_db_instance", bundle.OnCreate)[0]
	a := &engine.Activation{Resource: tftypes.NewValue(dbType, nil)}
	l.check(context.Background(), old, StagePlan, &ctl, a, "", "", &collected{})
	l.progs.Range(func(k, _ any) bool {
		if d := k.(progKey).digest; d != old.Controls.Digest() {
			t.Errorf("program cached under %s, want the snapshot digest %s", d, old.Controls.Digest())
		}
		return true
	})
}

// slowCompiler takes d to compile and then fails.
type slowCompiler struct{ d time.Duration }

func (slowCompiler) ID() string { return "slow" }

func (s slowCompiler) Compile(*bundle.Control, tftypes.Type) (engine.Program, error) {
	time.Sleep(s.d)
	return nil, errors.New("no program")
}

// TestBudgetSlowCompile: compile time counts against the run, and a compile
// that ends past the deadline is timeout, not unresolved.
func TestBudgetSlowCompile(t *testing.T) {
	var n atomic.Int32
	l := budgetLifecycle(t, profile.Budgets{PerResourceMs: 10}, sleepProgram{}, &n)
	l.compiler = slowCompiler{30 * time.Millisecond}
	got := summaries(t)(l.Evaluate(context.Background(), createPlan(t)))
	if !strings.HasPrefix(got, "error [rds_db_instance_encryption_at_rest_enabled] not evaluable (timeout)") {
		t.Fatalf("got %s", got)
	}
	if spent := time.Duration(l.spent.Load()); spent < 30*time.Millisecond {
		t.Fatalf("spent %s, want the compile time charged", spent)
	}
}

// lagCtx has a passed deadline whose cancel has not run yet.
type lagCtx struct{ context.Context }

func (lagCtx) Deadline() (time.Time, bool) { return time.Now().Add(-time.Millisecond), true }

// TestBudgetDeadlineBeforeCancel: a passed deadline is timeout even while
// ctx.Err() is still nil.
func TestBudgetDeadlineBeforeCancel(t *testing.T) {
	var n atomic.Int32
	l := budgetLifecycle(t, profile.Budgets{}, sleepProgram{}, &n)
	ctl := l.cfg.Controls.For("aws_db_instance", bundle.OnCreate)[0]
	a := &engine.Activation{Resource: tftypes.NewValue(dbType, nil)}
	if out := l.budgeted(lagCtx{context.Background()}, l.cfg, &ctl, a); out.State != engine.NotEvaluable || out.Err != engine.ErrTimeout {
		t.Fatalf("outcome %+v, want not_evaluable timeout", out)
	}
}

// TestBudgetExcludesSchemaFetch: the per-resource deadline covers
// the programs only. A value whose type resolves slowly (the proxy fetches
// the upstream schema on first use when Terraform skipped GetSchema: 0.3-1 s
// for hashicorp/aws) must not time out every control.
func TestBudgetExcludesSchemaFetch(t *testing.T) {
	var n atomic.Int32
	// Each fetch alone is twice the budget, and the budget is wide enough
	// for four instant programs on a loaded machine.
	l := budgetLifecycle(t, profile.Budgets{PerResourceMs: 300}, sleepProgram{}, &n)
	slow := func(raw string) *hook.Value {
		return hook.NewValue(msgpack(t, json.RawMessage(raw)), nil, func() (tftypes.Type, error) {
			time.Sleep(600 * time.Millisecond)
			return dbType, nil
		})
	}
	v := `{"storage_encrypted": true, "kms_key_id": "k", "engine": "postgres", "deletion_protection": true}`
	req := &hook.Request{Stage: hook.StagePlan, Kind: hook.KindResource, TypeName: "aws_db_instance", Op: hook.OpCreate,
		Config: slow(v), Prior: slow(`null`), Planned: slow(v)}
	if got := summaries(t)(l.Evaluate(context.Background(), req)); got != "" {
		t.Fatalf("got %s, want no diagnostics", got)
	}
}

// countProgram counts its runs and sleeps d.
type countProgram struct {
	d time.Duration
	n *atomic.Int32
}

func (p countProgram) Eval(context.Context, *engine.Activation) engine.Outcome {
	p.n.Add(1)
	time.Sleep(p.d)
	return engine.Outcome{State: engine.Pass}
}

// TestBudgetRunConcurrent: concurrent evaluations cannot overshoot
// per_run_s by more than one admission. Each admission reserves its
// per-resource deadline, so 40 parallel 100 ms programs under a 1 s run
// budget and a 200 ms deadline run at most (1 s + 200 ms) / 100 ms = 12
// times; the rest are not_evaluable/limit. Run with -race.
func TestBudgetRunConcurrent(t *testing.T) {
	var compiles, runs atomic.Int32
	l := budgetLifecycle(t, profile.Budgets{PerResourceMs: 200, PerRunS: 1}, countProgram{100 * time.Millisecond, &runs}, &compiles)
	ctl := l.cfg.Controls.For("aws_db_instance", bundle.OnCreate)[0]
	start := make(chan struct{})
	var limited, other atomic.Int32
	var wg sync.WaitGroup
	for range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a := &engine.Activation{Resource: tftypes.NewValue(dbType, nil)}
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			switch out := l.budgeted(ctx, l.cfg, &ctl, a); {
			case out.Err == engine.ErrLimit:
				limited.Add(1)
			case out.State != engine.Pass && out.Err != engine.ErrTimeout: // timeout: a scheduling stall
				other.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if n := runs.Load(); n > 12 || n == 0 {
		t.Fatalf("%d programs ran under a 1 s run budget (%d limited), want 1..12", n, limited.Load())
	}
	if other.Load() != 0 {
		t.Fatalf("%d outcomes neither pass, limit nor timeout", other.Load())
	}
}

// TestStageUsesEvaluateSnapshot: a stage evaluates under the
// snapshot Evaluate took its deadline from, not one it reads again.
func TestStageUsesEvaluateSnapshot(t *testing.T) {
	var n atomic.Int32
	l := budgetLifecycle(t, profile.Budgets{}, sleepProgram{}, &n)
	c := l.cfg
	l.cfg = nil // a reconfigure after Evaluate read the snapshot
	if got := summaries(t)(l.plan(context.Background(), c, createPlan(t))); got != "" {
		t.Fatalf("plan under the passed snapshot: %s", got)
	}
}

type errCompiler struct{ err error }

func (errCompiler) ID() string { return "err" }

func (c errCompiler) Compile(*bundle.Control, tftypes.Type) (engine.Program, error) {
	return nil, c.err
}

// TestCompileErrorClass: a control that does not compile is
// not_evaluable with its engine.CompileError class, else unresolved.
func TestCompileErrorClass(t *testing.T) {
	ctl := &bundle.Control{ID: "c"}
	act := &engine.Activation{Resource: tftypes.NewValue(tftypes.Bool, true)}
	for _, c := range []struct {
		err  error
		want engine.ErrClass
	}{
		{&engine.CompileError{Class: engine.ErrNoSuchAttribute, Err: errors.New("type missing")}, engine.ErrNoSuchAttribute},
		{errors.New("no upstream schema source"), engine.ErrUnresolved},
	} {
		l := New(Options{})
		l.compiler = errCompiler{c.err}
		if got := l.budgeted(context.Background(), nil, ctl, act); got.State != engine.NotEvaluable || got.Err != c.want {
			t.Errorf("%v: got %+v, want not_evaluable/%s", c.err, got, c.want)
		}
	}
}

// TestProgramCacheHandBuilt: a Configured built without a
// compiler compiles with a fresh celeng compiler over its own schemas, so
// its programs are never cached under a key another snapshot with the same
// bundle digest and other schemas hits.
func TestProgramCacheHandBuilt(t *testing.T) {
	l := New(Options{})
	cs := stageControlSet(t)
	table := profile.ModeTable{RunMode: profile.HardFail}
	l.cfg = &Configured{Table: table, Controls: cs, Schemas: dbSchemas{}}
	if got := summaries(t)(l.Evaluate(context.Background(), createPlan(t))); strings.Contains(got, "(unresolved)") {
		t.Fatalf("with schemas: %s", got)
	}
	l.cfg = &Configured{Table: table, Controls: cs} // same digest, no upstream schemas
	got := summaries(t)(l.Evaluate(context.Background(), createPlan(t)))
	if want := "error [rds_db_instance_encryption_at_rest_enabled] not evaluable (unresolved)"; !strings.Contains(got, want) {
		t.Fatalf("without schemas: %s\nwant it to contain %s", got, want)
	}
	n := 0
	l.progs.Range(func(any, any) bool { n++; return true })
	if n != 0 {
		t.Errorf("%d programs cached for hand-built snapshots, want none", n)
	}
}

// opProgram fails under create and passes under any other op, like
// rds_op_create_encrypted on a bad value. Under op slow it first sleeps d,
// past the per-resource deadline: one evaluation of a control times out.
type opProgram struct {
	slow engine.Op
	d    time.Duration
}

func (p opProgram) Eval(_ context.Context, a *engine.Activation) engine.Outcome {
	if a.Op == p.slow {
		time.Sleep(p.d)
	}
	if a.Op == engine.OpCreate {
		return engine.Outcome{State: engine.Fail}
	}
	return engine.Outcome{State: engine.Pass}
}

// TestTimeoutNeverWaives: a timeout in the evaluation under
// Request.Op (update, passes) or under the alt op (create, fails)
// leaves a deny control blocking, and the exception lookups, which share
// the spent per-resource deadline, never waive it. Without a timeout the
// alt op's fail is waived by the same exception, so the oracle is live.
func TestTimeoutNeverWaives(t *testing.T) {
	for _, tc := range []struct {
		name     string
		slow     engine.Op
		excepted bool
	}{
		{"no timeout", "", true},
		{"request op times out", engine.OpUpdate, false},
		{"alt op times out", engine.OpCreate, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, _ := opLifecycle(t, opEncryption, "true", false)
			var n atomic.Int32
			l.compiler = fakeCompiler{opProgram{tc.slow, 300 * time.Millisecond}, &n}
			i := slices.IndexFunc(l.cfg.Controls.All(), func(c bundle.Control) bool { return c.ID == opEncryption })
			ctl := l.cfg.Controls.All()[i]
			budget := 100 * time.Millisecond
			if tc.slow == "" {
				budget = time.Minute // the oracle checks the waiver, not the budget
			}
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			col := &collected{alt: []engine.Op{engine.OpCreate}}
			l.check(ctx, l.cfg, StageApplyPre, &ctl, &engine.Activation{Resource: tftypes.NewValue(dbType, nil), Op: engine.OpUpdate}, "", "", col)
			if len(col.results) != 1 || (col.results[0].Decision == "excepted") != tc.excepted {
				t.Fatalf("results %+v, want excepted %v", col.results, tc.excepted)
			}
			blocked := slices.ContainsFunc(col.diags, func(d hook.Diagnostic) bool { return d.Severity == hook.SeverityError })
			if blocked == tc.excepted {
				t.Errorf("diagnostics %+v, want blocked %v", col.diags, !tc.excepted)
			}
		})
	}
}
