package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/baseline"
	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/evidence"
	"github.com/compliancetf/terraform-provider-aws/internal/exceptions"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict"
)

// Wants reports whether the loaded control set targets typeName of kind. It
// is a skip shortcut only: apply_pre reaches Evaluate for every type. Before
// Configure it wants every resource, data source and ephemeral resource, so
// Evaluate fails closed: a plan or an ephemeral open errors, and a data
// source read is blocked with an error diagnostic.
func (l *Lifecycle) Wants(kind hook.Kind, typeName string) bool {
	if kind != hook.KindResource && kind != hook.KindEphemeral && kind != hook.KindDataSource {
		return false
	}
	c := l.Configured()
	if c == nil || c.Controls == nil {
		return true
	}
	if kind == hook.KindEphemeral || kind == hook.KindDataSource {
		return len(c.Controls.OfKind(bundle.Kind(kind), typeName)) > 0
	}
	for _, on := range []bundle.On{bundle.OnCreate, bundle.OnUpdate, bundle.OnDelete} {
		if len(c.Controls.For(typeName, on)) > 0 {
			return true
		}
	}
	return false
}

// Evaluate runs one hook stage. validate evaluates nothing (L4); plan,
// apply_pre, apply_post, read (refresh), import, ephemeral_open and
// data_source evaluate.
func (l *Lifecycle) Evaluate(ctx context.Context, req *hook.Request) (*hook.Result, error) {
	// Decode first: the first Get may fetch the upstream schema (0.3-1 s for
	// hashicorp/aws when Terraform skipped GetSchema), which is not a program
	// and must not spend the budget. Get memoizes value and error;
	// the stages report the error as before.
	if req.Stage != hook.StageValidate {
		for _, v := range []*hook.Value{req.Config, req.Prior, req.Planned, req.New} {
			if v != nil {
				_, _ = v.Get() //nolint:errcheck // memoized: the stage reports it
			}
		}
	}
	// One snapshot for the deadline and the stage, and one
	// per-resource deadline around every program of this evaluation (5.7).
	c := l.Configured()
	ctx, cancel := context.WithTimeout(ctx, l.budgets(c).perResource)
	defer cancel()
	switch req.Stage {
	case hook.StageValidate:
		return &hook.Result{}, nil
	case hook.StagePlan:
		return l.plan(ctx, c, req)
	case hook.StageApplyPre:
		return l.applyPre(ctx, c, req)
	case hook.StageApplyPost:
		return l.applyPost(ctx, c, req)
	case hook.StageRead:
		return l.observe(ctx, c, req, StageRead, engine.OpRefresh)
	case hook.StageImport:
		return l.observe(ctx, c, req, StageImport, engine.OpImport)
	case hook.StageEphemeralOpen:
		return l.ephemeralOpen(ctx, c, req)
	case hook.StageDataSource:
		return l.dataSource(ctx, c, req)
	case hook.StageRPC:
		return l.rpcGate(ctx, c, req)
	}
	return nil, fmt.Errorf("lifecycle: stage %s is not implemented in this provider version", req.Stage)
}

// plan evaluates the upstream plan (the proxy forwards first, so Planned is
// upstream's PlannedState) and returns the versions digest for the envelope.
// A delete runs the deletion guards on Prior; a replace runs both halves (the
// guards on Prior, the change controls on Planned) and a block in either
// blocks the plan; every other op runs the change controls.
func (l *Lifecycle) plan(ctx context.Context, c *Configured, req *hook.Request) (*hook.Result, error) {
	if c == nil || c.Controls == nil {
		return nil, errors.New("lifecycle: plan before Configure")
	}
	if req.Config == nil || req.Planned == nil {
		// Core always sends both; a null default would pass negated predicates.
		return nil, errors.New("lifecycle: plan request without config or planned state")
	}
	prior, err := get(req.Prior)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: prior state: %w", err)
	}
	planned, err := get(req.Planned)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: planned state: %w", err)
	}
	config, err := get(req.Config)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: config: %w", err)
	}
	// A null Planned is a delete; a non-null Planned with a replace or delete
	// hint or a RequiresReplace path is a replace. Envelope hints only raise:
	// a delete hint on a non-null Planned adds the create half, never drops it.
	// A null Prior is a create, so RequiresReplace
	// is ignored there (SDKv2 upstreams send it on create; Terraform core and
	// proxy planOp agree). A replace or delete hint on a null Prior still fails.
	deleting := planned.IsNull()
	replacing := !deleting && (req.Op == hook.OpDelete || req.Op == hook.OpReplace || (len(req.RequiresReplace) > 0 && !prior.IsNull()))
	if deleting && prior.IsNull() {
		// Core never sends this; a guard on a null Prior would decide nothing.
		return nil, errors.New("lifecycle: delete plan without prior state")
	}
	if replacing && prior.IsNull() {
		return nil, errors.New("lifecycle: replace plan without prior state")
	}
	res := &hook.Result{ControlVersionsDigest: c.Controls.VersionsDigest(req.TypeName)}
	col := &collected{}
	half := func(h string) string {
		if replacing {
			return h
		}
		return ""
	}
	op := engine.OpCreate
	switch {
	case deleting:
		op = engine.OpDelete
	case replacing:
		op = engine.OpReplace
	case !prior.IsNull():
		op = engine.OpUpdate
	}
	// An update that changes nothing (Planned
	// equals Prior, both fully known, so no unknown can fake equality)
	// downgrades blocking failures to warnings. Terraform applies nothing for
	// it, and terraform destroy's pre-destroy plan has this shape. Any change,
	// replace, create and delete keep the full matrix.
	col.unchanged = op == engine.OpUpdate && planned.IsFullyKnown() && prior.IsFullyKnown() && planned.Equal(prior)
	// Delete half (L1): only on [delete] controls, the deletion guards, on Prior.
	if deleting || replacing {
		guards := c.Controls.For(req.TypeName, bundle.OnDelete)
		for i := range guards {
			a := &engine.Activation{Resource: prior, Config: config, Prior: prior, Op: op, RegionFromResource: true}
			l.check(ctx, c, StagePlan, &guards[i], a, "", half("delete"), col)
		}
	}
	if deleting {
		col.diags = append(col.diags, l.record(c, req, StagePlan, op, prior, col.results, false, false)...)
		res.Diagnostics = col.diags
		return res, nil
	}
	// Create half, and every other op. op is a hint for the activation and
	// the severity matrix (replace raises unknown to an error) only.
	controls := changeControls(c.Controls, req.TypeName)
	for i := range controls {
		ctl := &controls[i]
		resource := planned
		if ctl.PresenceMode == bundle.PresenceConfigured {
			resource = config
		}
		a := &engine.Activation{Resource: resource, Config: config, Prior: prior, Op: op}
		l.check(ctx, c, StagePlan, ctl, a, "", half("create"), col)
	}
	evOp := op
	switch {
	case op == engine.OpUpdate && req.Op == hook.OpImport:
		evOp = engine.OpImport // evidence only, never a decision input
	case col.unchanged:
		evOp = engine.OpNoOp
	}
	col.diags = append(col.diags, l.record(c, req, StagePlan, evOp, planned, col.results, false, false)...)
	res.Diagnostics = col.diags
	return res, nil
}

// changeControls is the set every non-delete change runs (L1): each control
// whose on includes create or update. Classification never drives
// enforcement, so an update cannot skip a create-only control. Apply's create
// and update RPCs reuse it.
func changeControls(cs *bundle.ControlSet, typeName string) []bundle.Control {
	return union(cs.For(typeName, bundle.OnCreate), cs.For(typeName, bundle.OnUpdate))
}

// eval is the only evaluation path. It binds env from the trusted scope
// dimension env and the provider from c, overwriting whatever the caller
// set, then compiles ctl
// against the bound value's type (cached per bundle digest and type) and
// runs it on a copy of a under the budgets (5.7, budget.go). A control that
// does not compile (an expr control without upstream schemas) is
// not_evaluable and takes the fail row. c is the snapshot ctl came from (nil
// before Configure): budgets and the cache key read it, never a newer one.
func (l *Lifecycle) eval(ctx context.Context, c *Configured, env profile.Dim, ctl *bundle.Control, a *engine.Activation) engine.Outcome {
	return l.budgeted(ctx, c, ctl, bound(c, env, a))
}

// bound is a copy of a with the trusted env and the provider bound (the
// resource's own region overrides the provider-level one): the
// activation of a control and of its exception selectors.
func bound(c *Configured, env profile.Dim, a *engine.Activation) *engine.Activation {
	act := *a
	act.Env, act.EnvKnown = trustedEnv(env)
	act.Provider = bindProvider(c, &act)
	return &act
}

// bindProvider is the provider binding of a: the Configure snapshot's,
// overridden by the resource's own region. Recompute it after
// changing a's values.
func bindProvider(c *Configured, a *engine.Activation) engine.ProviderInfo {
	p := engine.ProviderInfo{}
	if c != nil {
		p = c.Provider
	}
	return resourceProvider(p, a)
}

// trustedEnv is the engine env binding (Scope binding).
// Only a signed scope is trusted: profile.ComputeModeTable is the only
// writer of ModeTable.Environment and sets Source "profile" only from the
// scope of a verified profile and "verdict" only from a verified verdict;
// local environment values never reach it. Trust is by provenance, the
// value is used verbatim; an empty or whitespace-padded value is untrusted,
// so env-dependent results are not_evaluable/scope_untrusted (fail closed).
func trustedEnv(d profile.Dim) (string, bool) {
	if (d.Source != "profile" && d.Source != "verdict") || d.Value == "" || strings.TrimSpace(d.Value) != d.Value {
		return "", false
	}
	return d.Value, true
}

// union is a followed by the controls of b not in a, keyed by (id, kind).
func union(a, b []bundle.Control) []bundle.Control {
	out := slices.Clone(a)
	for _, c := range b {
		if !slices.ContainsFunc(a, func(x bundle.Control) bool { return x.ID == c.ID && x.Kind == c.Kind }) {
			out = append(out, c)
		}
	}
	return out
}

// get decodes a hook value; an absent value is a null of unknown type.
func get(v *hook.Value) (tftypes.Value, error) {
	if v == nil {
		return tftypes.NewValue(tftypes.DynamicPseudoType, nil), nil
	}
	return v.Get()
}

// collected is what one stage call gathers: diagnostics and evidence results.
type collected struct {
	diags     []hook.Diagnostic
	results   []evidence.Result
	unchanged bool // plan of an update with Planned == Prior: errors become warnings
	// listed, at apply under verdict_required, is what the verdict lists for
	// the matched instance: an exception it does not list never waives.
	listed *listing
	// baseline, at apply, is the one matched verdict entry for the baseline
	// matcher; the zero Instance (plan, no or several matches) never matches.
	// At apply_post it is the apply_pre Instance of the same RPC.
	baseline baseline.Instance
	// applied, at apply_post, is NewState: the baseline entry that matched
	// at apply_pre must also match with NewState as the planned state.
	applied *tftypes.Value
	// appliedIdentity, at apply_post, is NewIdentity: an identity-kind entry
	// must also name the identity upstream returned.
	appliedIdentity map[string]any
	// alt are the ops a control is also evaluated under; the worst outcome
	// stands. At apply the envelope steers Request.Op to replace
	// or change, so a control reading op is also run under the RPC shape op.
	alt []engine.Op
	// prov, at apply, holds the matched entries' resource-local provisional
	// decisions and their proofs; nil without a matched entry.
	prov *provisional
	// preset, when set, is the outcome of the control instead of evaluating
	// it: a data source read with no value to bind is not_evaluable.
	preset *engine.Outcome
}

// grandfathered is the baseline decision for ctl on col.baseline; at
// apply_post the same entry must also match with the applied state as the
// planned state (and, for kind identity, the applied identity), so an
// upstream change to a read attribute or the identity never rides an
// apply_pre match.
func (col *collected) grandfathered(c *Configured, ctl *bundle.Control) bool {
	d := baselineDecision(c, ctl, col.baseline)
	if !d.Grandfathered || col.applied == nil {
		return d.Grandfathered
	}
	post := col.baseline
	post.Planned = *col.applied
	if post.IdentityKind == "identity" {
		post.PriorIdentity = nil // no applied identity: never matches
		if b, err := json.Marshal(col.appliedIdentity); err == nil && col.appliedIdentity != nil {
			post.PriorIdentity = b
		}
	}
	e := baselineDecision(c, ctl, post)
	return e.Grandfathered && e.Entry == d.Entry
}

const shapeSplitNote = "This control fails under one of create and update and passes under the other. " +
	"Terraform did not say whether it created or updated this resource, so the outcome depends on which it did: this violation warns."

const unchangedNote = "No change planned: this violation warns until the resource changes; any change to it is blocked."

// check evaluates one control at stage, records its result and appends its
// diagnostic, if the severity matrix gives one. A non-empty changed is the
// stamp mismatch detail: the control is still evaluated but takes the fail
// row, so blocking controls fail closed and the others warn. half is the
// replace half (create or delete) or "".
func (l *Lifecycle) check(ctx context.Context, c *Configured, stage Stage, ctl *bundle.Control, a *engine.Activation, changed, half string, col *collected) {
	// c is the snapshot ctl came from, not whatever is loaded now: the
	// program cache keys by its bundle digest.
	var base engine.Outcome
	if col.preset != nil {
		base = *col.preset
	} else {
		base = l.eval(ctx, c, c.Table.Environment, ctl, a)
	}
	out := base
	var altPass, altFail bool
	for _, op := range col.alt {
		o := base
		if op != a.Op {
			b := *a
			b.Op = op
			o = l.eval(ctx, c, c.Table.Environment, ctl, &b)
		}
		switch o.State {
		case engine.Pass:
			altPass = true
		case engine.Fail:
			altFail = true
		}
		if rank(o.State) > rank(out.State) {
			out = o
		}
	}
	// At apply_post an op change is a create or an update and Terraform does
	// not say which: when one shape passes and the other fails the control
	// warns, it cannot error on a shape that may not have run.
	// Unknown and not_evaluable, under a shape or under change itself, are no
	// split: they keep the worse severity. Evidence keeps the worst outcome.
	split := stage == StageApplyPost && a.Op == engine.OpChange && altPass && altFail && changed == "" &&
		out.State == engine.Fail && (base.State == engine.Pass || base.State == engine.Fail)
	state := out.State
	if changed != "" {
		state = engine.Fail
	}
	mode := c.Table.ControlMode(ctl.ID, ctl.Action == bundle.ActionDeny)
	// The baseline matches only a verified verdict entry: apply_pre passes
	// the one matched entry, apply_post that same entry, every other stage
	// the zero Instance.
	gf := col.grandfathered(c, ctl)
	v := Classify(mode, ctl.Action, state, stage, a.Op, gf)
	downgraded := col.unchanged && stage == StagePlan && v.Severity == SeverityError
	if downgraded {
		v.Severity = SeverityWarning
	}
	r := result(ctl, out, state, stage, v.Severity, half, c.pathCompiler())
	if stage == StagePlan {
		r.ReadDigest = c.readDigest(ctl, a.Prior)
	}
	split = split && v.Severity == SeverityError
	if split {
		v.Severity = SeverityWarning
	}
	// A matched entry's resource-local provisional decision needs
	// its final proof whatever this evaluation gives, with or without
	// verdict_required: only an exception every match lists, the baseline
	// matcher under mode grandfather or a receipt proves it.
	addr, prov := "", false
	if stage == StageApplyPre && changed == "" {
		addr, prov = col.prov.on(ctl.ID, ctl.Version)
	}
	lst := col.listed
	if prov && lst == nil {
		lst = col.prov.listed
	}
	// Under verdict_required plan never waives with a local exception: only
	// the exceptions the verdict lists count, and the verdict loads at apply
	// (A59, A60), so an eligible failure stays a provisional warning.
	if (state != engine.Pass || prov) && changed == "" && (stage != StagePlan || !c.Table.VerdictRequired) {
		// A signed grant or a self-service exception waives fail, unknown
		// and not_evaluable with no diagnostic; a stamp mismatch is never
		// waived. A grant is tried first; the first exception considered is
		// recorded when none applies.
		act := bound(c, c.Table.Environment, a)
		d := l.exceptAll(ctx, c, ctl, act, col.alt)
		if d.Applied && lst != nil && !lst.allows(d.Exception) {
			e := *d.Exception
			e.Status = exceptions.StatusRejected
			d.Exception, d.Applied = &e, false
			d.Log = append(d.Log, fmt.Sprintf("exception %s: not applied: the verdict does not list it for this instance", e.ID))
		}
		d.WriteLog()
		r.Exception = d.Exception
		if d.Applied {
			if state != engine.Pass {
				r.Decision = "excepted"
			}
			col.results = append(col.results, r)
			if stage == StagePlan && half != "" {
				col.diags = append(col.diags, l.halfCheck(ctx, c, ctl, act, engine.Op(half), d)...)
			}
			return
		}
	}
	if prov {
		if id, ok := col.prov.receipt(ctl.ID, ctl.Version); ok {
			if state != engine.Pass {
				r.Decision = "excepted"
			}
			r.BreakGlassID = id
			col.results = append(col.results, r)
			return
		}
		if mode != profile.Grandfather || !gf {
			r.Decision, r.Situation = "blocked", verdict.SitUnproven
			col.results = append(col.results, r)
			col.diags = append(col.diags, hook.Diagnostic{Severity: hook.SeverityError, Attribute: attrPath(ctl.Reads),
				Summary: verdict.UnprovenText(ctl.ID, addr)})
			return
		}
	}
	var pending []string
	if stage == StagePlan && v.Severity == SeverityError && (state == engine.Fail || state == engine.NotEvaluable) {
		pending = pendingKinds(c, ctl, mode)
	}
	if len(pending) > 0 {
		v.Severity = SeverityWarning
		r.Decision = decision(stage, state, v.Severity)
	}
	col.results = append(col.results, r)
	if v.Severity == SeverityNone {
		return
	}
	if len(pending) > 0 {
		col.diags = append(col.diags, pendingDiags(c, ctl, out, mode, stage, pending)...)
		return
	}
	d := hook.Diagnostic{Severity: hook.SeverityError, Attribute: attrPath(ctl.Reads)}
	if v.Severity == SeverityWarning {
		d.Severity = hook.SeverityWarning
	}
	if changed != "" {
		d.Summary = fmt.Sprintf("[%s] controls changed between plan and apply", ctl.ID)
		d.Detail = changed
	} else {
		d.Summary, d.Detail = diagText(ctl, out, mode, v.Severity, stage, c.fields(ctl.ID))
	}
	if downgraded {
		d.Detail = unchangedNote + "\n" + d.Detail
	}
	if split {
		d.Detail = shapeSplitNote + "\n" + d.Detail
	}
	col.diags = append(col.diags, d)
}

// pendingKinds are the exemption kinds eligible at plan for a blocking
// fail or not_evaluable of ctl under mode: the signed coverable
// map only, never an exemption artifact; grant also needs
// exception_grants_dir, self_service the control in the signed profile's
// exceptions.self_service, baseline mode grandfather and a grandfatherable
// control, break_glass a profile that enables it online.
func pendingKinds(c *Configured, ctl *bundle.Control, mode profile.Mode) []string {
	gf := false
	if mode == profile.Grandfather && c.Schemas != nil {
		s, _ := c.Schemas.Resource(ctl.ResourceType) //nolint:errcheck // nil: not grandfatherable
		gf = baseline.Grandfatherable(ctl, s)
	}
	return verdict.PendingKinds(verdict.Eligibility{Coverable: func(k string) bool { return c.Coverability.Coverable(ctl.ID, k) },
		Grandfather: gf, BreakGlass: c.BreakGlass.Enabled(), Grants: c.Grants != nil, SelfService: slices.Contains(c.Table.SidecarControls, ctl.ID)})
}

// pendingDiags are the plan warnings of a blocking failure eligible for an
// exemption: one per kind, value-free (control id, message and fixed text).
func pendingDiags(c *Configured, ctl *bundle.Control, out engine.Outcome, mode profile.Mode, stage Stage, kinds []string) []hook.Diagnostic {
	summary, detail := diagText(ctl, out, mode, SeverityError, stage, c.fields(ctl.ID))
	diags := make([]hook.Diagnostic, len(kinds))
	for i, k := range kinds {
		diags[i] = hook.Diagnostic{Severity: hook.SeverityWarning, Attribute: attrPath(ctl.Reads), Summary: verdict.PendingSummary(k, ctl.ID),
			Detail: fmt.Sprintf("%s\nThis blocking failure is eligible for a %s exemption, so plan continues. Apply blocks it unless ctfkit gate sign lists the final proof for this instance.\n%s", summary, k, detail)}
	}
	return diags
}

// except is the exception decision for ctl on the bound activation act: a
// signed grant first, then the sidecar.
func (l *Lifecycle) except(ctx context.Context, c *Configured, ctl *bundle.Control, act *engine.Activation) exceptions.Decision {
	d := c.Grants.Lookup(ctx, ctl, c.Schemas, act, l.opt.Now())
	if !d.Applied {
		d = exceptions.Combine(d, c.Sidecar.Lookup(ctx, ctl, c.Schemas, act, l.opt.Now()))
	}
	return d
}

// exceptAll is the exception decision for ctl under act.Op and every alt op.
// A selector must waive under every op the control ran under, so an
// envelope-steered op never widens an exception. The decision
// under act.Op (Request.Op) is the one recorded, with the log lines of every
// lookup. When an alt op refuses, the entry that applied under act.Op is
// recorded rejected, so the evidence names it.
func (l *Lifecycle) exceptAll(ctx context.Context, c *Configured, ctl *bundle.Control, act *engine.Activation, alt []engine.Op) exceptions.Decision {
	first := l.except(ctx, c, ctl, act)
	if !first.Applied {
		return first
	}
	for _, op := range alt {
		if op == act.Op {
			continue
		}
		b := *act
		b.Op = op
		d := l.except(ctx, c, ctl, &b)
		d.Log = appendNew(slices.Clone(first.Log), d.Log...)
		if !d.Applied {
			d.Log = append(d.Log, fmt.Sprintf("exception %s: not applied: selector not matched or unknown under op %s", first.Exception.ID, op))
			e := *first.Exception
			e.Status = exceptions.StatusRejected
			d.Exception = &e
			return d
		}
		first.Log = d.Log
	}
	return first
}

// halfCheck runs at plan on a replace half whose control the exception d
// waived under replace. Apply runs that half as its own RPC, under replace
// and the half op, and waives only if both match; the create RPC
// has no prior and the delete RPC no config. halfCheck runs that same
// lookup on that shape and warns when it would not waive. The
// plan decision stands.
func (l *Lifecycle) halfCheck(ctx context.Context, c *Configured, ctl *bundle.Control, act *engine.Activation, op engine.Op, d exceptions.Decision) []hook.Diagnostic {
	b := *act // Op stays replace; op is the alt, as at apply
	null := tftypes.NewValue(tftypes.DynamicPseudoType, nil)
	shape := "no prior state"
	if op == engine.OpCreate {
		b.Prior = null
	} else {
		b.Config = null
		shape = "no configuration"
	}
	b.Provider = bindProvider(c, &b) // the region source may have changed
	if h := l.exceptAll(ctx, c, ctl, &b, []engine.Op{op}); h.Applied || h.Unresolved {
		return nil // an unknown selector is retried at apply
	}
	return []hook.Diagnostic{{Severity: hook.SeverityWarning, Attribute: attrPath(ctl.Reads),
		Summary: fmt.Sprintf("[%s] exception %s waives this replace at plan but not at apply", ctl.ID, d.Exception.ID),
		Detail: fmt.Sprintf("Apply checks the %s half under op replace and under op %s, with %s, and there this exception is not matched, so it will not waive at apply. "+
			"A match that reads op must name the half ops (op in ['replace', 'create', 'delete']) or read no op.", op, op, shape)}}
}

// appendNew is log with the lines of more it does not already hold.
func appendNew(log []string, more ...string) []string {
	for _, m := range more {
		if !slices.Contains(log, m) {
			log = append(log, m)
		}
	}
	return log
}

// rank orders states by how much they block: pass, then unknown, then the
// fail row (fail, not_evaluable and any unrecognized state).
func rank(s engine.State) int {
	switch s {
	case engine.Pass:
		return 0
	case engine.Unknown:
		return 1
	}
	return 2
}

// diagText is the summary and detail of the diagnostics table.
func diagText(ctl *bundle.Control, out engine.Outcome, mode profile.Mode, sev Severity, stage Stage, show shown) (string, string) {
	paths := strings.Join(out.UnknownPaths, ", ")
	if stage == StageEphemeralOpen && sev == SeverityError {
		// Every block names the control and
		// says the secret was not opened; the reason lines are value-free.
		lines := []string{fmt.Sprintf("Opening ephemeral %s was blocked; the secret was not opened.", ctl.ResourceType)}
		switch out.State {
		case engine.Unknown:
			lines = append(lines, fmt.Sprintf("Still unknown: %s.", paths))
		case engine.NotEvaluable:
			lines = append(lines, fmt.Sprintf("Not evaluable (%s): treated as a failure of this control.", out.Err))
		}
		return fmt.Sprintf("[%s] %s", ctl.ID, ctl.Message), strings.Join(append(lines, detailLines(ctl, mode, stage, show)...), "\n")
	}
	switch {
	case out.State == engine.Unknown && stage == StageDataSource:
		return fmt.Sprintf("[%s] pending: re-checked when known", ctl.ID), fmt.Sprintf("Still unknown: %s.", paths)
	case out.State == engine.Unknown && sev == SeverityError && stage == StagePlan:
		return fmt.Sprintf("[%s] replacement blocked: control undecided at plan", ctl.ID),
			"The prior object would be destroyed before this control runs."
	case out.State == engine.Unknown && sev == SeverityError:
		return fmt.Sprintf("[%s] cannot be verified before apply", ctl.ID),
			fmt.Sprintf("Still unknown: %s. Set them in configuration or use presence_mode configured.", paths)
	case out.State == engine.Unknown:
		return fmt.Sprintf("[%s] pending: re-checked at apply", ctl.ID), fmt.Sprintf("Unknown until apply: %s.", paths)
	case out.State == engine.NotEvaluable:
		return fmt.Sprintf("[%s] not evaluable (%s)", ctl.ID, out.Err), "Treated as a failure of this control."
	}
	summary := fmt.Sprintf("[%s] %s", ctl.ID, ctl.Message)
	var lines []string
	if stage == StageApplyPost {
		summary = fmt.Sprintf("[%s] applied value violates control", ctl.ID)
		lines = append(lines, "The change was applied and state recorded. Fix configuration and apply again.")
	}
	return summary, strings.Join(append(lines, detailLines(ctl, mode, stage, show)...), "\n")
}

// shown is what the detail lines of one control's diagnostics show: the
// COMPLIANCETF_DIAGNOSTICS fields and the exceptions_file path when the
// sidecar can waive the control ("" when it cannot).
type shown struct {
	fields Field
	waive  string
}

// fields is what diagnostics of control id show under c.
func (c *Configured) fields(id string) shown {
	s := shown{fields: c.Block.Fields}
	if c.Sidecar.Waivable(id) {
		s.waive = c.Block.ExceptionsFile
	}
	return s
}

// detailLines are the detail lines after the reason, in field order: fix,
// docs, waive, severity, mode, stage (and type at the data source stage),
// frameworks. Zero fields is the default set.
func detailLines(ctl *bundle.Control, mode profile.Mode, stage Stage, show shown) []string {
	f := show.fields
	if f == 0 {
		f = presets["default"]
	}
	var lines []string
	if f&FieldFix != 0 && ctl.Fix != "" {
		lines = append(lines, "Fix: "+ctl.Fix)
	}
	if f&FieldDocs != 0 {
		lines = append(lines, "Docs: "+docsBase+ctl.ID+"/")
	}
	if f&FieldWaive != 0 && show.waive != "" {
		lines = append(lines, fmt.Sprintf("To waive: add an exception for %s in %s", ctl.ID, show.waive))
	}
	if f&FieldSeverity != 0 {
		lines = append(lines, "Severity: "+string(ctl.Severity))
	}
	if f&FieldMode != 0 {
		lines = append(lines, "Mode: "+mode.String())
	}
	if f&FieldStage != 0 {
		lines = append(lines, "Stage: "+stageName(stage))
		if stage == StageDataSource {
			lines = append(lines, "Type: "+ctl.ResourceType)
		}
	}
	if f&FieldFrameworks != 0 && len(ctl.FrameworkRefs) > 0 {
		lines = append(lines, "Frameworks: "+strings.Join(ctl.FrameworkRefs, ", "))
	}
	return lines
}

// attrPath is the top-level attribute of the first reads path. reads drop
// the "*" element steps, so a deeper path could name a collection element
// as an attribute; the top-level name is always a valid path.
func attrPath(reads []string) *tftypes.AttributePath {
	if len(reads) == 0 {
		return nil
	}
	top, _, _ := strings.Cut(reads[0], ".")
	return tftypes.NewAttributePath().WithAttributeName(top)
}
