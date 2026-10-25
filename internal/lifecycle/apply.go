package lifecycle

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/baseline"
	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/evidence"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
)

// applyPre is apply before forwarding. It re-derives the control set from
// the loaded bundles (the envelope never selects controls) and runs only the
// RPC's own half: a destroy RPC (null Planned) the deletion guards on Prior,
// ignoring the envelope; any other RPC the change controls, the same set as
// plan. Any error diagnostic blocks the forward (0A rule).
func (l *Lifecycle) applyPre(ctx context.Context, c *Configured, req *hook.Request) (*hook.Result, error) {
	if c == nil || c.Controls == nil {
		return nil, errors.New("lifecycle: apply before Configure")
	}
	if req.Blocked != "" {
		return l.proxyBlocked(c, req)
	}
	if req.Config == nil || req.Planned == nil {
		return nil, errors.New("lifecycle: apply request without config or planned state")
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
	if planned.IsNull() && prior.IsNull() {
		return nil, errors.New("lifecycle: delete apply without prior state")
	}
	op := engine.Op(req.Op)
	sc, err := l.scopedToVerdict(c)
	if err != nil {
		state := planned
		if planned.IsNull() {
			state = prior
		}
		// Like a verdict that fails to load, this blocks before any situation
		// table row is reached: no row label.
		return &hook.Result{Diagnostics: l.gateBlock(c, req, op, state, scopeSummary, scopeDetail, "")}, nil
	}
	c = sc
	// The verdict gate is the first step for every type and op (B4).
	g := l.applyVerdictGate(ctx, c, req, op, prior, planned, config)
	if g.block != nil {
		return &hook.Result{Diagnostics: g.block}, nil
	}
	res := &hook.Result{}
	col := &collected{alt: []engine.Op{shapeOp(prior, planned)}, diags: g.diags, results: g.results, listed: g.listed, baseline: g.baseline, prov: g.prov}
	required := evidenceRequired(c)
	if planned.IsNull() {
		// A missing or stale envelope on a delete is treated as absent (A53).
		guards := c.Controls.For(req.TypeName, bundle.OnDelete)
		for i := range guards {
			a := &engine.Activation{Resource: prior, Config: config, Prior: prior, Op: op, RegionFromResource: true}
			l.check(ctx, c, StageApplyPre, &guards[i], a, "", "", col)
		}
		col.diags = append(col.diags, l.recordMatched(c, req, StageApplyPre, op, prior, col.results, false, required, g.matched)...)
		res.Diagnostics = col.diags
		return res, nil
	}
	controls := changeControls(c.Controls, req.TypeName)
	changed, absent := "", false
	switch loaded := c.Controls.VersionsDigest(req.TypeName); {
	case len(controls) == 0:
	case req.Envelope == nil:
		absent = true
		col.diags = append(col.diags, hook.Diagnostic{Severity: hook.SeverityWarning,
			Summary: "Compliance plan envelope absent",
			Detail:  fmt.Sprintf("The plan for %s carried no compliance envelope; every control is evaluated at apply.", req.TypeName)})
	case req.Envelope.CTF.ControlVersionsDigest != loaded:
		planUsed := req.Envelope.CTF.ControlVersionsDigest
		if planUsed == "" {
			planUsed = "none"
		}
		changed = fmt.Sprintf("Controls changed between plan and apply: plan used %s, provider loaded %s. Re-run plan.", planUsed, loaded)
	}
	for i := range controls {
		ctl := &controls[i]
		resource := planned
		if ctl.PresenceMode == bundle.PresenceConfigured {
			resource = config
		}
		a := &engine.Activation{Resource: resource, Config: config, Prior: prior, Op: op}
		l.check(ctx, c, StageApplyPre, ctl, a, changed, "", col)
	}
	// The record is written (fsynced under evidence.required) before the
	// proxy forwards; a required write failure blocks the forward.
	col.diags = append(col.diags, l.recordMatched(c, req, StageApplyPre, op, planned, col.results, absent, required, g.matched)...)
	res.Diagnostics = col.diags
	res.Carry = g.baseline // apply_post re-checks the same match on NewState
	return res, nil
}

// applyPost is apply after forwarding: the effective change controls on
// NewState (configured controls and deletion guards are skipped). A failing
// blocking control errors after an update and warns after a create (the
// severity matrix). Under op change (create or update, unknown which) a
// control that fails under one and passes under the other warns.
// NewState is never altered.
func (l *Lifecycle) applyPost(ctx context.Context, c *Configured, req *hook.Request) (*hook.Result, error) {
	if sc, err := l.scopedToVerdict(c); err == nil { // on error apply_pre blocked this change
		c = sc
	}
	return l.observe(ctx, c, req, StageApplyPost, engine.Op(req.Op))
}

// observe evaluates the effective change controls on req.New after upstream
// acted: apply_post, refresh (read) and import. Configured controls and
// deletion guards are skipped (binding table); a null New has nothing to check.
func (l *Lifecycle) observe(ctx context.Context, c *Configured, req *hook.Request, stage Stage, op engine.Op) (*hook.Result, error) {
	if c == nil || c.Controls == nil {
		return nil, fmt.Errorf("lifecycle: %s before Configure", stageName(stage))
	}
	if req.New == nil {
		return nil, fmt.Errorf("lifecycle: %s request without new state", stageName(stage))
	}
	newState, err := req.New.Get()
	if err != nil {
		return nil, fmt.Errorf("lifecycle: new state: %w", err)
	}
	res, col := &hook.Result{}, &collected{}
	if stage == StageApplyPost {
		col.alt = postShapes(op)
		// The apply_pre baseline match of this RPC, also required to cover
		// NewState: a grandfathered update stays non-blocking only while the
		// applied reads equal the baselined ones.
		col.baseline, _ = req.Carry.(baseline.Instance) //nolint:errcheck // absent: the zero Instance never matches
		col.applied, col.appliedIdentity = &newState, req.Identity
	}
	if newState.IsNull() { // destroyed or gone: nothing to check
		res.Diagnostics = l.record(c, req, stage, op, newState, nil, false, false)
		return res, nil
	}
	// Prior is set only at refresh (the state before the read); apply_post
	// and import carry none, so it binds null there.
	prior, err := get(req.Prior)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: prior state: %w", err)
	}
	null := tftypes.NewValue(tftypes.DynamicPseudoType, nil)
	controls := changeControls(c.Controls, req.TypeName) // never deletion guards
	for i := range controls {
		ctl := &controls[i]
		if ctl.PresenceMode == bundle.PresenceConfigured {
			continue // no Config after upstream acted
		}
		a := &engine.Activation{Resource: newState, Config: null, Prior: prior, Op: op}
		l.check(ctx, c, stage, ctl, a, "", "", col)
	}
	col.diags = append(col.diags, l.record(c, req, stage, op, newState, col.results, false, false)...)
	res.Diagnostics = col.diags
	return res, nil
}

// shapeOp is the op of an apply_pre RPC from its shape alone: a null Planned
// deletes, a null Prior creates, anything else updates. Request.Op is the
// envelope op combined with it (proxy applyOp), so it can read replace or
// change; a control is evaluated under both.
func shapeOp(prior, planned tftypes.Value) engine.Op {
	switch {
	case planned.IsNull():
		return engine.OpDelete
	case prior.IsNull():
		return engine.OpCreate
	}
	return engine.OpUpdate
}

// postShapes are the shape ops an apply_post op can stand for. apply_post
// has no Prior, so the shape comes only from the proxy op: replace reaches it
// only through the create half, and change (the envelope disagreed with the
// RPC) is a create or an update.
func postShapes(op engine.Op) []engine.Op {
	switch op {
	case engine.OpCreate, engine.OpUpdate:
		return nil
	case engine.OpReplace:
		return []engine.Op{engine.OpCreate}
	}
	return []engine.Op{engine.OpCreate, engine.OpUpdate}
}

// proxyBlocked records an apply the proxy refused before the hook:
// one apply_pre record whose result is the block token as a
// synthetic control, from the type and request-shape op only (no value, no
// envelope). The proxy blocks regardless; under evidence.required a failed
// write adds its error diagnostic.
func (l *Lifecycle) proxyBlocked(c *Configured, req *hook.Request) (*hook.Result, error) {
	if req.Blocked != hook.BlockEnvelopeInvalid && req.Blocked != hook.BlockEnvelopeDisagrees {
		return nil, fmt.Errorf("lifecycle: unknown proxy block %q", req.Blocked)
	}
	if sc, err := l.scopedToVerdict(c); err == nil {
		c = sc // record the scope the apply would have run under
	}
	op := engine.Op(req.Op)
	if op == "" {
		op = engine.OpChange
	}
	res := evidence.Result{Control: req.Blocked, Version: gateVersion, State: "fail", Decision: "blocked", Paths: []string{}}
	null := tftypes.NewValue(tftypes.DynamicPseudoType, nil)
	return &hook.Result{Diagnostics: l.record(c, &hook.Request{TypeName: req.TypeName}, StageApplyPre, op, null,
		[]evidence.Result{res}, false, evidenceRequired(c))}, nil
}
