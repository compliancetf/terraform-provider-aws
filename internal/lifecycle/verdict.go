package lifecycle

// Verdict gate.

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/baseline"
	"github.com/compliancetf/terraform-provider-aws/internal/breakglass"
	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/evidence"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict"
)

// KeyForm is the instance key form. The provider picks it from the RPC
// shape, never from the envelope op (H2).
type KeyForm string

const (
	KeyCreate KeyForm = "create" // null Prior: Planned, prior_identity_kind none
	KeyUpdate KeyForm = "update" // Prior and Planned set: Planned plus prior identity
	KeyDelete KeyForm = "delete" // null Planned: prior identity
	KeyRPC    KeyForm = "rpc"    // a gated RPC: method and request bytes
)

// InstanceKey is the unhashed key input recomputed from the request, never
// a key taken from the envelope or a verdict. internal/verdict hashes the mutation
// forms with the instance_key format (internal/verdict) and defines rpc-form matching; every
// field, Form included, compares by exact equality.
type InstanceKey struct {
	Form     KeyForm
	TypeName string        // the request's resource type; empty for rpc
	Planned  tftypes.Value // create and update; the null planned state for delete; zero for rpc
	// PriorIdentity is, for update and delete: kind identity the request's
	// identity, which the proxy puts in the envelope once it equals the
	// envelope's; kind id {"id":<id>} from the decoded prior
	// state; kind none nil.
	PriorIdentity     json.RawMessage
	PriorIdentityKind string // "none" for create
	Method            string // rpc only: full gRPC method
	Request           []byte // rpc only: the raw request message
}

// Equal is the only key match: exact equality of every field, so a
// one-byte difference never matches. PriorIdentity and Request compare as
// byte sequences (no canonicalization; nil and empty are the same empty
// input). Planned compares by tftypes.Value.Equal: type and value, so the
// zero Value (rpc form) never equals a typed null (delete form).
func (k InstanceKey) Equal(o InstanceKey) bool {
	return k.Form == o.Form && k.TypeName == o.TypeName && k.Planned.Equal(o.Planned) &&
		k.PriorIdentityKind == o.PriorIdentityKind && bytes.Equal(k.PriorIdentity, o.PriorIdentity) &&
		k.Method == o.Method && bytes.Equal(k.Request, o.Request)
}

// Verdict returns nil when a verdict entry matches key. apply_pre calls it
// once per ApplyResourceChange with the key of that RPC's own half:
// a destroy RPC the delete key, a create RPC the create key, never both.
type Verdict interface {
	Match(ctx context.Context, key InstanceKey) error
}

// noVerdict is the Verdict of a run without a verdict (verdict = none):
// it matches nothing. A loaded verdict is matched by internal/verdict; a
// test may install another Verdict.
type noVerdict struct{}

var errNoVerdict = errors.New(verdict.TextNoVerdict) //nolint:staticcheck // spec text

func (noVerdict) Match(context.Context, InstanceKey) error { return errNoVerdict }

// loadVerdict loads the verdict at the first ApplyResourceChange of the
// process and returns the same outcome to every later one (verdict.Lazy).
// No other stage calls it, so plan, read, import and Configure never read
// COMPLIANCETF_VERDICT.
func (l *Lifecycle) loadVerdict(c *Configured) (*verdict.Verdict, error) {
	return l.loaded.Load(func() verdict.Input {
		now := time.Now
		if l.opt.Now != nil {
			now = l.opt.Now
		}
		return verdict.Input{Profile: c.Resolution.Profile, Revocations: c.Controls.Revocations(), BundleDigest: c.Controls.Digest(), ContentDigest: c.Content,
			WrapperName: l.opt.WrapperName, WrapperVersion: l.opt.ProviderVersion, UpstreamName: l.opt.UpstreamName, UpstreamVersion: l.opt.UpstreamVersion, Now: now()}
	})
}

const (
	scopeSummary = "Compliance scope cannot be bound to the verdict"
	scopeDetail  = "The mode table could not be rebuilt under the verdict workspace and environment. " +
		"Re-run terraform plan and ctfkit gate, then apply through ctfkit apply."
)

// scopedToVerdict is the apply-time view under a verified verdict (Scope
// binding): the mode table recomputed with the verdict scope, which
// is trusted only on a dimension the signed profile scope fixes (Load
// checked the verdict matches it). The values
// equal the Configure-time ones, so the sidecar and grants stand; the
// trusted scope records source verdict. Without a verdict, when it fails to
// load (the gate blocks) or for a hand-built Configured without a profile
// table input, c is returned. Built once per Configured; an error blocks
// every apply.
func (l *Lifecycle) scopedToVerdict(c *Configured) (*Configured, error) {
	v, err := l.loadVerdict(c)
	if err != nil || v == nil || c.tableIn.Resolution.Profile == nil {
		return c, nil
	}
	l.scopeMu.Lock()
	defer l.scopeMu.Unlock()
	if l.scopeFor != c {
		in := c.tableIn
		in.Verdict = v.Scope()
		t, err := profile.ComputeModeTable(in)
		var sc *Configured
		if err == nil {
			cc := *c
			cc.Table = t
			sc = &cc
		}
		l.scopeFor, l.scopeCfg, l.scopeErr = c, sc, err
	}
	return l.scopeCfg, l.scopeErr
}

// verdictSource is the configured Verdict; nil (a zero Lifecycle) fails
// closed as noVerdict.
func (l *Lifecycle) verdictSource() Verdict {
	if l.verdict == nil {
		return noVerdict{}
	}
	return l.verdict
}

const (
	gateControl = "verdict_required" // the synthetic evidence result of the gate
	gateVersion = "1"
	gateSummary = "Verdict required"
)

// gate is the verdict gate outcome of one apply RPC: block non-nil stops
// the forward (its record is written); otherwise diags and results join the
// apply_pre record, and listed (set under verdict_required) restricts the
// exceptions apply honors to those the verdict lists for the instance.
type gate struct {
	block    []hook.Diagnostic
	diags    []hook.Diagnostic
	results  []evidence.Result
	listed   *listing
	baseline baseline.Instance // the one matched entry; zero never grandfathers
	matched  []evidence.Match  // the entries the lookup matched; nil when none ran
	// prov is the resource-local provisional decision check; nil
	// without a matched verdict entry.
	prov *provisional
}

// applyVerdictGate is the first apply_pre step for every type and op, also
// with zero controls (B4: outside Wants). Under verdict_required every
// mutation needs its entry; without it only a type with graph controls for
// this RPC's half looks one up. The RPC's own half is matched: a
// destroy RPC delete_key and delete_decisions, any other instance_key and
// decisions. A block is emitted directly, never through Classify, so no mode
// downgrades it, and writes the eval record (fsynced under
// evidence.required).
//
// A COMPLIANCETF_VERDICT that fails to load blocks every apply, whether or
// not verdict_required is set: a supplied verdict is never ignored.
func (l *Lifecycle) applyVerdictGate(ctx context.Context, c *Configured, req *hook.Request, op engine.Op, prior, planned, config tftypes.Value) gate {
	del := planned.IsKnown() && planned.IsNull()
	state := planned
	if del {
		state = prior
	}
	v, err := l.loadVerdict(c)
	if err != nil {
		summary, detail := verdict.SummaryInvalid, err.Error()
		var ve *verdict.Error
		if errors.As(err, &ve) {
			summary, detail = ve.Summary, ve.Detail
		}
		return gate{block: l.gateBlock(c, req, op, state, summary, detail, "")}
	}
	required := c.Table.VerdictRequired
	graph := graphControls(c, req.TypeName, del)
	if !required && len(graph) == 0 && v == nil {
		return gate{} // nothing to decide: no graph control, no verdict entry to match
	}
	key, why := instanceKey(req, prior, planned)
	if v == nil && required {
		// verdict = none: noVerdict blocks; only a test installs another Verdict.
		if why == "" {
			if err := l.verdictSource().Match(ctx, key); err != nil {
				why = err.Error()
			}
		}
		if why != "" {
			return gate{block: l.gateBlock(c, req, op, state, gateSummary, why, verdict.SitNoVerdict)}
		}
		return gate{}
	}
	a := verdict.Apply{Verdict: v, Required: required, Type: req.TypeName, Delete: del, Graph: graphRefs(c, graph, op)}
	g := gate{}
	if v != nil {
		if why == "" {
			var kerr error
			a.Matches, kerr = v.Match(query(key))
			if kerr != nil {
				why = "The verdict instance key cannot be computed: " + kerr.Error() + "."
			} else {
				g.matched = matchedEntries(a.Matches, del)
			}
		}
		if required {
			g.listed = &listing{v: v, digests: verdict.Listed(a.Matches)}
		}
		act := &engine.Activation{Resource: state, Config: config, Prior: prior, Op: op, RegionFromResource: del}
		shape := shapeOp(prior, planned)
		if len(a.Matches) == 1 { // several matches never pick one, so none grandfathers
			g.baseline = l.baselineInstance(c, v, a.Matches[0], key, req, prior, planned, act)
		}
		a.Excepted = func(id string) bool { return l.graphExcepted(ctx, c, graph, id, act, shape, g.listed, g.baseline) }
		set, warns := l.breakGlass(c, v)
		for _, w := range warns { // once per process, with the first apply
			g.diags = append(g.diags, hook.Diagnostic{Severity: hook.SeverityWarning, Summary: "Break-glass receipt not honored", Detail: w})
		}
		a.BreakGlass = func(id, result string) (string, bool) { return breakGlassOn(set, a.Matches, del, id, result) }
		if len(a.Matches) > 0 {
			ms := a.Matches
			g.prov = &provisional{matches: ms, del: del, listed: &listing{v: v, digests: verdict.Listed(ms)},
				breakGlass: func(id string) (string, bool) { return breakGlassOn(set, ms, del, id, verdict.ResultProvisional) }}
		}
	}
	rows := verdict.Situation(a)
	blocked := false
	for _, r := range rows {
		d := hook.Diagnostic{Severity: hook.SeverityWarning, Summary: r.Text}
		if r.Control == "" {
			d.Summary, d.Detail = gateSummary, r.Text
			if r.Severity == verdict.SevWarning {
				d.Summary, d.Detail = r.Text, ""
			}
			if r.Result == verdict.SitNoMatch && why != "" {
				d.Detail += " " + why
			}
		}
		if r.Severity == verdict.SevError {
			d.Severity, blocked = hook.SeverityError, true
		}
		if r.Severity != verdict.SevNone {
			g.diags = append(g.diags, d)
		}
		if r.Control == "" && r.Severity == verdict.SevWarning { // not enforced: each graph control undecided
			for _, gr := range a.Graph {
				g.results = append(g.results, evidence.Result{Control: gr.ID, Version: gr.Version, State: "not_evaluable", Decision: "warning",
					Paths: []string{}, Situation: r.Result})
			}
			continue
		}
		g.results = append(g.results, situationResult(r))
	}
	if blocked {
		g.block = append(slices.Clone(g.diags), l.recordMatched(c, req, StageApplyPre, op, state, g.results, false, evidenceRequired(c), g.matched)...)
	}
	return g
}

// breakGlass verifies the verdict's embedded receipts once per process,
// with the verdict (verdict.Lazy); only the first call returns the
// warnings.
func (l *Lifecycle) breakGlass(c *Configured, v *verdict.Verdict) (*breakglass.Set, []string) {
	var warns []string
	l.bgOnce.Do(func() { l.bgSet, warns = breakglass.Verify(c.BreakGlass, v) })
	return l.bgSet, warns
}

// breakGlassOn is the override_id of the first honored receipt (verdict
// order) covering control's result on every match: each match's own action
// key (delete_key on a destroy RPC, else instance_key) and the receipt
// digest listed in each match's break_glass[]. One override serves all
// matches, so no match borrows another's receipt (as for exceptions,
// Listed), and an unlisted receipt never shadows a listed one.
func breakGlassOn(s *breakglass.Set, matches []*verdict.Instance, del bool, control, result string) (string, bool) {
	if len(matches) == 0 {
		return "", false
	}
	for _, o := range s.Honor(control, matches[0].Key(del), result) {
		if !slices.ContainsFunc(matches, func(m *verdict.Instance) bool {
			return !slices.Contains(m.BreakGlass, o.ReceiptDigest) || !slices.Contains(s.Honor(control, m.Key(del), result), o)
		}) {
			return o.ID, true
		}
	}
	return "", false
}

// provisional is what apply needs about the matched entries' resource-local
// provisional decisions: the state machine blocks each one without
// its final proof, with or without verdict_required.
type provisional struct {
	matches []*verdict.Instance
	del     bool
	// listed is what every match lists: the only exceptions that prove a
	// provisional decision, also when verdict_required is off.
	listed *listing
	// breakGlass is the override_id of an honored receipt every match lists
	// for the control.
	breakGlass func(control string) (string, bool)
}

// on reports whether any match records a provisional decision for
// (control, version) in this RPC's half, and the address of the first.
func (p *provisional) on(control, version string) (string, bool) {
	if p == nil {
		return "", false
	}
	for _, m := range p.matches {
		if p.records(m, control, version) {
			return m.Address, true
		}
	}
	return "", false
}

// receipt is the override_id of an honored receipt proving the provisional
// decision of (control, version): every match must record it as provisional,
// so no match borrows another's decision.
func (p *provisional) receipt(control, version string) (string, bool) {
	if p == nil || p.breakGlass == nil || slices.ContainsFunc(p.matches, func(m *verdict.Instance) bool { return !p.records(m, control, version) }) {
		return "", false
	}
	return p.breakGlass(control)
}

func (p *provisional) records(m *verdict.Instance, control, version string) bool {
	ds := m.Decisions
	if p.del {
		ds = m.DeleteDecisions
	}
	return slices.ContainsFunc(ds, func(d verdict.Decision) bool {
		return d.Control == control && d.Version == version && d.Result == verdict.ResultProvisional
	})
}

// matchedEntries is the evidence of the lookup: each matched entry's index
// in the verdict and its key for this half, ascending; empty, never nil,
// when nothing matched.
func matchedEntries(matches []*verdict.Instance, del bool) []evidence.Match {
	out := make([]evidence.Match, 0, len(matches))
	for _, m := range matches {
		out = append(out, evidence.Match{Entry: int64(m.Entry()), InstanceKey: m.Key(del)})
	}
	slices.SortFunc(out, func(a, b evidence.Match) int { return cmp.Compare(a.Entry, b.Entry) })
	return out
}

// graphControls are the loaded graph controls that this RPC's half of typ
// checks, re-derived from the verified bundles: a destroy RPC the deletion
// guards (companion_absent_forbidden) whose companion_type is typ, since a
// guard forbids deleting the companion while its target (resource_type)
// stays; any other RPC the other graph controls whose resource_type is typ.
func graphControls(c *Configured, typ string, del bool) []bundle.Control {
	var out []bundle.Control
	if del {
		for _, g := range c.Controls.All() {
			if g.Kind == bundle.KindGraph && g.Graph != nil && g.Graph.Rule == bundle.GraphCompanionAbsentForbidden && g.Graph.CompanionType == typ {
				out = append(out, g)
			}
		}
		return out
	}
	for _, g := range c.Controls.OfKind(bundle.KindGraph, typ) {
		if g.Graph != nil && g.Graph.Rule != bundle.GraphCompanionAbsentForbidden {
			out = append(out, g)
		}
	}
	return out
}

// graphRefs gives each graph control its mode-mapped fail row (6.1).
func graphRefs(c *Configured, graph []bundle.Control, op engine.Op) []verdict.Graph {
	out := make([]verdict.Graph, len(graph))
	for i, g := range graph {
		mode := c.Table.ControlMode(g.ID, g.Action == bundle.ActionDeny)
		sev := Classify(mode, g.Action, engine.Fail, StageApplyPre, op, false).Severity
		out[i] = verdict.Graph{ID: g.ID, Version: g.Version, Message: g.Message, FailSeverity: string(sev)}
	}
	return out
}

// situationResult is the evidence result of a situation row: the frozen v1
// states carry pass, fail, not_evaluable and unknown (pending); a row that
// has no decision (no_match, collision, missing_decision, no_verdict) is
// not_evaluable, a gate row the synthetic verdict_required result.
func situationResult(r verdict.Row) evidence.Result {
	if r.Control == "" {
		res := gateResult(r.Severity != verdict.SevError)
		res.Situation = r.Result
		return res
	}
	res := evidence.Result{Control: r.Control, Version: r.Version, State: "not_evaluable", Paths: []string{}, BreakGlassID: r.BreakGlassID, Situation: r.Result}
	switch r.Result {
	case verdict.SitPass:
		res.State = "pass"
	case verdict.SitFail, verdict.SitUnproven, verdict.SitExcepted:
		res.State = "fail"
	case verdict.SitPending:
		res.State = "unknown"
	}
	switch {
	case r.Result == verdict.SitExcepted:
		res.Decision = "excepted"
	case r.Result == verdict.SitPending:
		res.Decision = "pending"
	case r.Severity == verdict.SevError:
		res.Decision = "blocked"
	case r.Severity == verdict.SevWarning:
		res.Decision = "warning"
	default:
		res.Decision = "logged"
	}
	return res
}

// query is the verdict lookup of key: kind id's prior is {"id": <id>} as
// built by instanceKey, kind identity the envelope identity object.
func query(k InstanceKey) verdict.Query {
	return verdict.Query{Form: verdict.Form(k.Form), Type: k.TypeName, Planned: k.Planned, PriorKind: k.PriorIdentityKind, Prior: k.PriorIdentity}
}

// graphExcepted reports whether an exception applies to graph control id
// on this activation and, under verdict_required, the verdict lists it for
// every matched entry. It proves a provisional decision and waives a
// no_match or collision row. A break-glass receipt proves one through
// verdict.Apply.BreakGlass, never here.
func (l *Lifecycle) graphExcepted(ctx context.Context, c *Configured, graph []bundle.Control, id string, act *engine.Activation, shape engine.Op, lst *listing, bi baseline.Instance) bool {
	i := slices.IndexFunc(graph, func(g bundle.Control) bool { return g.ID == id })
	if i < 0 {
		return false
	}
	ctl := &graph[i]
	if g := ctl.Graph; g != nil && g.Rule == bundle.GraphCompanionAbsentForbidden {
		// A guard runs on its companion's destroy RPC: the selector reads that
		// instance, so it resolves against the companion's type and schema.
		cp := *ctl
		cp.ResourceType = g.CompanionType
		ctl = &cp
	}
	// A baseline entry proves it only under mode grandfather (Plan-time
	// provisional exemptions), matched to the verified entry.
	if c.Table.ControlMode(id, ctl.Action == bundle.ActionDeny) == profile.Grandfather && grandfathered(c, ctl, bi) {
		return true
	}
	// Under every op the change runs as, as for the change controls: the
	// envelope may steer act.Op to replace, the RPC shape is create, update
	// or delete, so an op-reading selector never widens here.
	d := l.exceptAll(ctx, c, ctl, bound(c, c.Table.Environment, act), []engine.Op{shape})
	d.WriteLog()
	return d.Applied && (lst == nil || lst.allows(d.Exception))
}

// baselineInstance is what the baseline matcher needs about this apply:
// the one matched verdict entry, the request,
// the instance key's identity (request-derived, never the envelope's)
// and the provider binding. An unknown account or region stays empty, so no
// entry's scope equals it (fail closed).
func (l *Lifecycle) baselineInstance(c *Configured, v *verdict.Verdict, in *verdict.Instance, key InstanceKey, req *hook.Request, prior, planned tftypes.Value, act *engine.Activation) baseline.Instance {
	bi := baseline.Instance{OrgID: v.Doc.OrgID, Workspace: v.Doc.Workspace, Address: in.Address, PreviousAddress: in.PreviousAddress,
		Action: in.Action, Refreshed: in.Refreshed, Listed: in.Baselines, Type: req.TypeName, Prior: prior, Planned: planned, Now: l.opt.Now()}
	for _, b := range v.Doc.Baselines {
		bi.Matched = append(bi.Matched, b.Digest)
	}
	if p := bindProvider(c, act); p.AccountKnown && p.RegionKnown {
		bi.AccountID, bi.Region = p.AccountID, p.Region
	}
	bi.IdentityKind, bi.PriorIdentity = key.PriorIdentityKind, key.PriorIdentity
	if c.Schemas != nil {
		bi.Schema, _ = c.Schemas.Resource(req.TypeName)
	}
	return bi
}

// listing is what the verdict lists for the matched instance under
// verdict_required: only these exceptions are honored at apply.
type listing struct {
	v       *verdict.Verdict
	digests map[string]bool
}

// allows reports whether e is listed for the instance with the same source
// and expiry; a self-service exception must also expire before the verdict
// does (provider checks, read literally).
func (s *listing) allows(e *evidence.Exception) bool {
	if e == nil || !s.digests[e.Digest] {
		return false
	}
	ref, ok := s.v.ExceptionRef(e.Digest)
	if !ok || ref.Source != e.Source {
		return false
	}
	want, err1 := time.Parse(time.RFC3339, ref.Expires)
	got, err2 := time.Parse(time.RFC3339, e.Expires)
	vexp, err3 := time.Parse(time.RFC3339, s.v.Doc.ExpiresAt)
	if err1 != nil || err2 != nil || err3 != nil || !want.Equal(got) {
		return false
	}
	return e.Source != "self_service" || got.Before(vexp)
}

// gateBlock is the blocking verdict gate diagnostic plus its eval record;
// situation is the row label, "" for a verdict that failed to load.
func (l *Lifecycle) gateBlock(c *Configured, req *hook.Request, op engine.Op, state tftypes.Value, summary, detail, situation string) []hook.Diagnostic {
	block := hook.Diagnostic{Severity: hook.SeverityError, Summary: summary, Detail: detail}
	res := gateResult(false)
	res.Situation = situation
	return append([]hook.Diagnostic{block}, l.record(c, req, StageApplyPre, op, state,
		[]evidence.Result{res}, false, evidenceRequired(c))...)
}

// instanceKey recomputes the key of this RPC's own half, or says why it
// cannot be computed (the change is then blocked before Match).
func instanceKey(req *hook.Request, prior, planned tftypes.Value) (InstanceKey, string) {
	if !prior.IsKnown() || !planned.IsKnown() {
		return InstanceKey{}, fmt.Sprintf("The apply request for %s carries an unknown state; the verdict instance key cannot be computed.", req.TypeName)
	}
	k := InstanceKey{TypeName: req.TypeName, Planned: planned}
	if prior.IsNull() {
		k.Form, k.PriorIdentityKind = KeyCreate, "none"
		return k, ""
	}
	k.Form = KeyUpdate
	if planned.IsNull() {
		k.Form = KeyDelete
	}
	env := req.Envelope
	if env == nil || env.CTF.PriorIdentityKind == "" {
		return InstanceKey{}, fmt.Sprintf("The plan for %s carried no prior identity, so the verdict instance key cannot be computed. Re-run plan.", req.TypeName)
	}
	k.PriorIdentityKind = env.CTF.PriorIdentityKind
	if k.Form == KeyDelete && env.CTF.Op == hook.OpCreate && k.PriorIdentityKind == "none" {
		// A tainted replace is planned as a create (null prior), so its destroy
		// RPC carries that create envelope. FORMAT.md v1 keys the destroy half
		// of a tainted replace with kind id.
		k.PriorIdentityKind = "id"
	}
	switch k.PriorIdentityKind {
	case "identity":
		k.PriorIdentity = env.CTF.PriorIdentity
	case "id":
		id := topID(prior)
		if id == "" {
			return InstanceKey{}, fmt.Sprintf("The prior state of %s has no id for the verdict instance key (prior_identity_kind id). Re-run plan.", req.TypeName)
		}
		k.PriorIdentity, _ = json.Marshal(map[string]string{"id": id}) //nolint:errcheck // a string map always marshals
	}
	return k, ""
}

// topID is the known top-level string id of v, "" otherwise.
func topID(v tftypes.Value) string {
	var attrs map[string]tftypes.Value
	var id string
	if v.As(&attrs) != nil {
		return ""
	}
	if a, ok := attrs["id"]; ok && a.IsKnown() && !a.IsNull() && a.As(&id) == nil {
		return id
	}
	return ""
}

func gateResult(pass bool) evidence.Result {
	r := evidence.Result{Control: gateControl, Version: gateVersion, State: "fail", Decision: "blocked", Paths: []string{}}
	if pass {
		r.State, r.Decision = "pass", "logged"
	}
	return r
}

const callFunction = "/tfplugin5.Provider/CallFunction"

// stateUpgradeRPCs pass the rpc gate under verdict_required without Match
// (an addition to the RPC allowlist): they only translate
// stored state to the current schema, Terraform calls them on every plan and
// refresh of existing state, and every mutation stays gated at apply.
var stateUpgradeRPCs = map[string]bool{
	"/tfplugin5.Provider/UpgradeResourceState":    true,
	"/tfplugin5.Provider/UpgradeResourceIdentity": true,
}

// reRPCToken is the evidence resource.type of a gated RPC (schema v1
// resource.type, rpc_ prefix); the proxy sets it from its static table.
var reRPCToken = regexp.MustCompile(`^rpc_[a-z0-9_]{1,124}$`)

// rpcGate is StageRPC: a passthrough RPC the proxy gates. Before
// Configure it is refused, except CallFunction, which Terraform calls during
// validate and which only computes a value. Without verdict_required it is a
// no-op, and so is a state upgrade RPC (stateUpgradeRPCs: no Match, no
// record); with it every other RPC needs a matching rpc-form entry, and the
// decision is recorded in stage rpc (fsynced under evidence.required) before
// the proxy forwards or refuses. A refusal before Configure has no
// chain to record in.
func (l *Lifecycle) rpcGate(ctx context.Context, c *Configured, req *hook.Request) (*hook.Result, error) {
	if c == nil || c.Controls == nil {
		if req.Method == callFunction {
			return &hook.Result{}, nil
		}
		return &hook.Result{Diagnostics: []hook.Diagnostic{{Severity: hook.SeverityError, Summary: "Compliance not configured",
			Detail: fmt.Sprintf("%s was called before the provider was configured; under compliance.tf it is refused until configuration loads.", req.Method)}}}, nil
	}
	if !c.Table.VerdictRequired || stateUpgradeRPCs[req.Method] {
		return &hook.Result{}, nil
	}
	rec := *req
	if !reRPCToken.MatchString(rec.TypeName) {
		rec.TypeName = "rpc_unclassified"
	}
	err := l.verdictSource().Match(ctx, InstanceKey{Form: KeyRPC, Method: req.Method, Request: req.RPCRequest})
	var diags []hook.Diagnostic
	if err != nil {
		diags = []hook.Diagnostic{{Severity: hook.SeverityError, Summary: gateSummary, Detail: err.Error()}}
	}
	null := tftypes.NewValue(tftypes.DynamicPseudoType, nil)
	diags = append(diags, l.record(c, &rec, StageRPC, engine.OpChange, null,
		[]evidence.Result{gateResult(err == nil)}, false, evidenceRequired(c))...)
	return &hook.Result{Diagnostics: diags}, nil
}
