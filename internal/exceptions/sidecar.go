package exceptions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/internal/evidence"
	"github.com/compliancetf/terraform-provider-aws/internal/fsutil"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

// The self-service sidecar:
// an unsigned HCL file that counts only for controls the signed profile
// lists under exceptions.self_service, with a trusted workspace and an
// absolute expiry within exceptions.max_lifetime_days.

// maxSidecarBytes and maxSidecarEntries bound the exceptions_file.
const (
	maxSidecarBytes   = 1 << 20
	maxSidecarEntries = 256
)

// scopeRE is the evidence scope value grammar; workspace and environments
// must satisfy it so a recorded entry never invalidates the eval record.
var scopeRE = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,256}$`)

// Evidence exception statuses of a sidecar entry.
const (
	StatusApplied          = "applied"
	StatusExpired          = "expired"
	StatusRejected         = "rejected"
	StatusWrongWorkspace   = "wrong_workspace"
	StatusWrongEnvironment = "wrong_environment"
	StatusNotCoverable     = "not_coverable"
	StatusStaleBinding     = "stale_binding" // grants only
)

// Entry is one sidecar exception block; Match is the CEL selector.
// Unknown attributes and blocks fail the load.
type Entry struct {
	Label        string   `hcl:"label,label"`
	Controls     []string `hcl:"controls"`
	Match        string   `hcl:"match"`
	Workspace    string   `hcl:"workspace"`
	Environments []string `hcl:"environments,optional"`
	Reason       string   `hcl:"reason"`
	Ticket       string   `hcl:"ticket,optional"`
	Expires      string   `hcl:"expires"`
}

// SidecarInput: Table is the run's mode table (trusted scope, profile
// exception policy, SidecarControls), Resolve maps a catalog id or tool_refs
// alias to the loaded control ids (none: unresolved), Coverable the
// effective coverable map (zero: nothing coverable), Now the local run
// clock and Clock the exceptions clock (NewClock; zero: Now).
type SidecarInput struct {
	Table   profile.ModeTable
	Resolve func(ref string) []string
	// ResolveFold resolves forbid_environment_scoped entries case-insensitively
	// (bundle.ControlSet.ResolveFold); nil fails closed: with a non-empty
	// forbid list every environment-scoped entry is rejected.
	ResolveFold func(ref string) []string
	Coverable   Coverability
	Now         time.Time
	Clock       Clock
}

// Notices are the load warnings and configure evidence events (each event
// once).
type Notices struct {
	Warnings, Events []string
}

func (n *Notices) event(e string) {
	if !slices.Contains(n.Events, e) {
		n.Events = append(n.Events, e)
	}
}

// Sidecar is a loaded self-service sidecar; a nil Sidecar applies nothing.
type Sidecar struct {
	clock   Clock             // the plan-time re-check resolves through it
	digests []string          // entry digests, sorted
	rules   map[string][]rule // control id -> entries naming it
	// waivable are the control ids a new entry could waive in this run:
	// add's entry-independent checks pass for them.
	waivable []string
}

type rule struct {
	label, workspace string // workspace "": none recorded
	source, digest   string // evidence source (self_service, grant) and digest
	sel              *celeng.Selector
	expires          time.Time
	status           string // load-time status; expiry is re-checked at honor time
}

// Decision is the sidecar outcome for one failing, unknown or not_evaluable
// control result. Exception is the entry considered (nil: none matched);
// Applied waives the result; Unresolved: an applicable entry's selector was
// unknown at this stage, so the control is enforced now and the entry is
// tried again at the next stage. Log holds the pending and rejected lines
// of applicable entries (labels and error classes only); WriteLog writes
// them.
type Decision struct {
	Exception  *evidence.Exception
	Applied    bool
	Unresolved bool
	Log        []string
}

// WriteLog writes d.Log to the provider log (stderr, TF_LOG).
func (d Decision) WriteLog() {
	for _, l := range d.Log {
		log.Printf("[compliance] %s", l)
	}
}

// LoadSidecar reads path once per run. It returns nil with no error when no
// sidecar is configured or the mode table enables no self-service control
// (ComputeModeTable already warned). A malformed file fails the load.
func LoadSidecar(path string, in SidecarInput) (*Sidecar, Notices, error) {
	if path == "" || len(in.Table.SidecarControls) == 0 {
		return nil, Notices{}, nil
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, Notices{}, fmt.Errorf("exceptions_file: %w", err)
	}
	defer root.Close() //nolint:errcheck // read-only
	src, err := fsutil.ReadFile(root, filepath.Base(path), maxSidecarBytes)
	if err != nil {
		return nil, Notices{}, fmt.Errorf("exceptions_file: %w", err)
	}
	return parseSidecar(src, path, in)
}

func parseSidecar(src []byte, filename string, in SidecarInput) (*Sidecar, Notices, error) {
	f, diags := hclparse.NewParser().ParseHCL(src, filename)
	if diags.HasErrors() {
		return nil, Notices{}, fmt.Errorf("exceptions_file: %s", diags.Error())
	}
	if err := selfServiceScope(f.Body); err != nil {
		return nil, Notices{}, fmt.Errorf("exceptions_file: %w", err)
	}
	if err := literalOnly(f.Body); err != nil {
		return nil, Notices{}, fmt.Errorf("exceptions_file: %w", err)
	}
	var file struct {
		Exceptions []Entry `hcl:"exception,block"`
	}
	if diags := gohcl.DecodeBody(f.Body, nil, &file); diags.HasErrors() {
		return nil, Notices{}, fmt.Errorf("exceptions_file: %s", diags.Error())
	}
	if len(file.Exceptions) > maxSidecarEntries {
		return nil, Notices{}, fmt.Errorf("exceptions_file: more than %d exceptions", maxSidecarEntries)
	}
	s := &Sidecar{clock: in.Clock, rules: map[string][]rule{}}
	var unknown string
	in.Now, unknown = in.Clock.resolve(in.Now)
	var n Notices
	seen := map[string]bool{}
	forbid := newForbidSet(in.Table, in.ResolveFold)
	s.waivable = waivable(in, unknown)
	for _, e := range file.Exceptions {
		if seen[e.Label] {
			return nil, Notices{}, fmt.Errorf("exceptions_file: duplicate exception %q", e.Label)
		}
		seen[e.Label] = true
		exp, sel, err := e.validate()
		if err != nil {
			return nil, Notices{}, fmt.Errorf("exceptions_file: exception %q: %w", e.Label, err)
		}
		d, err := e.digest()
		if err != nil {
			return nil, Notices{}, fmt.Errorf("exceptions_file: exception %q: %w", e.Label, err)
		}
		s.digests = append(s.digests, d)
		s.add(e, d, exp, sel, in, forbid, unknown, &n)
	}
	slices.Sort(s.digests)
	return s, n, nil
}

// ErrSelfServiceScope is the self_service_scope load failure; Configure
// records it as configure event exception_self_service_scope.
var ErrSelfServiceScope = errors.New("self_service_scope")

// scopeTokens name what self_service never covers: baselines,
// quarantine clearing, floor updates and run keys.
var scopeTokens = []string{"baseline", "quarantine", "floor", "runkey"}

// selfServiceScope fails the sidecar when a block type or attribute name at
// any depth, lower-cased with '-' and '_' removed, contains a scope token,
// naming the earliest one in the file. It is diagnostic only: strict
// decoding rejects every other unknown name; labels and values are not names.
func selfServiceScope(body hcl.Body) error {
	sb, ok := body.(*hclsyntax.Body)
	if !ok {
		return errors.New("not native HCL syntax")
	}
	var first *hcl.Range
	var name string
	check := func(n string, r hcl.Range) {
		norm := strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(n))
		if slices.ContainsFunc(scopeTokens, func(t string) bool { return strings.Contains(norm, t) }) &&
			(first == nil || r.Start.Byte < first.Start.Byte) {
			first, name = &r, n
		}
	}
	hclsyntax.VisitAll(sb, func(n hclsyntax.Node) hcl.Diagnostics { //nolint:errcheck // the visitor returns none
		switch x := n.(type) {
		case *hclsyntax.Attribute:
			check(x.Name, x.NameRange)
		case *hclsyntax.Block:
			check(x.Type, x.TypeRange)
		}
		return nil
	})
	if first == nil {
		return nil
	}
	return fmt.Errorf("%w: %s at %s: the self-service sidecar covers exceptions only "+
		"(no baselines, quarantine clearing, floor updates or run keys)", ErrSelfServiceScope, name, first)
}

// literalOnly rejects every expression but string literals and lists of
// them, so decoding evaluates nothing (no comprehensions, interpolation,
// function calls, references, numbers, bools or null).
func literalOnly(body hcl.Body) error {
	sb, ok := body.(*hclsyntax.Body)
	if !ok {
		return errors.New("not native HCL syntax")
	}
	diags := hclsyntax.VisitAll(sb, func(n hclsyntax.Node) hcl.Diagnostics {
		switch x := n.(type) {
		case *hclsyntax.Body, hclsyntax.Attributes, *hclsyntax.Attribute, hclsyntax.Blocks, *hclsyntax.Block,
			*hclsyntax.TemplateExpr, *hclsyntax.TupleConsExpr:
			return nil
		case *hclsyntax.LiteralValueExpr:
			// strings only: a number literal converts to a string of
			// unbounded length (1e100000000) during decode.
			if x.Val.Type() == cty.String && !x.Val.IsNull() {
				return nil
			}
		}
		r := n.Range()
		return hcl.Diagnostics{{Severity: hcl.DiagError, Summary: "only literal strings and lists are allowed", Subject: &r}}
	})
	if diags.HasErrors() {
		return errors.New(diags[0].Error())
	}
	return nil
}

// validate is the entry grammar; expires is an absolute date (YYYY-MM-DD,
// expiring at 00:00 UTC of that day).
func (e *Entry) validate() (time.Time, *celeng.Selector, error) {
	exp, err := time.Parse(time.DateOnly, e.Expires)
	switch {
	case !controlRE.MatchString(e.Label):
		return time.Time{}, nil, errors.New("label")
	case err != nil:
		return time.Time{}, nil, errors.New("expires: want an absolute date YYYY-MM-DD")
	case len(e.Controls) == 0 || len(e.Controls) > 64:
		return time.Time{}, nil, errors.New("controls: want 1 to 64")
	case !scopeRE.MatchString(e.Workspace):
		return time.Time{}, nil, errors.New("workspace")
	case len(e.Reason) == 0 || len(e.Reason) > 1024 || len(e.Ticket) > 256:
		return time.Time{}, nil, errors.New("reason or ticket length")
	case len(e.Environments) > 64:
		return time.Time{}, nil, errors.New("environments: more than 64")
	}
	for i, env := range e.Environments {
		if !scopeRE.MatchString(env) || slices.Contains(e.Environments[:i], env) {
			return time.Time{}, nil, errors.New("environments: bad or duplicate entry")
		}
	}
	for _, c := range e.Controls {
		if !controlRE.MatchString(c) {
			return time.Time{}, nil, errors.New("controls: bad id")
		}
	}
	sel, err := compileSelector(e.Match)
	return exp, sel, err
}

// add resolves the entry's controls and records one rule per self-service
// control with its load-time status. Expired and rejected entries warn. A
// non-empty unknown (the exceptions clock is unknown) rejects the entry.
func (s *Sidecar) add(e Entry, digest string, exp time.Time, sel *celeng.Selector, in SidecarInput, forbid forbidSet, unknown string, n *Notices) {
	t := in.Table
	base, why := StatusApplied, ""
	scopeErr := t.CheckScope(nil, e.Environments, true) // every sidecar entry is workspace-scoped
	switch {
	case scopeErr != nil:
		base, why = StatusRejected, scopeErr.Error()
		n.event(CodeScopeUntrusted)
	case e.Workspace != t.Workspace.Value:
		base = StatusWrongWorkspace
	case len(e.Environments) > 0 && !slices.Contains(e.Environments, t.Environment.Value):
		base = StatusWrongEnvironment
	case unknown != "":
		base, why = StatusRejected, unknown
	case !in.Now.Before(exp):
		base, why = StatusExpired, "expired at "+exp.Format(time.RFC3339)
	case t.Exceptions == nil || t.Exceptions.MaxLifetimeDays <= 0:
		base, why = StatusRejected, "the org profile sets no max_lifetime_days"
	case exp.After(in.Now.AddDate(0, 0, int(t.Exceptions.MaxLifetimeDays))):
		base, why = StatusRejected, "expires beyond max_lifetime_days "+strconv.FormatInt(t.Exceptions.MaxLifetimeDays, 10)
	}
	var ids []string
	for _, ref := range e.Controls {
		got := in.Resolve(ref)
		if len(got) == 0 {
			n.Warnings = append(n.Warnings, fmt.Sprintf("exception %s: %s is not a known control id or alias; ignored", e.Label, ref))
			n.event("exception_unresolved_id")
		}
		for _, id := range got {
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
	}
	for _, id := range ids {
		if !slices.Contains(t.SidecarControls, id) {
			n.Warnings = append(n.Warnings, fmt.Sprintf("exception %s: %s is not self-service in the org profile; ignored", e.Label, id))
			continue
		}
		status, w := base, why
		if status == StatusApplied && !in.Coverable.Coverable(id, string(bundle.CoverSelfService)) {
			status = StatusNotCoverable
			n.Warnings = append(n.Warnings, fmt.Sprintf("exception %s: %s is not exemption-coverable for self_service; enforced", e.Label, id))
			n.event("exception_not_coverable")
		}
		if status == StatusApplied && len(e.Environments) > 0 && forbid.has(id) {
			status, w = StatusRejected, "control may not be excepted per environment"
		}
		if w != "" {
			n.Warnings = append(n.Warnings, fmt.Sprintf("exception %s: %s; %s enforced", e.Label, w, id))
		}
		s.rules[id] = append(s.rules[id], rule{label: e.Label, workspace: e.Workspace, source: "self_service", digest: digest,
			sel: sel, expires: exp, status: status})
	}
}

// waivable are the self-service ids add could apply an entry to: a known
// clock, a trusted workspace, a profile max_lifetime_days and a
// self_service-coverable id. Keep in step with add.
func waivable(in SidecarInput, unknown string) []string {
	t := in.Table
	if unknown != "" || t.CheckScope(nil, nil, true) != nil || t.Exceptions == nil || t.Exceptions.MaxLifetimeDays <= 0 {
		return nil
	}
	var ids []string
	for _, id := range t.SidecarControls {
		if in.Coverable.Coverable(id, string(bundle.CoverSelfService)) {
			ids = append(ids, id)
		}
	}
	return ids
}

// Waivable reports whether an entry in this sidecar can waive control id
// (false for a nil Sidecar). Diagnostics offer the waive hint only then.
func (s *Sidecar) Waivable(id string) bool {
	return s != nil && slices.Contains(s.waivable, id)
}

// Digests are the entry digests of every exception in the file, sorted
// (nil for a nil Sidecar).
func (s *Sidecar) Digests() []string {
	if s == nil {
		return nil
	}
	return slices.Clone(s.digests)
}

// canonical is the RFC 8785 form of the entry's digest input (B8): label,
// workspace, controls as written (sorted, duplicates kept), selector (the
// match string), environments (sorted, absent is []) and the literal
// expires date; reason and ticket are not part of it. A string that is not
// valid UTF-8 fails rather than collide after encoding/json replaces it.
func (e *Entry) canonical() ([]byte, error) {
	sorted := func(l []string) []string { out := append([]string{}, l...); slices.Sort(out); return out }
	controls, envs := sorted(e.Controls), sorted(e.Environments)
	for _, v := range slices.Concat([]string{e.Label, e.Workspace, e.Match, e.Expires}, controls, envs) {
		if !utf8.ValidString(v) {
			return nil, errors.New("entry holds invalid UTF-8")
		}
	}
	raw, err := json.Marshal(map[string]any{"label": e.Label, "workspace": e.Workspace, "controls": controls,
		"selector": e.Match, "environments": envs, "expires": e.Expires})
	if err != nil {
		return nil, err
	}
	return bundle.CanonicalJSON(raw)
}

// digest is the entry digest a verdict lists: sha256 of canonical.
func (e *Entry) digest() (string, error) {
	c, err := e.canonical()
	if err != nil {
		return "", err
	}
	return digest(c), nil
}

// Lookup decides the sidecar for control ctl on activation a, the input
// the control used at this stage (trusted env and provider bound), under
// the control's per-resource deadline on ctx. An applicable entry whose
// selector is true applies; otherwise the first matching non-applicable
// entry is reported (control enforced). Expiry is re-checked against now,
// through the exceptions clock: under airgap now is ignored, unknown
// applies nothing.
func (s *Sidecar) Lookup(ctx context.Context, ctl *bundle.Control, schemas celeng.SchemaSource, a *engine.Activation, now time.Time) Decision {
	if s == nil {
		return Decision{}
	}
	return lookup(ctx, s.rules[ctl.ID], s.clock, ctl, schemas, a, now)
}

// lookup is Lookup over one control's rules (sidecar entries or grants).
// Only a true selector applies.
// Rules that can apply are evaluated first, so rules that cannot (expired,
// rejected, not coverable, stale, wrong scope) never spend the shared
// per-resource deadline before them: an unknown applicable selector leaves
// the control pending for the next stage, an error records the entry
// rejected with its class. Only when none applies and nothing is recorded
// yet are the other rules evaluated, up to the first true one, for the
// evidence record.
func lookup(ctx context.Context, rules []rule, clock Clock, ctl *bundle.Control, schemas celeng.SchemaSource, a *engine.Activation, now time.Time) Decision {
	var d Decision
	now, unknown := clock.resolve(now)
	status := func(r rule) string {
		switch {
		case r.status == StatusApplied && unknown != "":
			return StatusRejected
		case r.status == StatusApplied && !now.Before(r.expires):
			return StatusExpired
		}
		return r.status
	}
	for _, r := range rules {
		if status(r) != StatusApplied {
			continue
		}
		out := r.sel.Eval(ctx, schemas, ctl.Kind, ctl.ResourceType, a)
		switch out.State {
		case engine.Pass:
			// Applied waives now: earlier pending lines no longer hold;
			// rejected lines stay.
			d.Exception, d.Applied, d.Unresolved, d.Log = r.evidence(StatusApplied), true, false, dropPending(d.Log)
			return d
		case engine.Unknown:
			d.Unresolved = true
			d.Log = append(d.Log, fmt.Sprintf("exception %s%s", r.label, pendingSuffix))
		case engine.NotEvaluable:
			d.Log = append(d.Log, fmt.Sprintf("exception %s: exception_rejected: selector %s", r.label, out.Err))
			if d.Exception == nil {
				d.Exception = r.evidence(StatusRejected)
			}
		}
	}
	for _, r := range rules {
		if st := status(r); st != StatusApplied && d.Exception == nil &&
			r.sel.Eval(ctx, schemas, ctl.Kind, ctl.ResourceType, a).State == engine.Pass {
			d.Exception = r.evidence(st)
		}
	}
	return d
}

const pendingSuffix = " pending: selector unknown"

// dropPending is log without its pending lines.
func dropPending(log []string) []string {
	return slices.DeleteFunc(slices.Clone(log), func(l string) bool { return strings.HasSuffix(l, pendingSuffix) })
}

// Combine merges the grants decision g with the sidecar decision s, looked
// up when g did not apply. An applied decision wins; otherwise the first
// exception considered (the grant's) is recorded, the control is pending
// when either is, and both log trails are kept.
func Combine(g, s Decision) Decision {
	if g.Applied {
		return g
	}
	if s.Applied {
		s.Log = append(dropPending(g.Log), s.Log...)
		return s
	}
	out := Decision{Exception: g.Exception, Unresolved: g.Unresolved || s.Unresolved, Log: append(slices.Clone(g.Log), s.Log...)}
	if out.Exception == nil {
		out.Exception = s.Exception
	}
	return out
}

func (r rule) evidence(status string) *evidence.Exception {
	e := &evidence.Exception{Digest: r.digest, Expires: r.expires.UTC().Format(time.RFC3339), ID: r.label,
		Source: r.source, Status: status}
	if r.workspace != "" {
		ws := r.workspace
		e.Workspace = &ws
	}
	return e
}
