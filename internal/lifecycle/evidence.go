package lifecycle

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/baseline"
	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/internal/evidence"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// openEvidence replaces the process chain after a successful Configure and
// writes the configure record. A failure is a warning (spec: evidence dir on
// a read-only or full disk); only evidence.required blocks, at apply_pre.
func (l *Lifecycle) openEvidence(c *Configured, terraformVersion string) []string {
	l.evMu.Lock()
	defer l.evMu.Unlock()
	if l.ev != nil {
		_ = l.ev.Close() //nolint:errcheck // the old chain ends here; a close error changes nothing
		l.ev = nil
	}
	prov := evidence.Provider{Address: l.opt.ProviderAddress, Version: l.opt.ProviderVersion, UpstreamVersion: l.opt.UpstreamVersion}
	w, err := evidence.Open(evidence.Options{Dir: c.Block.EvidenceDir, Run: evidence.RunFromEnv(os.Getenv), Provider: prov, Now: l.opt.Now})
	if err != nil {
		l.evClass = errClass(err)
		return []string{fmt.Sprintf("evidence: cannot open the evidence chain in %s (%s); records are not written", c.Block.EvidenceDir, l.evClass)}
	}
	l.ev, l.evClass = w, ""
	var warns []string
	for _, ev := range c.Events {
		r := evidence.Record{Kind: evidence.KindConfigure, Provider: &prov, Terraform: &evidence.Terraform{Version: terraformVersion},
			Digests: digests(c, ""), Mode: c.Table.RunMode.String(), Scope: scope(c.Table), Event: ev}
		if ev == "bundle_loaded" {
			r.BundleSources, r.CacheSkipped = c.Sources, &c.Skipped
		}
		if ev != "floor_reset" {
			err = w.Append(r)
		} else {
			// Synced before the unrecorded flag is cleared, so a crash
			// cannot leave the reset unattested.
			err = w.AppendSync(r)
		}
		if err != nil {
			return append(warns, fmt.Sprintf("evidence: configure record not written (%s)", errClass(err)))
		}
		if ev == "floor_reset" && c.reset != nil {
			if err := trust.ClearUnrecordedReset(c.reset.dir, c.reset.org, c.reset.at); err != nil {
				warns = append(warns, fmt.Sprintf("Floor reset recorded, but its unrecorded flag was not cleared (%v); the next Configure records it again.", err))
			}
		}
	}
	return warns
}

// Close ends the evidence chain (io.Closer, called by the proxy at exit).
func (l *Lifecycle) Close() error {
	l.evMu.Lock()
	defer l.evMu.Unlock()
	if l.ev == nil {
		return nil
	}
	err := l.ev.Close()
	l.ev = nil
	return err
}

// record writes the eval record of one stage call. With required (profile
// evidence.required at apply_pre) the record is fsynced and a failure is an
// error diagnostic that blocks the forward; otherwise a failure warns once.
func (l *Lifecycle) record(c *Configured, req *hook.Request, stage Stage, op engine.Op, state tftypes.Value,
	results []evidence.Result, envelopeAbsent, required bool) []hook.Diagnostic {
	return l.recordMatched(c, req, stage, op, state, results, envelopeAbsent, required, nil)
}

// recordMatched is record with the verdict entries the apply's own half
// matched (nil: no lookup ran; empty: it matched nothing).
func (l *Lifecycle) recordMatched(c *Configured, req *hook.Request, stage Stage, op engine.Op, state tftypes.Value,
	results []evidence.Result, envelopeAbsent, required bool, matched []evidence.Match) []hook.Diagnostic {
	r := evidence.Record{Kind: evidence.KindEval, Digests: digests(c, controlVersions(c, stage, req.TypeName)),
		Mode: c.Table.RunMode.String(), Scope: scope(c.Table), Stage: stageName(stage), Results: results,
		Resource: resource(req.TypeName, op, state, req.Identity)}
	if envelopeAbsent {
		r.Envelope = "absent"
	}
	if v := l.loaded.Peek(); v != nil && stage == StageApplyPre && r.Digests != nil {
		d := v.Digest // the verdict the apply was gated by
		r.Digests.Verdict = &d
		r.Matched = matched
	}
	l.evMu.Lock()
	w, class := l.ev, l.evClass
	var err error
	switch {
	case w == nil:
		err = &evidence.WriteError{Class: class, Err: errors.New("no evidence chain")}
	case required:
		err = w.AppendSync(r)
	default:
		err = w.Append(r)
	}
	l.evMu.Unlock()
	switch {
	case err == nil:
		return nil
	case required:
		before := "apply"
		if stage == StageEphemeralOpen {
			before = "opening an ephemeral resource"
		}
		return []hook.Diagnostic{{Severity: hook.SeverityError, Summary: "Evidence required",
			Detail: fmt.Sprintf("evidence write failed: %s; profile requires evidence before %s", errClass(err), before)}}
	case w != nil && l.evWarned.CompareAndSwap(false, true):
		return []hook.Diagnostic{{Severity: hook.SeverityWarning, Summary: "Evidence not written",
			Detail: fmt.Sprintf("evidence write failed: %s; the chain continues with a chain_break record", errClass(err))}}
	}
	return nil // no chain: Configure already warned
}

func errClass(err error) string {
	var we *evidence.WriteError
	if errors.As(err, &we) && we.Class != "" {
		return we.Class
	}
	return evidence.ClassWrite
}

func evidenceRequired(c *Configured) bool {
	return c.Resolution.Profile != nil && c.Resolution.Profile.Evidence.Required
}

// controlVersions is digests.control_versions: the versions digest of the
// control kind the stage evaluates. A new stage that evaluates another kind
// (a data source read) adds its case.
func controlVersions(c *Configured, stage Stage, typeName string) string {
	switch stage {
	case StageEphemeralOpen:
		return c.Controls.VersionsDigestOf(typeName, bundle.KindEphemeral)
	case StageDataSource:
		return c.Controls.VersionsDigestOf(typeName, bundle.KindDataSource)
	default: // managed resource stages: the plan-to-apply stamp
		return c.Controls.VersionsDigest(typeName)
	}
}

func digests(c *Configured, controlVersions string) *evidence.Digests {
	d := &evidence.Digests{Bundles: c.Bundles}
	if s := c.Controls.Digest(); s != "" {
		d.Bundle = &s
	}
	if c.Content != "" { // the content digest: null when the bundle has none
		d.Content = &c.Content
	}
	if p := c.Resolution.Profile; p != nil && p.Digest != "" {
		d.Profile = &p.Digest
	}
	if controlVersions != "" {
		d.ControlVersions = &controlVersions
	}
	d.Exceptions = slices.Concat(c.Sidecar.Digests(), c.Grants.Digests())
	return d
}

var reScope = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,256}$`)

// scope is the evidence scope: profile values are trusted, local ones are
// recorded with source local. Account and region come from the upstream
// provider configuration, which this version does not read (null).
func scope(t profile.ModeTable) *evidence.Scope {
	dim := func(trusted profile.Dim, local string) *evidence.Sourced {
		switch {
		case trusted.Value != "" && reScope.MatchString(trusted.Value):
			return &evidence.Sourced{Value: trusted.Value, Source: trusted.Source}
		case local != "" && reScope.MatchString(local):
			return &evidence.Sourced{Value: local, Source: "local"}
		}
		return nil
	}
	env := ""
	if len(t.LocalEnvironment) == 1 {
		env = t.LocalEnvironment[0]
	}
	return &evidence.Scope{Workspace: dim(t.Workspace, t.LocalWorkspace), Environment: dim(t.Environment, env)}
}

// resource names the evaluated object for the inventory join: id
// is the known cloud id attribute of state (prior for a delete, else the
// evaluated state); identity_kind takes identity when the hook carried a
// usable identity object, else id when the id is known, else none.
func resource(typeName string, op engine.Op, state tftypes.Value, identity map[string]any) *evidence.Resource {
	r := &evidence.Resource{Type: typeName, Op: string(op), IdentityKind: "none"}
	var attrs map[string]tftypes.Value
	if state.IsKnown() && !state.IsNull() && state.As(&attrs) == nil {
		var id string
		if v, ok := attrs["id"]; ok && v.IsKnown() && !v.IsNull() && v.As(&id) == nil && textValue(id) {
			r.ID, r.IdentityKind = &id, "id"
		}
	}
	if m := identityAttrs(identity); m != nil {
		r.Identity, r.IdentityKind = m, "identity"
	}
	return r
}

var (
	reIdentityKey = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	// reIdentityText is a non-empty string the line format carries
	// unescaped (spec 10.1: no escape sequences).
	reIdentityText = regexp.MustCompile("^[^\"\\\\\\x00-\\x1f\\x7f\u2028\u2029\ufffd]+$")
)

// textValue reports s fits the line unescaped and within the writer's
// 2048-byte cap (bytes, as evidence validates). A state id or
// identity value that does not is left out, so the record degrades rather
// than being refused.
func textValue(s string) bool {
	return len(s) <= 2048 && utf8.ValidString(s) && reIdentityText.MatchString(s)
}

// identityAttrs is the identity object as evidence carries it: at most 16
// keys, every value a non-empty string. Anything else (a null, number, bool
// or nested value, an empty object, a value the line cannot carry) is no
// identity, so the record falls back to the id rather than being refused.
// shortcut: string values only; widen when an identity schema has a number.
func identityAttrs(in map[string]any) map[string]string {
	if len(in) == 0 || len(in) > 16 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		s, ok := v.(string)
		if !ok || !reIdentityKey.MatchString(k) || !textValue(s) {
			return nil
		}
		out[k] = s
	}
	return out
}

// result is the evidence of one control outcome: the evaluated state, and a
// decision from the stage, the classified state (fail on a stamp mismatch)
// and the severity the matrix gave. Declared reads are cut at a schema map
// attribute by cc, like UnknownPaths.
func result(ctl *bundle.Control, out engine.Outcome, classified engine.State, stage Stage, sev Severity, half string, cc *celeng.Compiler) evidence.Result {
	r := evidence.Result{Control: ctl.ID, Version: ctl.Version, Half: half, State: out.State.String(),
		Decision: decision(stage, classified, sev), Err: string(out.Err)}
	switch out.State {
	case engine.Unknown:
		r.Paths = evidencePaths(out.UnknownPaths)
	case engine.Fail, engine.NotEvaluable:
		r.Paths = evidencePaths(cc.Paths(ctl))
	}
	return r
}

// readDigest is results[].read_digest of ctl at plan: the baseline read
// digest over the prior state, as baseline entries record it. "" without
// the baseline key, without a prior state (a create), when a read is
// unknown, without the upstream schema of the type, or when ctl is not
// grandfatherable (a schema-sensitive or
// unresolvable read: no keyed hash of a sensitive value is written).
func (c *Configured) readDigest(ctl *bundle.Control, prior tftypes.Value) string {
	if c.readKey == nil || !prior.IsKnown() || prior.IsNull() || c.Schemas == nil {
		return ""
	}
	s, ok := c.Schemas.Resource(ctl.ResourceType)
	if !ok || !baseline.Grandfatherable(ctl, s) { // no upstream schema: sensitivity unknown, no digest
		return ""
	}
	d, _ := baseline.ReadDigest(c.readKey, ctl.Reads, prior) // "" when a read is unknown
	return d
}

func decision(stage Stage, state engine.State, sev Severity) string {
	switch {
	case state == engine.Pass:
		return "logged"
	case sev == SeverityError && (stage == StagePlan || stage == StageApplyPre || stage == StageEphemeralOpen || stage == StageDataSource):
		return "blocked"
	case state == engine.Unknown && (stage == StagePlan || stage == StageDataSource) && sev == SeverityWarning:
		return "pending"
	case state == engine.Unknown && stage == StageApplyPre:
		return "carried"
	case state == engine.Unknown && stage == StageApplyPost:
		return "unverifiable"
	case state == engine.Unknown:
		return "logged"
	case stage == StageApplyPost:
		return "post_apply_violation"
	case stage == StageRead:
		return "drift_violation"
	case sev == SeverityWarning:
		return "warning"
	}
	return "logged" // advisory: recorded only
}

var rePath = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+|\[\*\]|\[[0-9]+\])*$`)

// evidencePaths rewrites dot paths with "*" steps to the schema form
// (a.*.b -> a[*].b) and drops any path the schema would reject.
func evidencePaths(in []string) []string {
	out := []string{}
	for _, p := range in {
		p = strings.ReplaceAll(strings.ReplaceAll(p, ".*", "[*]"), "*", "[*]")
		if rePath.MatchString(p) && !slices.Contains(out, p) && len(out) < 32 {
			out = append(out, p)
		}
	}
	return out
}
