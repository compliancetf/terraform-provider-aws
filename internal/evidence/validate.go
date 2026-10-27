package evidence

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Enumerations of the evidence-record-1 format; the JSON Schema mirrors them.
var (
	modes         = []string{"advisory", "soft_fail", "grandfather", "hard_fail"}
	stages        = []string{"plan", "apply_pre", "apply_post", "refresh", "import", "ephemeral_open", "data_source", "rpc"}
	ops           = []string{"create", "update", "replace", "delete", "no-op", "import", "refresh", "change", "open", "read"}
	identityKinds = []string{"identity", "id", "none"}
	states        = []string{"pass", "fail", "unknown", "not_evaluable"}
	decisions     = []string{"blocked", "error", "warning", "logged", "excepted", "pending", "carried", "unverifiable", "post_apply_violation", "drift_violation"}
	errClasses    = []string{"type_error", "limit", "timeout", "no_such_attribute", "unresolved", "scope_untrusted"}
	halves        = []string{"create", "delete"}
	situations    = []string{"pass", "fail", "not_evaluable", "pending", "excepted", "exemption_unproven", "missing_decision", "no_match", "collision", "no_verdict"}
	events        = []string{"bundle_loaded", "bundle_expired_grace", "rollback_rejected", "profile_missing", "exception_unresolved_id", "exception_scope_untrusted", "exception_not_coverable", "exception_stale_binding", "floor_reset", "exception_self_service_scope", "break_glass_dropped"}
	scopeSources  = []string{"verdict", "profile", "provider_config", "local"}
	excSources    = []string{"grant", "self_service"}
	excStatuses   = []string{"applied", "expired", "rejected", "wrong_workspace", "wrong_environment", "stale_binding", "not_coverable"}
	bundleSources = []string{"embedded", "local", "fetched", "cache"}
	skipReasons   = []string{"not_regular", "unreadable", "unverified", "digest_mismatch", "over_limit"}
	reTypeName    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,127}$`)
	reIdentityKey = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	rePath        = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+|\[\*\]|\[[0-9]+\])*$`)
	reControlID   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	reScopeValue  = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,256}$`)
	reDigest      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reTime        = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$`)
	maxPaths      = 32
	maxIdentity   = 16
	maxIDLen      = 2048
	maxCount      = int64(999999999999999) // the schema's cache_skipped.count maximum
)

// kindFields lists, per kind, the fields beyond the header that a record
// must carry and may carry (the schema's oneOf branches), in field order.
var kindFields = map[Kind][]string{
	KindChainStart: {"provider"},
	KindConfigure:  {"digests", "event", "mode", "provider", "scope", "terraform"},
	KindEval:       {"digests", "mode", "resource", "results", "scope", "stage"},
	KindChainBreak: {"last_good"},
	KindChainEnd:   {"last_seq"},
}

func presentFields(r *Record) []string {
	var f []string
	for _, p := range []struct {
		name string
		set  bool
	}{
		{"digests", r.Digests != nil}, {"event", r.Event != ""}, {"last_good", r.LastGood != nil},
		{"last_seq", r.LastSeq != nil}, {"mode", r.Mode != ""}, {"provider", r.Provider != nil},
		{"resource", r.Resource != nil}, {"results", r.Results != nil}, {"scope", r.Scope != nil},
		{"stage", r.Stage != ""}, {"terraform", r.Terraform != nil},
	} {
		if p.set {
			f = append(f, p.name)
		}
	}
	return f
}

type checker struct{ err error }

func (c *checker) fail(field string) {
	if c.err == nil {
		c.err = fmt.Errorf("invalid %s", field)
	}
}

func (c *checker) enum(field, v string, set []string) {
	if !slices.Contains(set, v) {
		c.fail(field)
	}
}

func (c *checker) optEnum(field, v string, set []string) {
	if v != "" {
		c.enum(field, v, set)
	}
}

func (c *checker) match(field, v string, re *regexp.Regexp) {
	if !re.MatchString(v) {
		c.fail(field)
	}
}

func (c *checker) digest(field string, v *string) {
	if v != nil {
		c.match(field, *v, reDigest)
	}
}

// validate checks the kind-specific fields a caller set. The rest of the
// value-free guarantee is the escape ban and size limit in the writer.
func validate(r *Record) error {
	c := &checker{}
	want, ok := kindFields[r.Kind]
	if !ok {
		return errors.New("invalid kind")
	}
	if got := presentFields(r); !slices.Equal(got, want) {
		return fmt.Errorf("kind %s needs exactly the fields %v", r.Kind, want)
	}
	if r.Envelope != "" && (r.Kind != KindEval || r.Envelope != "absent") {
		c.fail("envelope") // optional, eval only
	}
	if r.Matched != nil && (r.Kind != KindEval || r.Stage != "apply_pre" || r.Digests == nil || r.Digests.Verdict == nil) {
		c.fail("matched") // optional, apply_pre under a loaded verdict only
	}
	for i, m := range r.Matched {
		c.match("matched.instance_key", m.InstanceKey, reDigest)
		if m.Entry < 0 || m.Entry > maxCount || (i > 0 && m.Entry <= r.Matched[i-1].Entry) {
			c.fail("matched.entry") // distinct and ascending
		}
	}
	if (r.BundleSources != nil || r.CacheSkipped != nil) && r.Kind != KindConfigure {
		c.fail("bundle_sources or cache_skipped") // optional, configure only
	}
	for _, bs := range r.BundleSources {
		c.match("bundle_sources.digest", bs.Digest, reDigest)
		c.enum("bundle_sources.source", bs.Source, bundleSources)
	}
	if cs := r.CacheSkipped; cs != nil {
		if cs.Count < 0 || cs.Count > maxCount || cs.Reasons == nil || !slices.IsSorted(cs.Reasons) {
			c.fail("cache_skipped")
		}
		for i, s := range cs.Reasons {
			c.enum("cache_skipped.reasons", s, skipReasons)
			if slices.Contains(cs.Reasons[:i], s) {
				c.fail("cache_skipped.reasons") // distinct, as the schema's uniqueItems
			}
		}
	}
	switch r.Kind {
	case KindConfigure:
		c.enum("event", r.Event, events)
	case KindEval:
		c.enum("stage", r.Stage, stages)
		if r.Stage == "rpc" && !strings.HasPrefix(r.Resource.Type, "rpc_") {
			c.fail("resource.type") // a gated RPC records its rpc_ method token
		}
		checkResource(c, r.Resource)
		for i := range r.Results {
			checkResult(c, &r.Results[i])
		}
	}
	if r.Kind == KindConfigure || r.Kind == KindEval {
		c.enum("mode", r.Mode, modes)
		checkDigests(c, r.Digests)
		for _, s := range []*Sourced{r.Scope.AccountID, r.Scope.Environment, r.Scope.Region, r.Scope.Workspace} {
			if s != nil {
				c.enum("scope source", s.Source, scopeSources)
				c.match("scope value", s.Value, reScopeValue)
			}
		}
	}
	return c.err
}

func checkDigests(c *checker, d *Digests) {
	for _, p := range []*string{d.Bundle, d.Content, d.ControlVersions, d.Profile, d.SchemaCompat, d.Verdict} {
		c.digest("digest", p)
	}
	for _, s := range append(slices.Clone(d.Bundles), d.Exceptions...) {
		c.match("digest", s, reDigest)
	}
}

func checkResource(c *checker, res *Resource) {
	c.match("resource.type", res.Type, reTypeName)
	c.enum("resource.op", res.Op, ops)
	c.enum("resource.identity_kind", res.IdentityKind, identityKinds)
	if res.ID != nil && (*res.ID == "" || len(*res.ID) > maxIDLen) {
		c.fail("resource.id")
	}
	if len(res.Identity) > maxIdentity {
		c.fail("resource.identity")
	}
	for k, v := range res.Identity {
		c.match("resource.identity key", k, reIdentityKey)
		if len(v) > maxIDLen {
			c.fail("resource.identity value")
		}
	}
}

func checkResult(c *checker, res *Result) {
	c.match("results.control", res.Control, reControlID)
	c.match("results.version", res.Version, reControlID)
	c.enum("results.state", res.State, states)
	c.enum("results.decision", res.Decision, decisions)
	c.optEnum("results.err", res.Err, errClasses)
	c.optEnum("results.half", res.Half, halves)
	if res.BreakGlassID != "" {
		c.match("results.break_glass_id", res.BreakGlassID, reControlID)
	}
	c.optEnum("results.situation", res.Situation, situations)
	if res.ReadDigest != "" {
		c.match("results.read_digest", res.ReadDigest, reDigest)
	}
	if len(res.Paths) > maxPaths {
		c.fail("results.paths")
	}
	for _, p := range res.Paths {
		c.match("results.paths", p, rePath)
	}
	if e := res.Exception; e != nil {
		c.enum("exception.source", e.Source, excSources)
		c.enum("exception.status", e.Status, excStatuses)
		c.match("exception.id", e.ID, reControlID)
		c.match("exception.digest", e.Digest, reDigest)
		c.match("exception.expires", e.Expires, reTime)
		if e.Workspace != nil {
			c.match("exception.workspace", *e.Workspace, reScopeValue)
		}
	}
}
