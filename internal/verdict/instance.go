package verdict

// Verdict instances and the apply lookup: the verdict document, the
// instance key and the provider checks.

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Instance is one verdict entry. Optional members are the omitempty ones
// and delete_decisions (omitzero: present exactly on delete and replace);
// every other member is required (arrays may be empty).
type Instance struct {
	Address           string         `json:"address"`
	Deposed           string         `json:"deposed,omitempty"`
	Type              string         `json:"type"`
	Action            string         `json:"action"`
	PreviousAddress   string         `json:"previous_address,omitempty"`
	InstanceKey       string         `json:"instance_key,omitempty"`
	DeleteKey         string         `json:"delete_key,omitempty"`
	PriorIdentityKind string         `json:"prior_identity_kind"`
	Refreshed         string         `json:"refreshed"`
	UnknownPaths      [][]string     `json:"unknown_paths"`
	Decisions         []Decision     `json:"decisions"`
	DeleteDecisions   []Decision     `json:"delete_decisions,omitzero"`
	NotEvaluable      []NotEvaluable `json:"not_evaluable"`
	Exceptions        []string       `json:"exceptions"`
	Baselines         []string       `json:"baselines"`
	BreakGlass        []string       `json:"break_glass"`

	entry int // index in instances[], set by buildIndex
}

// Key is the entry's key for one RPC half: delete_key on a destroy RPC,
// else instance_key.
func (in *Instance) Key(del bool) string {
	if del {
		return in.DeleteKey
	}
	return in.InstanceKey
}

// Entry is the index of in in the verdict's instances[], set by
// buildIndex at load (every entry Match returns is indexed).
func (in *Instance) Entry() int { return in.entry }

// Decision is a gate decision for one (control, version).
type Decision struct {
	Control string `json:"control"`
	Version string `json:"version"`
	Result  string `json:"result"`
	Action  string `json:"action"`
}

// NotEvaluable names why a control was not decidable at plan.
type NotEvaluable struct {
	Control string `json:"control"`
	Reason  string `json:"reason"`
}

// ExceptionRef is a top-level exceptions[] member.
type ExceptionRef struct {
	Digest  string `json:"digest"`
	Source  string `json:"source"`
	Expires string `json:"expires"`
}

// Decision results (the decision state machine).
const (
	ResultPass         = "pass"
	ResultFail         = "fail"
	ResultNotEvaluable = "not_evaluable"
	ResultProvisional  = "provisional"
	ResultPending      = "pending"
)

var (
	reKey   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	actions = []string{"create", "update", "replace", "delete", "no-op", "import", "move", "forget"}
	results = []string{ResultPass, ResultFail, ResultNotEvaluable, ResultProvisional, ResultPending}
	reasons = []string{"sensitive_input", "ambiguous_reference", "unknown_reference", "unknown_value", "identity_alias",
		"identity_conflict", "wildcard", "catalog_miss", "limit", "state_action"}
)

// validate checks the members the type system cannot (load-time, whole
// verdict): enums, key formats, which keys each action
// carries, delete-scoped deposed entries, unique decisions and listed
// exemption digests.
func (d *Document) validate() error {
	listed := map[string]bool{}
	for _, e := range d.Exceptions {
		if !reKey.MatchString(e.Digest) || e.Source != "grant" && e.Source != "self_service" || listed[e.Digest] {
			return errors.New("exceptions[] holds a malformed or duplicate entry")
		}
		if _, err := parseUTC(e.Expires); err != nil {
			return errors.New("exceptions[] expires must be an RFC 3339 UTC time")
		}
		listed[e.Digest] = true
	}
	for i := range d.Instances {
		if err := d.Instances[i].validate(listed); err != nil {
			return fmt.Errorf("instances[%d]: %w", i, err)
		}
	}
	return nil
}

func (in *Instance) validate(listed map[string]bool) error {
	kinds := []string{KindIdentity, KindID} // the prior kinds of an update or a delete
	switch {
	case in.Address == "" || in.Type == "":
		return errors.New("address and type are required")
	case !slices.Contains(actions, in.Action):
		return errors.New("unknown action")
	case in.Refreshed != "true" && in.Refreshed != "false":
		return errors.New(`refreshed must be "true" or "false"`)
	case in.Deposed != "" && in.Action != "delete":
		return errors.New("a deposed object takes only a delete entry")
	}
	var wantInstance, wantDelete bool
	switch in.Action {
	case "create":
		wantInstance, kinds = true, []string{KindNone}
	case "update":
		wantInstance = true
	case "delete":
		wantDelete = true
	case "replace":
		wantInstance, wantDelete = true, true
	default: // no-op, import, move, forget: no mutation key (FORMAT.md v1)
		kinds = []string{KindIdentity, KindID, KindNone}
	}
	switch {
	case !slices.Contains(kinds, in.PriorIdentityKind):
		return errors.New("prior_identity_kind does not fit the action")
	case wantInstance != (in.InstanceKey != "") || wantDelete != (in.DeleteKey != ""):
		return errors.New("instance_key and delete_key do not fit the action")
	case in.InstanceKey != "" && !reKey.MatchString(in.InstanceKey), in.DeleteKey != "" && !reKey.MatchString(in.DeleteKey):
		return errors.New("malformed key")
	case wantDelete != (in.DeleteDecisions != nil):
		return errors.New("delete_decisions is present exactly on delete and replace")
	case in.Action == "delete" && len(in.Decisions) != 0:
		return errors.New("a delete entry decides only delete_decisions")
	case in.Action == "delete" && len(in.UnknownPaths) != 0:
		return errors.New("a delete entry has no unknown paths")
	}
	for _, p := range in.UnknownPaths {
		if len(p) == 0 { // an empty step may be a map key; checkPath reads every step against the schema
			return errors.New("malformed unknown path")
		}
	}
	for _, ds := range [][]Decision{in.Decisions, in.DeleteDecisions} {
		seen := map[[2]string]bool{}
		for _, dc := range ds {
			k := [2]string{dc.Control, dc.Version}
			if dc.Control == "" || dc.Version == "" || seen[k] || !slices.Contains(results, dc.Result) || dc.Action != "deny" && dc.Action != "warn" {
				return errors.New("malformed or duplicate decision")
			}
			seen[k] = true
		}
	}
	for _, ne := range in.NotEvaluable {
		if ne.Control == "" || !slices.Contains(reasons, ne.Reason) {
			return errors.New("malformed not_evaluable entry")
		}
	}
	for _, ds := range [][]string{in.Exceptions, in.Baselines, in.BreakGlass} {
		for _, dg := range ds {
			if !reKey.MatchString(dg) {
				return errors.New("malformed exemption digest")
			}
		}
	}
	for _, dg := range in.Exceptions {
		if !listed[dg] {
			return errors.New("an instance exception is not in the top-level exceptions[]")
		}
	}
	return nil
}

// Query is one apply RPC's own half: Form from the RPC shape,
// Planned the apply PlannedState (create and update), Prior the prior
// identity JSON object (update and delete) of kind PriorKind.
type Query struct {
	Form      Form
	Type      string
	Planned   tftypes.Value
	PriorKind string
	Prior     json.RawMessage
}

// Match returns every entry whose key for q's half equals the key the
// provider recomputes (exact equality, never a key taken from the request).
// A create RPC matches instance_key of create and replace entries, an update
// RPC instance_key of update entries, a destroy RPC delete_key of delete and
// replace entries; the entry's prior_identity_kind must equal the derived
// kind (none for the create half). err says why no key could be computed
// when nothing matched.
func (v *Verdict) Match(q Query) ([]*Instance, error) {
	kind := q.PriorKind
	if q.Form == FormCreate {
		kind = "" // the create half is kind none whatever the entry's (replace) prior kind
	}
	var firstErr error
	var out []*Instance
	for _, g := range v.idx[slot{q.Type, q.Form, kind}] {
		key, err := Key(v.leaf, q.Type, q.Form, q.Planned, g.paths, q.Prior)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		out = append(out, g.byKey[key]...)
	}
	if len(out) > 0 {
		firstErr = nil
	}
	return out, firstErr
}

// slot selects the entries one RPC half can match: type, form and (update
// and delete) the entry's prior kind.
type slot struct {
	typ  string
	form Form
	kind string
}

// group is the entries of a slot sharing one unknown_paths mask: one key
// computation per group.
type group struct {
	mask  string // JSON of paths
	paths [][]string
	byKey map[string][]*Instance
}

// index is built once at load for the provider lookup at apply.
type index map[slot][]*group

func buildIndex(instances []Instance) index {
	idx := index{}
	add := func(s slot, paths [][]string, key string, in *Instance) {
		mask, _ := json.Marshal(paths) //nolint:errcheck // [][]string always marshals
		for _, g := range idx[s] {
			if g.mask == string(mask) {
				g.byKey[key] = append(g.byKey[key], in)
				return
			}
		}
		idx[s] = append(idx[s], &group{mask: string(mask), paths: paths, byKey: map[string][]*Instance{key: {in}}})
	}
	for i := range instances {
		in := &instances[i]
		in.entry = i
		switch in.Action {
		case "create", "replace":
			add(slot{in.Type, FormCreate, ""}, in.UnknownPaths, in.InstanceKey, in)
		case "update":
			add(slot{in.Type, FormUpdate, in.PriorIdentityKind}, in.UnknownPaths, in.InstanceKey, in)
		}
		if in.Action == "delete" || in.Action == "replace" {
			add(slot{in.Type, FormDelete, in.PriorIdentityKind}, nil, in.DeleteKey, in)
		}
	}
	return idx
}
