package bundlegen

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

// LockFile is the content lock the generator writes next to the bundles; it
// is committed in the content repo and read back with --lock on the next run.
const LockFile = "content-lock.json"

// Lock is content-lock.json: per ControlKey ("<id>/<kind>/<type>")
// the version a control ships with and the digests of what decides its
// result. The lock owns every generated control's version; a version once
// written is never reused for different digests, so entries of controls no
// longer generated are kept.
type Lock map[string]LockEntry

// LockEntry digests: expr_digest is bundle.DigestRaw of the CEL source
// (for a graph control, which has no expr, bundle.DigestJSON of its graph
// object: rule, companion_type, link_attr, target_attrs in order and
// companion_expr), reads_digest bundle.DigestJSON of the sorted reads, semantics_digest
// bundle.DigestJSON of {action, on (sorted), presence_mode}, the fields
// outside expr and reads that can turn a pass into a fail.
type LockEntry struct {
	ExprDigest      string `json:"expr_digest"`
	ReadsDigest     string `json:"reads_digest"`
	SemanticsDigest string `json:"semantics_digest"`
	Version         string `json:"version"`
}

// Bump is one version_bump declaration. From is the locked version it
// applies to, so a bump left in bumps.yaml after the new lock is committed
// no longer matches and is ignored.
type Bump struct {
	Level string `yaml:"level"`
	From  string `yaml:"from"`
}

// Bumps are the version_bump declarations by ControlKey string, from
// bumps.yaml and the authored files' version_bump (MergeBumps).
type Bumps map[string]Bump

// MergeBumps returns bumps plus each authored file's version_bump
// (authored, by catalog id) under the ControlKey of every target of that id in
// controls. A key both name must carry the identical bump, else
// E_BUMP_CONFLICT: two sources for one version fail closed. An authored
// bump for an id without authored controls is E_INPUT.
func MergeBumps(bumps Bumps, authored map[string]Bump, controls map[string][]bundle.Control) (Bumps, error) {
	out := maps.Clone(bumps)
	if out == nil {
		out = Bumps{}
	}
	for _, id := range slices.Sorted(maps.Keys(authored)) {
		if len(controls[id]) == 0 {
			return nil, errf("E_INPUT", "%s: version_bump without authored controls", id)
		}
		b := authored[id]
		for i := range controls[id] {
			k := keyOf(&controls[id][i]).String()
			if have, ok := out[k]; ok && have != b {
				return nil, errf("E_BUMP_CONFLICT", "%s: bumps.yaml %s and %s.yaml version_bump %s differ",
					safeKey(k), safeBump(have), safeName(id), safeBump(b))
			}
			out[k] = b
		}
	}
	return out, nil
}

// ControlKey is the lock key of a control: one catalog id may target several
// types.
type ControlKey struct{ ID, Kind, Type string }

func (k ControlKey) String() string { return k.ID + "/" + k.Kind + "/" + k.Type }

func keyOf(c *bundle.Control) ControlKey {
	return ControlKey{c.ID, string(c.Kind), c.ResourceType}
}

var digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func validKey(k string) bool {
	parts := strings.Split(k, "/")
	return len(parts) == 3 && !slices.Contains(parts, "")
}

// lockMembers are the exact member names of a lock entry. encoding/json
// matches names case-insensitively, so they are checked before decoding.
var lockMembers = []string{"expr_digest", "reads_digest", "semantics_digest", "version"}

// ParseLock decodes content-lock.json strictly: input that is not I-JSON
// (duplicate member names, trailing data), an entry whose member names are
// not exactly lockMembers, malformed keys, versions and digests fail E_LOCK.
func ParseLock(data []byte) (Lock, error) {
	if _, err := bundle.DigestJSON(data); err != nil {
		return nil, errf("E_LOCK", "%s: %v (duplicate member, trailing data or invalid JSON)", LockFile, err)
	}
	var raw map[string]map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, errf("E_LOCK", "%s: %v", LockFile, err)
	}
	for _, k := range slices.Sorted(maps.Keys(raw)) {
		if names := slices.Sorted(maps.Keys(raw[k])); !slices.Equal(names, lockMembers) {
			return nil, errf("E_LOCK", "%s: %s: members %q, want exactly %q", LockFile, k, names, lockMembers)
		}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var l Lock
	if err := dec.Decode(&l); err != nil {
		return nil, errf("E_LOCK", "%s: %v", LockFile, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errf("E_LOCK", "%s: trailing data", LockFile)
	}
	if l == nil {
		return nil, errf("E_LOCK", "%s: want an object", LockFile)
	}
	for _, k := range slices.Sorted(maps.Keys(l)) {
		e := l[k]
		switch {
		case !validKey(k):
			return nil, errf("E_LOCK", "%s: key %q: want <id>/<kind>/<type>", LockFile, k)
		case !pinRe.MatchString(e.Version):
			return nil, errf("E_LOCK", "%s: %s: version %q: want MAJOR.MINOR.PATCH", LockFile, k, e.Version)
		case !digestRe.MatchString(e.ExprDigest) || !digestRe.MatchString(e.ReadsDigest) || !digestRe.MatchString(e.SemanticsDigest):
			return nil, errf("E_LOCK", "%s: %s: every digest must be sha256:<64 hex>", LockFile, k)
		}
	}
	return l, nil
}

// LoadLock reads and parses a content-lock.json. A missing file is an
// error: a fresh lock is an explicit "{}" file, never an absent one.
func LoadLock(path string) (Lock, error) {
	data, err := readRegular(path)
	if err != nil {
		return nil, err
	}
	return ParseLock(data)
}

// ParseBumps decodes bumps.yaml: a map of ControlKey to {level, from}.
// Unknown fields, duplicate keys, an unknown level or a from that is not
// MAJOR.MINOR.PATCH fail E_BUMP.
func ParseBumps(data []byte) (Bumps, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	b := Bumps{}
	if err := dec.Decode(&b); err != nil && !errors.Is(err, io.EOF) {
		return nil, errf("E_BUMP", "bumps: %v", err)
	}
	if err := dec.Decode(new(yaml.Node)); !errors.Is(err, io.EOF) {
		return nil, errf("E_BUMP", "bumps: one YAML document only")
	}
	for _, k := range slices.Sorted(maps.Keys(b)) {
		switch {
		case !validKey(k):
			return nil, errf("E_BUMP", "bumps: key %q: want <id>/<kind>/<type>", k)
		case !validLevel(b[k].Level):
			return nil, errf("E_BUMP", "bumps: %s: level %q: want major, minor or patch", k, b[k].Level)
		case !pinRe.MatchString(b[k].From):
			return nil, errf("E_BUMP", "bumps: %s: from %q: want the locked MAJOR.MINOR.PATCH", k, b[k].From)
		}
	}
	return b, nil
}

// safeKey and safeBump keep messages value-free: each key segment goes
// through safeName and a from that is not MAJOR.MINOR.PATCH is replaced.
func safeKey(k string) string {
	parts := strings.Split(k, "/")
	for i := range parts {
		parts[i] = safeName(parts[i])
	}
	return strings.Join(parts, "/")
}

func safeBump(b Bump) string {
	from := b.From
	if !pinRe.MatchString(from) {
		from = "<non-version>"
	}
	return "{" + safeName(b.Level) + ", from " + from + "}"
}

func validLevel(l string) bool { return l == "major" || l == "minor" || l == "patch" }

// LoadBumps reads and parses a bumps.yaml.
func LoadBumps(path string) (Bumps, error) {
	data, err := readRegular(path)
	if err != nil {
		return nil, err
	}
	return ParseBumps(data)
}

// lockEntry digests c; the version is left to ApplyLock.
func lockEntry(c *bundle.Control) (LockEntry, error) {
	expr := ""
	if c.Expr != nil {
		expr = *c.Expr
	}
	reads := slices.Sorted(slices.Values(append([]string{}, c.Reads...)))
	on := slices.Sorted(slices.Values(append([]bundle.On{}, c.On...)))
	rj, err := json.Marshal(slices.Compact(reads))
	if err != nil {
		return LockEntry{}, errf("E_LOCK", "%v", err)
	}
	sj, err := json.Marshal(struct {
		Action       bundle.Action       `json:"action"`
		On           []bundle.On         `json:"on"`
		PresenceMode bundle.PresenceMode `json:"presence_mode"`
	}{c.Action, on, c.PresenceMode})
	if err != nil {
		return LockEntry{}, errf("E_LOCK", "%v", err)
	}
	e := LockEntry{ExprDigest: bundle.DigestRaw([]byte(expr))}
	if c.Graph != nil {
		// The graph object is a graph control's rule, so it takes the expr
		// slot and the lock member set stays as is.
		gj, err := json.Marshal(c.Graph)
		if err != nil {
			return LockEntry{}, errf("E_LOCK", "%v", err)
		}
		if e.ExprDigest, err = bundle.DigestJSON(gj); err != nil {
			return LockEntry{}, errf("E_LOCK", "%v", err)
		}
	}
	if e.ReadsDigest, err = bundle.DigestJSON(rj); err != nil {
		return LockEntry{}, errf("E_LOCK", "%v", err)
	}
	if e.SemanticsDigest, err = bundle.DigestJSON(sj); err != nil {
		return LockEntry{}, errf("E_LOCK", "%v", err)
	}
	return e, nil
}

// ApplyLock sets every control's version from the previous lock prev and
// the bumps, and returns the controls with the new lock (prev's entries
// for controls not generated now are kept). Per ControlKey:
//   - not in prev: 1.0.0;
//   - a bump whose from equals the locked version: that bump (patch only
//     when no digest changed: patch is for message, fix and refs);
//   - otherwise unchanged digests keep the version and a changed digest
//     fails E_VERSION_BUMP_MISSING.
//
// Whether a bump is major (can turn a pass into a fail) or minor (only
// relaxes) is the author's declaration; it is not decidable here.
func ApplyLock(prev Lock, bumps Bumps, cs []bundle.Control) ([]bundle.Control, Lock, error) {
	next := maps.Clone(prev)
	if next == nil {
		next = Lock{}
	}
	out := slices.Clone(cs)
	seen := map[string]bool{}
	for _, i := range sortedByKey(out) {
		k := keyOf(&out[i]).String()
		if seen[k] {
			return nil, nil, errf("E_LOCK", "%s: generated twice", k)
		}
		seen[k] = true
		e, err := lockEntry(&out[i])
		if err != nil {
			return nil, nil, err
		}
		old, ok := prev[k]
		b, bumped := bumps[k]
		switch {
		case !ok:
			e.Version = "1.0.0"
		case bumped && b.From == old.Version:
			// Bumps built in code skip ParseBumps: check the level here too.
			if !validLevel(b.Level) {
				return nil, nil, errf("E_BUMP", "%s: level %q: want major, minor or patch", k, b.Level)
			}
			if changed := changedParts(old, e); b.Level == "patch" && changed != "" {
				return nil, nil, errf("E_VERSION_BUMP_LEVEL", "%s: %s changed since %s; patch is for message, fix and refs only", k, changed, old.Version)
			}
			if e.Version, err = bumpVersion(old.Version, b.Level); err != nil {
				return nil, nil, errf("E_LOCK", "%s: %v", k, err)
			}
		case changedParts(old, e) != "":
			return nil, nil, errf("E_VERSION_BUMP_MISSING", "%s: %s changed since %s", k, changedParts(old, e), old.Version)
		default:
			e.Version = old.Version
		}
		next[k] = e
		out[i].Version = e.Version
	}
	return out, next, nil
}

// sortedByKey returns the indexes of cs in ControlKey order, so the first
// error reported does not depend on input order.
func sortedByKey(cs []bundle.Control) []int {
	idx := make([]int, len(cs))
	for i := range idx {
		idx[i] = i
	}
	slices.SortStableFunc(idx, func(a, b int) int {
		return strings.Compare(keyOf(&cs[a]).String(), keyOf(&cs[b]).String())
	})
	return idx
}

// changedParts names the digests that differ between a and b, "" when none.
func changedParts(a, b LockEntry) string {
	var parts []string
	if a.ExprDigest != b.ExprDigest {
		parts = append(parts, "expr") // the graph object for a graph control
	}
	if a.ReadsDigest != b.ReadsDigest {
		parts = append(parts, "reads")
	}
	if a.SemanticsDigest != b.SemanticsDigest {
		parts = append(parts, "action/on/presence_mode")
	}
	return strings.Join(parts, ", ")
}

// bumpVersion applies level to v (MAJOR.MINOR.PATCH).
func bumpVersion(v, level string) (string, error) {
	m := pinRe.FindStringSubmatch(v)
	if m == nil {
		return "", fmt.Errorf("version %q: want MAJOR.MINOR.PATCH", v)
	}
	n := [3]int{}
	for i := range n {
		var err error
		if n[i], err = strconv.Atoi(m[i+1]); err != nil || n[i] == math.MaxInt {
			return "", fmt.Errorf("version %q out of range", v)
		}
	}
	switch level {
	case "major":
		n = [3]int{n[0] + 1, 0, 0}
	case "minor":
		n = [3]int{n[0], n[1] + 1, 0}
	case "patch":
		n[2]++
	default:
		return "", fmt.Errorf("level %q: want major, minor or patch", level)
	}
	return fmt.Sprintf("%d.%d.%d", n[0], n[1], n[2]), nil
}
