package bundlegen

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"maps"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
)

// Authored is one provider/controls/<id>.yaml: the controls of one catalog
// id, one per target, their fixtures
// and the version bump of a changed control. Message, severity, refs and
// exemption_coverable come from the catalog and the disposition (Generate); Version
// is a placeholder the content lock replaces. VersionBump has the
// bumps.yaml entry shape {level, from} and applies to every target of the
// file (Generate merges it into Inputs.Bumps); nil when absent.
type Authored struct {
	Controls    []bundle.Control
	Fixtures    []Fixture
	VersionBump *Bump
}

// Fixture is one hand-written case of an authored control, the crosscheck
// case fields the file cannot derive: the case id is
// <id>.<kind>.<type>.<name>, the control and schema come from the target.
type Fixture struct {
	Kind     bundle.Kind     `yaml:"kind" json:"kind"`
	Type     string          `yaml:"type" json:"resource_type"`
	Name     string          `yaml:"name" json:"name"`
	Bindings FixtureBindings `yaml:"bindings" json:"bindings"`
	Expect   FixtureExpect   `yaml:"expect" json:"expect"`
}

// FixtureBindings are the crosscheck case bindings; an omitted attribute is
// null and {"$unknown": true} marks an unknown.
type FixtureBindings struct {
	Op       bundle.On      `yaml:"op" json:"op"`
	Env      string         `yaml:"env,omitempty" json:"env,omitempty"`
	Provider map[string]any `yaml:"provider,omitempty" json:"provider,omitempty"`
	Resource map[string]any `yaml:"resource,omitempty" json:"resource,omitempty"`
	Config   map[string]any `yaml:"config,omitempty" json:"config,omitempty"`
	Prior    map[string]any `yaml:"prior,omitempty" json:"prior,omitempty"`
}

// FixtureExpect is the case expect; an omitted unknown_paths loads as [],
// the case format's value (never null).
type FixtureExpect struct {
	State        engine.State    `yaml:"state" json:"state"`
	ErrClass     engine.ErrClass `yaml:"err_class,omitempty" json:"err_class"`
	UnknownPaths []string        `yaml:"unknown_paths,omitempty" json:"unknown_paths"`
}

// authoredFile is the YAML document; unknown keys fail the load.
type authoredFile struct {
	Fix         string           `yaml:"fix"`
	Targets     []authoredTarget `yaml:"targets"`
	Fixtures    []Fixture        `yaml:"fixtures"`
	VersionBump *Bump            `yaml:"version_bump"`
}

// authoredTarget is a 7.2 control body without the fields Generate fills.
type authoredTarget struct {
	Kind         bundle.Kind         `yaml:"kind"`
	Type         string              `yaml:"type"`
	Reads        []string            `yaml:"reads"`
	PresenceMode bundle.PresenceMode `yaml:"presence_mode"`
	On           []bundle.On         `yaml:"on"`
	Expr         *string             `yaml:"expr"`
	Action       bundle.Action       `yaml:"action"`
}

// fixtureOps are the ops a crosscheck case replays (test/crosscheck knownOps).
var fixtureOps = []bundle.On{bundle.OnCreate, bundle.OnUpdate, bundle.OnDelete}

var (
	authoredNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{2,127}\.yaml$`)
	caseNameRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
)

// yaml.v3 error shapes rebuilt by yamlError; nothing between a line number
// and the type names is ever copied.
var (
	yamlLineRe      = regexp.MustCompile(`^(?:yaml: )?line ([0-9]+): `)
	yamlUnmarshalRe = regexp.MustCompile(`^line [0-9]+: cannot unmarshal (!![a-z]+) `)
	yamlFieldRe     = regexp.MustCompile(`^line [0-9]+: field (.*) not found in type [A-Za-z0-9_.]+$`)
)

// yamlError rebuilds a yaml.v3 decode error from the line, the YAML tag,
// the Go target type and a name-shaped unknown key only: the decoder quotes
// scalars and a scalar can hold any text, backticks and quotes included.
func yamlError(err error) string {
	var te *yaml.TypeError
	if !errors.As(err, &te) {
		if m := yamlLineRe.FindStringSubmatch(err.Error()); m != nil {
			return "line " + m[1] + ": YAML syntax error"
		}
		return "a value does not decode (enum or type)" // UnmarshalText errors carry the value
	}
	msgs := make([]string, 0, len(te.Errors))
	for _, e := range te.Errors {
		line := "line ?"
		if m := yamlLineRe.FindStringSubmatch(e); m != nil {
			line = "line " + m[1]
		}
		switch m, f := yamlUnmarshalRe.FindStringSubmatch(e), yamlFieldRe.FindStringSubmatch(e); {
		case m != nil:
			// the Go type follows the last " into ", after the value
			typ := e[strings.LastIndex(e, " into ")+len(" into "):]
			msgs = append(msgs, line+": cannot unmarshal "+m[1]+" into "+typ)
		case f != nil:
			msgs = append(msgs, line+": unknown field "+safeName(f[1]))
		default:
			msgs = append(msgs, line+": invalid value")
		}
	}
	return strings.Join(msgs, "; ")
}

// LoadAuthored reads every <id>.yaml in dir, sorted by name. Anything else in
// dir (another extension, a subdirectory, a symlink) fails closed: a
// misnamed file would otherwise be skipped and its id silently translated.
// Each target needs a pass and a fail fixture (E_FIXTURE_MISSING); other
// format errors are E_AUTHORED naming the file.
func LoadAuthored(dir string) (map[string]Authored, error) {
	root, err := openDirRoot(dir, "E_INPUT")
	if err != nil {
		return nil, err
	}
	defer root.Close() //nolint:errcheck // read-only
	ents, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil, errf("E_INPUT", "%v", err)
	}
	out := map[string]Authored{}
	for _, e := range ents { // ReadDir sorts by name
		if !authoredNameRe.MatchString(e.Name()) {
			return nil, errf("E_AUTHORED", "%s: %s is not an <id>.yaml file", dir, safeName(e.Name()))
		}
		data, err := readRootFile(root, e.Name())
		if err != nil {
			return nil, err
		}
		id := strings.TrimSuffix(e.Name(), ".yaml")
		a, err := parseAuthored(id, data)
		if err != nil {
			return nil, err
		}
		out[id] = a
	}
	return out, nil
}

// SetAuthored sets the Inputs.Authored controls, AuthoredFixtures and
// AuthoredBumps of in from a, by id.
func (in *Inputs) SetAuthored(a map[string]Authored) {
	in.Authored = map[string][]bundle.Control{}
	in.AuthoredFixtures = map[string][]Fixture{}
	in.AuthoredBumps = map[string]Bump{}
	for id, x := range a {
		in.Authored[id] = slices.Clone(x.Controls)
		in.AuthoredFixtures[id] = slices.Clone(x.Fixtures)
		if x.VersionBump != nil {
			in.AuthoredBumps[id] = *x.VersionBump
		}
	}
}

func parseAuthored(id string, data []byte) (Authored, error) {
	bad := func(format string, args ...any) (Authored, error) {
		return Authored{}, errf("E_AUTHORED", id+".yaml: "+format, args...)
	}
	var f authoredFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return bad("%s", yamlError(err))
	}
	if err := dec.Decode(new(yaml.Node)); !errors.Is(err, io.EOF) {
		return bad("one YAML document only")
	}
	if len(f.Targets) == 0 {
		return bad("no targets")
	}
	if b := f.VersionBump; b != nil && (!validLevel(b.Level) || !pinRe.MatchString(b.From)) {
		return bad("version_bump: want {level: major, minor or patch, from: the locked MAJOR.MINOR.PATCH}")
	}

	type key struct {
		kind bundle.Kind
		typ  string
	}
	cs := make([]bundle.Control, len(f.Targets))
	targets := map[key]bool{}
	for i, t := range f.Targets {
		cs[i] = bundle.Control{
			ID: id, Version: "1.0.0", Kind: t.Kind, ResourceType: t.Type, Reads: t.Reads,
			PresenceMode: t.PresenceMode, On: t.On, Expr: t.Expr, Action: t.Action,
			Severity: bundle.SeverityMedium, Message: id, Fix: f.Fix, ExemptionCoverable: []bundle.ExemptionKind{},
		}
		targets[key{t.Kind, t.Type}] = true
	}
	// The decoder the generator validates every kind with (the control schema).
	raw, err := canonicalJSON(cs)
	if err != nil {
		return Authored{}, err
	}
	if cs, err = bundle.DecodeControls(raw); err != nil {
		return bad("%v", err)
	}

	type count struct{ pass, fail int }
	counts := map[key]*count{}
	names := map[string]bool{}
	for i, x := range f.Fixtures {
		k := key{x.Kind, x.Type}
		if !targets[k] {
			return bad("fixture %d is not for a target kind and type", i)
		}
		if !caseNameRe.MatchString(x.Name) {
			return bad("fixture %d: name must match %s", i, caseNameRe)
		}
		n := string(x.Kind) + "." + x.Type + "." + x.Name
		if names[n] {
			return bad("fixture %d: duplicate case %s", i, n)
		}
		names[n] = true
		if !slices.Contains(fixtureOps, x.Bindings.Op) {
			return bad("fixture %s: bindings.op must be one of %v", x.Name, fixtureOps)
		}
		if x.Expect.UnknownPaths == nil {
			f.Fixtures[i].Expect.UnknownPaths = []string{}
		}
		if counts[k] == nil {
			counts[k] = &count{}
		}
		switch x.Expect.State {
		case engine.Pass:
			counts[k].pass++
		case engine.Fail:
			counts[k].fail++
		}
	}
	for _, k := range slices.SortedFunc(maps.Keys(targets), func(a, b key) int {
		return strings.Compare(string(a.kind)+" "+a.typ, string(b.kind)+" "+b.typ)
	}) {
		if c := counts[k]; c == nil || c.pass == 0 || c.fail == 0 {
			return Authored{}, errf("E_FIXTURE_MISSING", "%s.yaml: %s %s needs a pass and a fail fixture", id, k.kind, k.typ)
		}
	}
	return Authored{Controls: cs, Fixtures: f.Fixtures, VersionBump: f.VersionBump}, nil
}
