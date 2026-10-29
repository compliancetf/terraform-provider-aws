package bundlegen

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
)

// ReleasesFormat is the format key of releases.json.
const ReleasesFormat = "compliancetf.releases/v1"

// Releases is releases.json (repo root): the compliancetf/aws releases a
// premium bundle supports. Under version parity release X.Y.Z wraps
// hashicorp/aws X.Y.Z. Floor is the oldest supported release; only the owner
// raises it. Releases lists every supported release in ascending order, from
// the floor to the pin; make pin appends the new pin.
type Releases struct {
	Format   string   `json:"format"`
	Floor    string   `json:"floor"`
	Releases []string `json:"releases"`
}

// LoadReleases reads releases.json. Unknown keys fail: a typo must not drop
// the floor.
func LoadReleases(path string) (Releases, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied input path
	if err != nil {
		return Releases{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var r Releases
	if err := dec.Decode(&r); err != nil {
		return Releases{}, errf("E_RELEASE_FLOOR", "%s: %v", path, err)
	}
	if dec.More() {
		return Releases{}, errf("E_RELEASE_FLOOR", "%s: data after the JSON object", path)
	}
	if r.Format != ReleasesFormat {
		return Releases{}, errf("E_RELEASE_FLOOR", "%s: format %q, want %q", path, r.Format, ReleasesFormat)
	}
	return r, nil
}

// Older checks r against the pin and returns the supported releases below
// it. The releases are exact x.y.z versions, strictly ascending, all of the
// floor's major (the range ends at the next major), the first is the floor
// and the last the pin.
func (r Releases) Older(pin string) ([]string, error) {
	p, ok := parseRelease(pin)
	if !ok {
		return nil, errf("E_UPSTREAM_PIN", "upstream pin %q is not an exact x.y.z version", pin)
	}
	f, ok := parseRelease(r.Floor)
	if !ok {
		return nil, errf("E_RELEASE_FLOOR", "floor %q is not a release x.y.z version", r.Floor)
	}
	if f[0] != p[0] || cmpRelease(f, p) > 0 {
		return nil, errf("E_RELEASE_FLOOR", "floor %s is not at most the pin %s of the same major", r.Floor, pin)
	}
	n := len(r.Releases)
	if n == 0 || r.Releases[0] != r.Floor || r.Releases[n-1] != pin {
		return nil, errf("E_RELEASE_FLOOR", "releases %q must run from the floor %s to the pin %s", r.Releases, r.Floor, pin)
	}
	var prev [3]int
	for i, v := range r.Releases {
		x, ok := parseRelease(v)
		if !ok || x[0] != f[0] || i > 0 && cmpRelease(prev, x) >= 0 {
			return nil, errf("E_RELEASE_FLOOR", "release %q: want ascending x.y.z versions of major %d", v, f[0])
		}
		prev = x
	}
	return r.Releases[:n-1], nil
}

// LoadSupportedSchemas reads <dir>/<version>.json for each version, the
// schema of each supported release below the pin.
func LoadSupportedSchemas(dir string, versions []string) (map[string]Schemas, error) {
	out := map[string]Schemas{}
	for _, v := range versions {
		s, err := LoadSchemas(filepath.Join(dir, v+".json"))
		if err != nil {
			return nil, errf("E_SUPPORTED_SCHEMA", "supported release %s: %v (make pin keeps one schema per release; raise the floor to drop it)", v, err)
		}
		out[v] = s
	}
	return out, nil
}

func parseRelease(v string) ([3]int, bool) {
	m := pinRe.FindStringSubmatch(v)
	if m == nil {
		return [3]int{}, false
	}
	var x [3]int
	for i := range x {
		n, err := strconv.Atoi(m[i+1])
		if err != nil || n == math.MaxInt {
			return [3]int{}, false
		}
		x[i] = n
	}
	return x, true
}

func cmpRelease(a, b [3]int) int {
	for i := range a {
		if a[i] != b[i] {
			return a[i] - b[i]
		}
	}
	return 0
}

// checkSupported fails E_SUPPORTED_SCHEMA unless cs holds on the schema of
// every supported release below the pin (older): CheckSchema, with the pin
// schema as verified, every read of the type it has in the pin schema
// (celeng compiles resource reads as dyn, so the cases replayed against the
// pin say nothing for another type), and a clean celeng.Load (kinds,
// Computed-only).
func checkSupported(cs []bundle.Control, pin Schemas, supported map[string]Schemas, older []string) error {
	for _, v := range older {
		s, ok := supported[v]
		if !ok {
			return errf("E_SUPPORTED_SCHEMA", "no schema for supported release %s", v)
		}
		if err := CheckSchema(cs, s, pin); err != nil {
			return errf("E_SUPPORTED_SCHEMA", "hashicorp/aws %s: %v", v, err)
		}
		if err := sameReadTypes(cs, s, pin); err != nil {
			return errf("E_SUPPORTED_SCHEMA", "hashicorp/aws %s: %v", v, err)
		}
		// GraphReads covers the reads of the graph controls above.
		_, diags, err := celeng.Load(exprControls(cs), s.ProviderSchema())
		if err == nil && len(diags) > 0 {
			err = &diags[0]
		}
		if err != nil {
			return errf("E_SUPPORTED_SCHEMA", "hashicorp/aws %s: %v", v, err)
		}
	}
	return nil
}

// CheckSchema fails E_SCHEMA_TYPE when cs does not hold on s: a type or read
// is missing (SchemaCompatLines), or a read is Computed in s (ReadComputed)
// while its control checks the effective value (presence_mode not
// configured), which would judge a provider-filled value. A read Computed in
// verified too is left to Verify (E_OPTIONAL_COMPUTED replays its cases);
// pass Schemas{} to exempt none.
func CheckSchema(cs []bundle.Control, s, verified Schemas) error {
	if _, err := SchemaCompatLines(cs, s); err != nil {
		return err
	}
	for _, c := range cs {
		if c.PresenceMode == bundle.PresenceConfigured {
			continue
		}
		sc, _ := s.Lookup(c.Kind, c.ResourceType)
		vc, _ := verified.Lookup(c.Kind, c.ResourceType)
		for _, r := range c.Reads {
			if ReadComputed(sc, r) && !ReadComputed(vc, r) {
				return errf("E_SCHEMA_TYPE", "%s: read %s.%s is Computed: set presence_mode configured or rework the control", c.ID, c.ResourceType, r)
			}
		}
	}
	return nil
}

// ReadComputed reports whether an attribute on read path r of schema sc is
// Computed, or r names a block holding a Computed attribute (nested blocks
// carry their own flags). Steps into an attribute's object type carry no
// flags. A nil schema has no Computed read.
func ReadComputed(sc *tfprotov5.Schema, r string) bool {
	if sc == nil || sc.Block == nil {
		return false
	}
	b := sc.Block
	for _, seg := range strings.Split(r, ".") {
		var next *tfprotov5.SchemaBlock
		for _, a := range b.Attributes {
			if a.Name == seg {
				return a.Computed
			}
		}
		for _, nb := range b.BlockTypes {
			if nb.TypeName == seg {
				next = nb.Block
			}
		}
		if next == nil {
			return false
		}
		b = next
	}
	return anyComputed(b) // the read is the whole block
}

func anyComputed(b *tfprotov5.SchemaBlock) bool {
	for _, a := range b.Attributes {
		if a.Computed {
			return true
		}
	}
	for _, nb := range b.BlockTypes {
		if anyComputed(nb.Block) {
			return true
		}
	}
	return false
}

// sameReadTypes fails E_SCHEMA_TYPE when a read of cs (ControlReads on the
// pin) is on a type s lacks or has another type in s than in pin: its
// terminal type, or a list, set, map or object step on the way to it
// (readSignature).
func sameReadTypes(cs []bundle.Control, s, pin Schemas) error {
	for i := range cs {
		c := &cs[i]
		reads, err := ControlReads(c, pin)
		if err != nil {
			return err
		}
		for _, r := range reads {
			sc, _ := s.Lookup(r.Kind, r.Type)
			pc, _ := pin.Lookup(r.Kind, r.Type)
			if sc == nil || pc == nil {
				return errf("E_SCHEMA_TYPE", "%s: %s type %s is not in the upstream schema", c.ID, r.Kind, r.Type)
			}
			got, want := readSignature(sc.ValueType(), r.Path), readSignature(pc.ValueType(), r.Path)
			if got != want {
				return errf("E_SCHEMA_TYPE", "%s: read %s.%s has type %s, %s in the pin", c.ID, r.Type, r.Path, got, want)
			}
		}
	}
	return nil
}

// readSignature is the container steps (list, set, map, object) typeAt
// takes along read path r of t, then the terminal type JSON; "" when the
// path is not in t.
func readSignature(t tftypes.Type, r string) string {
	var b strings.Builder
	for _, seg := range strings.Split(r, ".") {
		for {
			if l, ok := t.(tftypes.List); ok {
				b.WriteString("list/")
				t = l.ElementType
			} else if st, ok := t.(tftypes.Set); ok {
				b.WriteString("set/")
				t = st.ElementType
			} else {
				break
			}
		}
		switch c := t.(type) {
		case tftypes.Map:
			b.WriteString("map/")
			t = c.ElementType
		case tftypes.Object:
			b.WriteString("object/")
			t = c.AttributeTypes[seg]
		default:
			if t != nil && t.Is(tftypes.DynamicPseudoType) {
				b.WriteString("dynamic")
				return b.String()
			}
			return ""
		}
		if t == nil {
			return ""
		}
	}
	tj, err := t.MarshalJSON() //nolint:staticcheck // the schema -json type signature, as SchemaCompatLines
	if err != nil {
		return ""
	}
	return b.String() + string(tj)
}
