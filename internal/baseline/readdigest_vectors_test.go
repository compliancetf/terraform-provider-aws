package baseline

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// TestReadDigestVectors replays testdata/readdigest/cases.json, a
// byte-identical copy of ctfkit pkg/verdict/testdata/readdigest/cases.json:
// the provider and ctfkit compute the same read_digest, so a baseline
// written from provider evidence matches at apply. An empty digest is a
// case both refuse (an unknown read, a path through a non-object).
func TestReadDigestVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "readdigest", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		KeyHex   string          `json:"key_hex"`
		KReadHex string          `json:"k_read_hex"`
		Type     json.RawMessage `json:"type"`
		Cases    []struct {
			Name    string          `json:"name"`
			Reads   []string        `json:"reads"`
			Value   json.RawMessage `json:"value"`
			Unknown [][]string      `json:"unknown"`
			KeyHex  string          `json:"key_hex"`
			Digest  string          `json:"digest"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	typ, err := tftypes.ParseJSONType(f.Type) //nolint:staticcheck // cty JSON type syntax of the vectors
	if err != nil {
		t.Fatal(err)
	}
	key := mustHex(t, f.KeyHex)
	if kr, err := hkdf.Key(sha256.New, key, nil, infoReadDigest, 32); err != nil || hex.EncodeToString(kr) != f.KReadHex {
		t.Fatalf("k_read %x (%v), want %s", kr, err, f.KReadHex)
	}
	if len(f.Cases) == 0 {
		t.Fatal("no cases")
	}
	refused := 0
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			v, err := tftypes.ValueFromJSON(c.Value, typ) //nolint:staticcheck // test input
			if err != nil {
				t.Fatal(err)
			}
			v = markUnknown(t, v, c.Unknown)
			k := key
			if c.KeyHex != "" {
				k = mustHex(t, c.KeyHex)
			}
			got, ok := ReadDigest(k, c.Reads, v)
			if c.Digest == "" {
				refused++
				if ok {
					t.Fatalf("digest %s, the vector refuses", got)
				}
				return
			}
			if !ok || got != c.Digest {
				t.Fatalf("got %q ok=%v, want %s", got, ok, c.Digest)
			}
		})
	}
	if refused == 0 || refused == len(f.Cases) {
		t.Errorf("%d of %d cases refused: the vectors lost a side", refused, len(f.Cases))
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("key %q: %v", s, err)
	}
	return b
}

// markUnknown replaces the value at each path with an unknown; a "*" step
// matches every element of a list, set or tuple (the vectors' generator rule).
func markUnknown(t *testing.T, v tftypes.Value, paths [][]string) tftypes.Value {
	t.Helper()
	v, err := tftypes.Transform(v, func(p *tftypes.AttributePath, x tftypes.Value) (tftypes.Value, error) {
		for _, want := range paths {
			if stepsMatch(p.Steps(), want) {
				return tftypes.NewValue(x.Type(), tftypes.UnknownValue), nil
			}
		}
		return x, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func stepsMatch(steps []tftypes.AttributePathStep, want []string) bool {
	if len(steps) != len(want) {
		return false
	}
	for i, s := range steps {
		var got string
		switch s := s.(type) {
		case tftypes.AttributeName:
			got = string(s)
		case tftypes.ElementKeyString:
			got = string(s)
		case tftypes.ElementKeyInt:
			got = strconv.FormatInt(int64(s), 10)
		case tftypes.ElementKeyValue:
			got = "*"
		}
		if want[i] != "*" && got != want[i] || want[i] == "*" && got != "*" && strings.Trim(got, "0123456789") != "" {
			return false
		}
	}
	return true
}
