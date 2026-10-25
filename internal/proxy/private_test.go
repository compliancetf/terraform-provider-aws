package proxy

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/envelope goldens")

// rawEnv frames header JSON and an upstream tail without validation.
func rawEnv(header, upstream string) []byte {
	b := append([]byte{}, envelopeMagic...)
	b = append(b, envelopeVersion)
	b = binary.BigEndian.AppendUint32(b, uint32(len(header)))
	return append(append(b, header...), upstream...)
}

func header(op hook.Op, digest, identity, kind string, imported bool) hook.EnvelopeHeader {
	h := hook.EnvelopeHeader{V: 1}
	h.CTF.Op, h.CTF.ControlVersionsDigest, h.CTF.PriorIdentityKind, h.CTF.Imported = op, digest, kind, imported
	if identity != "" {
		h.CTF.PriorIdentity = json.RawMessage(identity)
	}
	return h
}

const bobIdentity = `{"account_id":"123456789012","bucket":"bobthecorp-logs"}`

var goldens = map[string]struct {
	h        hook.EnvelopeHeader
	upstream string
}{
	"v1-full.bin":           {header(hook.OpUpdate, "sha256:0f1e2d", bobIdentity, "identity", true), `{"schema_version":"1"}`},
	"v1-minimal.bin":        {header(hook.OpCreate, "", "", "", false), `{"e2bfb730-ecaa-11e6-8f88-34363bc7c4c0":{"create":600000000000}}`},
	"v1-empty-upstream.bin": {header(hook.OpDelete, "sha256:0f1e2d", "", "id", false), ""},
}

func TestEnvelopeGolden(t *testing.T) {
	for name, g := range goldens {
		got, err := Wrap(g.h, []byte(g.upstream))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		path := filepath.Join("testdata", "envelope", name)
		if *updateGolden {
			if err := os.WriteFile(path, got, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: Wrap = %q, want golden %q", name, got, want)
		}
		h, up, err := Unwrap(want)
		if err != nil || !reflect.DeepEqual(*h, g.h) || string(up) != g.upstream {
			t.Errorf("%s: Unwrap = %+v %q %v, want %+v %q", name, h, up, err, g.h, g.upstream)
		}
	}
}

func TestEnvelopeNoMagic(t *testing.T) {
	for _, b := range [][]byte{nil, {}, []byte(`{"a":1}`), []byte("\x00CTFPRX..."), []byte("\x00\x01")} {
		h, up, err := Unwrap(b)
		if h != nil || err != nil || !bytes.Equal(up, b) {
			t.Errorf("Unwrap(%q) = %v %q %v, want passthrough", b, h, up, err)
		}
	}
}

func TestEnvelopeMalformed(t *testing.T) {
	ok := `{"v":1,"ctf":{"op":"update"}}`
	big := rawEnv(ok, "")
	binary.BigEndian.PutUint32(big[8:], maxHeader+1)
	for name, b := range map[string][]byte{
		"truncated magic":      []byte("\x00CTF"),
		"short length":         append(append([]byte{}, envelopeMagic...), 1, 0, 0),
		"version byte 2":       append(append(append([]byte{}, envelopeMagic...), 2), rawEnv(ok, "")[8:]...),
		"header too large":     big,
		"header past end":      rawEnv(ok, "")[:20],
		"bad json":             rawEnv(`{"v":1,`, ""),
		"trailing tokens":      rawEnv(ok+` {}`, ""),
		"not an object":        rawEnv(`[1]`, ""),
		"null":                 rawEnv(`null`, ""),
		"v 2":                  rawEnv(`{"v":2,"ctf":{"op":"update"}}`, ""),
		"v 1.0":                rawEnv(`{"v":1.0,"ctf":{"op":"update"}}`, ""),
		"v string":             rawEnv(`{"v":"1","ctf":{"op":"update"}}`, ""),
		"missing v":            rawEnv(`{"ctf":{"op":"update"}}`, ""),
		"missing ctf":          rawEnv(`{"v":1}`, ""),
		"ctf null":             rawEnv(`{"v":1,"ctf":null}`, ""),
		"unknown top key":      rawEnv(`{"v":1,"ctf":{"op":"update"},"x":1}`, ""),
		"unknown ctf key":      rawEnv(`{"v":1,"ctf":{"op":"update","allow":true}}`, ""),
		"case folded key":      rawEnv(`{"v":1,"ctf":{"OP":"update"}}`, ""),
		"duplicate key":        rawEnv(`{"v":1,"ctf":{"op":"update","op":"create"}}`, ""),
		"escaped duplicate":    rawEnv(`{"v":1,"ctf":{"op":"update","\u006fp":"create"}}`, ""),
		"nested duplicate":     rawEnv(`{"v":1,"ctf":{"op":"update","prior_identity_kind":"identity","prior_identity":{"a":[{"b":1,"b":2}]}}}`, ""),
		"missing op":           rawEnv(`{"v":1,"ctf":{}}`, ""),
		"empty op":             rawEnv(`{"v":1,"ctf":{"op":""}}`, ""),
		"op change":            rawEnv(`{"v":1,"ctf":{"op":"change"}}`, ""),
		"op null":              rawEnv(`{"v":1,"ctf":{"op":null}}`, ""),
		"imported null":        rawEnv(`{"v":1,"ctf":{"op":"update","imported":null}}`, ""),
		"imported string":      rawEnv(`{"v":1,"ctf":{"op":"update","imported":"true"}}`, ""),
		"digest number":        rawEnv(`{"v":1,"ctf":{"op":"update","control_versions_digest":1}}`, ""),
		"bad kind":             rawEnv(`{"v":1,"ctf":{"op":"update","prior_identity_kind":"arn"}}`, ""),
		"identity not object":  rawEnv(`{"v":1,"ctf":{"op":"update","prior_identity_kind":"identity","prior_identity":"x"}}`, ""),
		"identity without set": rawEnv(`{"v":1,"ctf":{"op":"update","prior_identity_kind":"identity"}}`, ""),
		"identity wrong kind":  rawEnv(`{"v":1,"ctf":{"op":"update","prior_identity_kind":"id","prior_identity":{"id":"x"}}}`, ""),
		"create with kind id":  rawEnv(`{"v":1,"ctf":{"op":"create","prior_identity_kind":"id"}}`, ""),
		"nested magic tail":    rawEnv(ok, string(rawEnv(ok, ""))),
		"too deep":             rawEnv(`{"v":1,"ctf":{"op":"update","prior_identity_kind":"identity","prior_identity":{"a":`+strings.Repeat("[", 40)+strings.Repeat("]", 40)+`}}}`, ""),
	} {
		if h, _, err := Unwrap(b); err == nil {
			t.Errorf("%s: Unwrap accepted %q as %+v", name, b, h)
		}
	}
}

func TestEnvelopeEmptyKindPasses0A(t *testing.T) {
	// Kind "" becomes fail closed once kinds are written.
	h, _, err := Unwrap(rawEnv(` { "ctf" : { "op" : "delete" } , "v" : 1 } `, "x"))
	if err != nil || h.CTF.PriorIdentityKind != "" || h.CTF.Op != hook.OpDelete {
		t.Fatalf("Unwrap = %+v, %v", h, err)
	}
}

func TestEnvelopeWrapOversize(t *testing.T) {
	if _, err := Wrap(header(hook.OpUpdate, strings.Repeat("a", maxHeader), "", "", false), nil); err == nil {
		t.Error("Wrap accepted a header over the limit")
	}
	if _, err := Wrap(header(hook.OpUpdate, "", "", "", false), rawEnv(`{}`, "")); err == nil {
		t.Error("Wrap accepted an upstream tail starting with the magic")
	}
}

func FuzzUnwrap(f *testing.F) {
	for _, g := range goldens {
		b, _ := Wrap(g.h, []byte(g.upstream))
		f.Add(b)
	}
	f.Add(rawEnv(`{"v":1,"ctf":{"op":"update","op":"x"}}`, ""))
	f.Add([]byte("\x00CTFP"))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, up, err := Unwrap(b)
		if err != nil || h == nil {
			return
		}
		again, err := Wrap(*h, up)
		if err != nil {
			t.Fatalf("accepted header does not re-wrap: %v", err)
		}
		h2, up2, err := Unwrap(again)
		if err != nil || !reflect.DeepEqual(h, h2) || !bytes.Equal(up, up2) {
			t.Fatalf("round trip changed %+v -> %+v", h, h2)
		}
	})
}

func identityMsgpack(t *testing.T, v any) *tfplugin5.ResourceIdentityData {
	t.Helper()
	b, err := msgpack.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return &tfplugin5.ResourceIdentityData{IdentityData: &tfplugin5.DynamicValue{Msgpack: b}}
}

func TestEnvelopeIdentityEqual(t *testing.T) {
	js := func(s string) *tfplugin5.ResourceIdentityData {
		return &tfplugin5.ResourceIdentityData{IdentityData: &tfplugin5.DynamicValue{Json: []byte(s)}}
	}
	for _, tc := range []struct {
		name string
		env  string
		id   *tfplugin5.ResourceIdentityData
		want bool
	}{
		{"same msgpack", bobIdentity, identityMsgpack(t, map[string]any{"bucket": "bobthecorp-logs", "account_id": "123456789012"}), true},
		{"same json", bobIdentity, js(`{"bucket":"bobthecorp-logs","account_id":"123456789012"}`), true},
		{"other bucket", bobIdentity, identityMsgpack(t, map[string]any{"bucket": "bobthecorp-other", "account_id": "123456789012"}), false},
		{"extra key", bobIdentity, js(`{"bucket":"bobthecorp-logs","account_id":"123456789012","region":"eu-west-1"}`), false},
		{"int equal", `{"n":5}`, identityMsgpack(t, map[string]any{"n": int64(5)}), true},
		{"int vs float", `{"n":5}`, identityMsgpack(t, map[string]any{"n": 5.0}), false},
		{"float equal", `{"n":0.1}`, identityMsgpack(t, map[string]any{"n": 0.1}), true},
		{"float exponent", `{"n":1E2}`, js(`{"n":100.0}`), true},
		{"float overflow", `{"n":1e999}`, js(`{"n":1e999}`), false},
		{"huge int", `{"n":` + strings.Repeat("9", 65) + `}`, js(`{"n":` + strings.Repeat("9", 65) + `}`), false},
		{"string vs number", `{"n":"5"}`, js(`{"n":5}`), false},
		{"null leaf", `{"n":null}`, identityMsgpack(t, map[string]any{"n": nil}), true},
		{"array order", `{"a":[1,2]}`, js(`{"a":[2,1]}`), false},
		{"bin leaf", `{"n":"x"}`, identityMsgpack(t, map[string]any{"n": []byte("x")}), false},
		{"both codecs", `{}`, &tfplugin5.ResourceIdentityData{IdentityData: &tfplugin5.DynamicValue{Json: []byte(`{}`), Msgpack: []byte{0x80}}}, false},
		{"absent", `{}`, nil, false},
		{"scalar top", `{}`, js(`5`), false},
		{"json duplicate", `{"a":1}`, js(`{"a":1,"a":1}`), false},
		{"msgpack duplicate", `{"a":1}`, &tfplugin5.ResourceIdentityData{IdentityData: &tfplugin5.DynamicValue{Msgpack: []byte{0x82, 0xa1, 'a', 0x01, 0xa1, 'a', 0x01}}}, false},
		{"msgpack int key", `{}`, &tfplugin5.ResourceIdentityData{IdentityData: &tfplugin5.DynamicValue{Msgpack: []byte{0x81, 0x01, 0x01}}}, false},
		{"msgpack trailing", `{}`, &tfplugin5.ResourceIdentityData{IdentityData: &tfplugin5.DynamicValue{Msgpack: []byte{0x80, 0xc0}}}, false},
	} {
		if got := IdentityEqual(json.RawMessage(tc.env), tc.id); got != tc.want {
			t.Errorf("%s: IdentityEqual = %v, want %v", tc.name, got, tc.want)
		}
	}
}
