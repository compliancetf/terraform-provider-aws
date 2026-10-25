package trust

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

var update = flag.Bool("update", false, "regenerate keyring_test.json and testdata/dsse vectors")

// Test keys are derived from public labels (testkeys), so no private key
// material is committed or needed to regenerate.
func testBundleKey(*testing.T) crypto.Signer { return testkeys.Bundle() }

func testProfileKey(*testing.T) crypto.Signer { return testkeys.Profile() }

func spki(t *testing.T, s crypto.Signer) []byte {
	der, err := x509.MarshalPKIXPublicKey(s.Public())
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func entry(t *testing.T, s crypto.Signer, alg, purpose, notBefore, notAfter string) map[string]any {
	der := spki(t, s)
	return map[string]any{"kid": KIDFromSPKI(der), "alg": alg, "purpose": []string{purpose},
		"public_key": base64.StdEncoding.EncodeToString(der), "not_before": notBefore, "not_after": notAfter}
}

func keyringBytes(entries ...map[string]any) []byte {
	if entries == nil {
		entries = []map[string]any{}
	}
	b, _ := json.MarshalIndent(map[string]any{"format": keyringFormat, "keys": entries}, "", "  ")
	return append(b, '\n')
}

// sign builds a DSSE envelope signed by each signer in order.
func sign(t *testing.T, payloadType string, payload []byte, signers ...crypto.Signer) []byte {
	pae := PAE(payloadType, payload)
	var sigs []map[string]string
	for _, s := range signers {
		var sig []byte
		var err error
		if _, ok := s.(ed25519.PrivateKey); ok {
			sig, err = s.Sign(nil, pae, crypto.Hash(0))
		} else {
			sum := sha256.Sum256(pae)
			sig, err = s.Sign(nil, sum[:], crypto.SHA256)
		}
		if err != nil {
			t.Fatal(err)
		}
		sigs = append(sigs, map[string]string{"keyid": KIDFromSPKI(spki(t, s)), "sig": base64.StdEncoding.EncodeToString(sig)})
	}
	b, _ := json.Marshal(map[string]any{"payloadType": payloadType,
		"payload": base64.StdEncoding.EncodeToString(payload), "signatures": sigs})
	return b
}

// floorEntry is a floor keyring entry of the given generation.
func floorEntry(t *testing.T, s crypto.Signer, gen int64, notBefore, notAfter string) map[string]any {
	e := entry(t, s, AlgES256, PurposeFloor, notBefore, notAfter)
	e["generation"] = gen
	return e
}

// writeTestKeyring writes keyring_test.json, compiled only under ctftest.
func writeTestKeyring(t *testing.T) {
	const nb, na = "2026-01-01T00:00:00Z", "2030-01-01T00:00:00Z"
	if err := os.WriteFile("keyring_test.json", keyringBytes(
		entry(t, testBundleKey(t), AlgES256, PurposeBundle, nb, na),
		entry(t, testProfileKey(t), AlgEd25519, PurposeProfile, nb, na),
		floorEntry(t, testkeys.Floor(), 1, nb, na),
		floorEntry(t, testkeys.FloorNext(), 2, nb, na)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// floorStatement is the good floor payload; mut edits a copy.
func floorStatement(digest string, mut func(map[string]any)) []byte {
	p := map[string]any{"format": floorFormat, "org_id": "bobthecorp", "min_profile_version": 7,
		"bundles": map[string]int64{"cis-aws": 5, "bobthecorp-soc2": 13}, "min_wrapper_version": "1.0.0",
		"keyring_digest": digest, "epoch": 7, "revocation_epoch": 0, "retired_keys": []string{},
		"issued_at": "2026-10-06T00:00:00Z", "expires_at": "2026-10-07T00:00:00Z"}
	if mut != nil {
		mut(p)
	}
	b, _ := json.Marshal(p)
	return b
}

// floorResetPayload is the reset-7-to-2 payload; mut edits a copy.
func floorResetPayload(digest string, mut func(map[string]any)) []byte {
	p := map[string]any{"format": floorResetFormat, "org_id": "bobthecorp", "keyring_digest": digest,
		"from_epoch": 7, "to_epoch": 2, "revocation_epoch": 0, "issued_at": "2026-10-06T02:00:00Z", "expires_at": "2026-10-07T02:00:00Z"}
	if mut != nil {
		mut(p)
	}
	b, _ := json.Marshal(p)
	return b
}

// ctftestKeyringDigest recomputes the ctftest keyring digest from the files
// on disk (the compiled copy is stale right after writeTestKeyring).
// TestCtftestKeyringDigestFormula keeps it equal to keyringDigest.
func ctftestKeyringDigest(t *testing.T) string {
	h := sha256.New()
	h.Write([]byte("compliancetf.keyring-digest/ctftest\x00"))
	for _, name := range []string{"keyring.json", "keyring_test.json"} {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(b))))
		h.Write(b)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// TestGenerateFloorVectors writes testdata/floor/*.dsse.json, signed by the
// ctftest floor keys (generation 1 unless noted) and bound to the ctftest
// keyring digest. Run with
// -tags ctftest -update after keyring_test.json changes.
func TestGenerateFloorVectors(t *testing.T) {
	if !*update {
		t.Skip("run with -tags ctftest -update to regenerate")
	}
	writeTestKeyring(t)
	digest := ctftestKeyringDigest(t)
	set := func(k string, v any) func(map[string]any) { return func(p map[string]any) { p[k] = v } }
	vectors := map[string]func(map[string]any){
		"good": nil,
		"expired": func(p map[string]any) {
			p["issued_at"], p["expires_at"] = "2026-10-04T00:00:00Z", "2026-10-05T00:00:00Z"
		},
		"wrong-keyring": set("keyring_digest", "sha256:"+strings.Repeat("0", 64)),
		"old-epoch":     set("epoch", 6),
		"airgap-8d":     set("expires_at", "2026-10-14T00:00:00Z"),
		"below-wrapper": set("min_wrapper_version", "9.0.0"),
	}
	nextKID := KIDFromSPKI(spki(t, testkeys.FloorNext()))
	vectors["revoked-current-key"] = set("epoch", 9)
	vectors["retires-successor"] = func(p map[string]any) { p["epoch"], p["retired_keys"] = 8, []string{nextKID} }
	// Signed by the next key (generation 2).
	next := map[string]bool{"next-key": true, "revoked-epoch-missing": true}
	vectors["next-key"] = set("epoch", 8)
	vectors["revoked-epoch-missing"] = func(p map[string]any) { p["epoch"], p["revocation_epoch"] = 9, 4 }
	// Epoch high-water: air-gap files live up to 7 days.
	vectors["epoch-7"] = nil
	vectors["airgap-epoch-6-valid"] = func(p map[string]any) {
		p["epoch"], p["issued_at"], p["expires_at"] = 6, "2026-10-05T12:00:00Z", "2026-10-12T12:00:00Z"
	}
	next["airgap-epoch-8-revocation"] = true
	vectors["airgap-epoch-8-revocation"] = func(p map[string]any) {
		p["epoch"], p["revocation_epoch"], p["issued_at"], p["expires_at"] = 8, 4, "2026-10-06T01:00:00Z", "2026-10-13T01:00:00Z"
	}
	// Floor generation high-water, issued in this order.
	at := func(epoch int64, issued, expires string) func(map[string]any) {
		return func(p map[string]any) { p["epoch"], p["issued_at"], p["expires_at"] = epoch, issued, expires }
	}
	vectors["gen1-epoch7"] = nil
	vectors["gen1-epoch7-reissue"] = at(7, "2026-10-06T00:30:00Z", "2026-10-07T00:30:00Z")
	next["gen2-epoch8"] = true
	vectors["gen2-epoch8"] = at(8, "2026-10-06T01:00:00Z", "2026-10-07T01:00:00Z")
	next["gen2-epoch7"] = true
	vectors["gen2-epoch7"] = at(7, "2026-10-06T01:30:00Z", "2026-10-07T01:30:00Z")
	vectors["gen1-epoch9-after-gen2"] = at(9, "2026-10-06T02:00:00Z", "2026-10-07T02:00:00Z")
	write := func(name string, env []byte) {
		if err := os.WriteFile(filepath.Join("testdata", "floor", name+".dsse.json"), append(env, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, mut := range vectors {
		key := testkeys.Floor()
		if next[name] {
			key = testkeys.FloorNext()
		}
		write(name, sign(t, PayloadFloor, floorStatement(digest, mut), key))
	}
	// Floor resets. reset-replay is the same artifact captured and replayed.
	reset := sign(t, PayloadFloorReset, floorResetPayload(digest, nil), testkeys.Floor())
	write("reset-7-to-2", reset)
	write("reset-replay", reset)
	write("reset-profile-key", sign(t, PayloadFloorReset, floorResetPayload(digest, nil), testkeys.Profile()))
	write("reset-wrong-org", sign(t, PayloadFloorReset, floorResetPayload(digest, func(p map[string]any) { p["org_id"] = "bobthecorp-other" }), testkeys.Floor()))
	// Valid reset of the gen2-epoch8 high-water, signed by the retired gen1 kid.
	write("reset-retired-key", sign(t, PayloadFloorReset, floorResetPayload(digest, func(p map[string]any) {
		p["from_epoch"], p["issued_at"], p["expires_at"] = 8, "2026-10-06T03:00:00Z", "2026-10-07T03:00:00Z"
	}), testkeys.Floor()))
}

const vectorPayload = `{"format":"compliancetf.bundle-manifest/v2","bundle_id":"bobthecorp-custom","bundle_version":1,"org_id":"bobthecorp","issued_at":"2026-10-01T00:00:00Z","expires_at":"2026-12-31T00:00:00Z"}`

func TestGenerateVectors(t *testing.T) {
	if !*update {
		t.Skip("run with -update to regenerate")
	}
	bk := testBundleKey(t)
	kid := KIDFromSPKI(spki(t, bk))
	const nb, na = "2026-01-01T00:00:00Z", "2030-01-01T00:00:00Z"

	writeTestKeyring(t)

	good := sign(t, PayloadBundleManifest, []byte(vectorPayload), bk)
	var badSig map[string]any
	_ = json.Unmarshal(good, &badSig)
	s := badSig["signatures"].([]any)[0].(map[string]any)
	raw, _ := base64.StdEncoding.DecodeString(s["sig"].(string))
	raw[len(raw)-1] ^= 0x01
	s["sig"] = base64.StdEncoding.EncodeToString(raw)
	badSigBytes, _ := json.Marshal(badSig)
	revoked, _ := json.Marshal(map[string]any{"format": revocationsFormat, "epoch": 3,
		"revoked_keys":     []map[string]string{{"kid": kid, "revoked_at": "2026-11-01T00:00:00Z"}},
		"revoked_bundles":  []any{},
		"revoked_controls": []any{}})

	type want struct {
		OK    bool   `json:"ok"`
		KID   string `json:"kid,omitempty"`
		Error string `json:"error,omitempty"`
	}
	vectors := map[string]map[string]any{
		"good": {"description": "ES256 bundle key signs a bundle manifest inside its window",
			"keyring":  json.RawMessage(keyringBytes(entry(t, bk, AlgES256, PurposeBundle, nb, na))),
			"envelope": json.RawMessage(good), "want": want{OK: true, KID: kid}},
		"bad-sig": {"description": "last signature byte flipped",
			"keyring":  json.RawMessage(keyringBytes(entry(t, bk, AlgES256, PurposeBundle, nb, na))),
			"envelope": json.RawMessage(badSigBytes), "want": want{Error: "signature invalid"}},
		"wrong-purpose": {"description": "the signing key is trusted for profiles only",
			"keyring":  json.RawMessage(keyringBytes(entry(t, bk, AlgES256, PurposeProfile, nb, na))),
			"envelope": json.RawMessage(good), "want": want{Error: "key purpose profile, payload needs bundle"}},
		"revoked": {"description": "kid revoked; revoked_at after issued_at does not save it",
			"keyring":     json.RawMessage(keyringBytes(entry(t, bk, AlgES256, PurposeBundle, nb, na))),
			"revocations": json.RawMessage(revoked),
			"envelope":    json.RawMessage(good), "want": want{Error: "key revoked"}},
		"outside-window": {"description": "key window ends before the payload issued_at",
			"keyring":  json.RawMessage(keyringBytes(entry(t, bk, AlgES256, PurposeBundle, nb, "2026-06-30T00:00:00Z"))),
			"envelope": json.RawMessage(good), "want": want{Error: "outside key window"}},
	}
	for name, v := range vectors {
		v["payload_type"] = PayloadBundleManifest
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join("testdata", "dsse", name+".json"), append(b, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
