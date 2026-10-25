//go:build unix

// The fixtures need unix file ownership, modes and symlinks; other
// platforms refuse every verdict file (TestLoadFailsClosedOffUnix).

package verdict

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict/verdicttest"
)

// fixture is one internal/verdict/testdata/configure case: a valid verdict
// built and signed in code, changed as the fields say, and the exact
// diagnostic Load must return (want.summary "" = loads).
type fixture struct {
	Description string `json:"description"`
	// Verdict: "file" (default), "unset", "payload" (the document itself in
	// COMPLIANCETF_VERDICT), "empty", "symlink", "dir" or "missing".
	Verdict     string `json:"verdict,omitempty"`
	VerdictMode string `json:"verdict_mode,omitempty"` // octal, default 600
	Oversize    bool   `json:"oversize,omitempty"`
	// Key: "file" (default), "unset", "symlink" or "missing".
	Key     string `json:"key,omitempty"`
	KeyMode string `json:"key_mode,omitempty"` // octal, default 600
	// KeyText: "good" (default), "other" (another run's key), "upper"
	// (the right key in upper-case hex) or "newline" (good plus "\n").
	KeyText string `json:"key_text,omitempty"`
	// Set replaces top-level members before signing; null removes one.
	Set        map[string]json.RawMessage `json:"set,omitempty"`
	NullMember string                     `json:"null_member,omitempty"` // set this member to JSON null before signing
	// Raw replaces the whole file with this text (unsigned).
	Raw string `json:"raw,omitempty"`
	// Sign: "good" (default), "tampered" (a member changed after signing),
	// "unknown_kid", "revoked", "wrong_use", "other_key", "bad_value",
	// "alg", "no_profile_keys".
	Sign string `json:"sign,omitempty"`
	Now  string `json:"now,omitempty"` // default issued_at + 1h
	Want struct {
		Summary string `json:"summary"`
		Detail  string `json:"detail"`
	} `json:"want"`
}

const (
	tOrg      = "bobthecorp"
	tProfile  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	tBundle   = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	tContent  = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	tIssued   = "2026-10-18T10:00:00Z"
	tWrapper  = "2.0.0"
	tUpstream = "6.14.1"
)

func TestConfigureFixtures(t *testing.T) {
	files, err := filepath.Glob("testdata/configure/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	signer := newKey(t)
	for _, f := range files {
		t.Run(strings.TrimSuffix(filepath.Base(f), ".json"), func(t *testing.T) {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var fx fixture
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&fx); err != nil {
				t.Fatal(err)
			}
			in := run(t, signer, &fx)
			v, err := Load(in)
			got := struct{ Summary, Detail string }{}
			if err != nil {
				e, ok := err.(*Error)
				if !ok {
					t.Fatalf("Load error %T %v, want *Error", err, err)
				}
				got.Summary, got.Detail = e.Summary, e.Detail
			}
			if got.Summary != fx.Want.Summary || got.Detail != fx.Want.Detail {
				t.Fatalf("Load\n got %q / %q\nwant %q / %q", got.Summary, got.Detail, fx.Want.Summary, fx.Want.Detail)
			}
			switch {
			case err != nil && v != nil:
				t.Fatal("verdict returned with an error")
			case err == nil && fx.Verdict == "unset" && v != nil:
				t.Fatal("unset COMPLIANCETF_VERDICT must give verdict none")
			case err == nil && fx.Verdict != "unset" && (v == nil || v.Doc.OrgID != tOrg || !strings.HasPrefix(v.Digest, "sha256:")):
				t.Fatalf("verdict %+v", v)
			}
		})
	}
}

func newKey(t *testing.T) verdicttest.Key {
	t.Helper()
	nb, _ := time.Parse(time.RFC3339, "2026-10-01T00:00:00Z")
	return verdicttest.NewKey(t, nb)
}

// run writes the fixture's files, sets the environment and returns the
// loaded context.
func run(t *testing.T, signer verdicttest.Key, fx *fixture) Input {
	t.Helper()
	dir := t.TempDir()
	secret := bytes.Repeat([]byte{0x5a}, 32)
	keyText := hex.EncodeToString(secret)
	issued, _ := time.Parse(time.RFC3339, tIssued)
	doc := verdicttest.Doc(t, verdicttest.Binding{OrgID: tOrg, ProfileDigest: tProfile, BundleDigest: tBundle, ContentDigest: tContent,
		Wrapper: tWrapper, Upstream: tUpstream, IssuedAt: issued}, secret)
	for k, v := range fx.Set {
		if string(v) == "null" {
			delete(doc, k)
			continue
		}
		doc[k] = v
	}
	if fx.NullMember != "" {
		doc[fx.NullMember] = json.RawMessage("null")
	}
	sk := signer
	if fx.Sign == "other_key" {
		sk = verdicttest.Key{Priv: newKey(t).Priv, Signer: signer.Signer} // the listed kid, another private key
	}
	doc["signature"] = sign(t, sk, doc, fx.Sign)
	if fx.Sign == "tampered" {
		doc["run_id"] = json.RawMessage(`"run-2"`)
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if fx.Raw != "" {
		body = []byte(fx.Raw)
	}
	if fx.Oversize {
		body = append(body, bytes.Repeat([]byte(" "), MaxBytes)...)
	}
	vpath := filepath.Join(dir, "verdict.json")
	writeFile(t, vpath, body, fx.VerdictMode)
	switch fx.Verdict {
	case "", "file":
		t.Setenv(EnvVerdict, vpath)
	case "unset":
		unsetenv(t, EnvVerdict)
	case "payload":
		t.Setenv(EnvVerdict, string(body))
	case "empty":
		t.Setenv(EnvVerdict, "")
	case "symlink":
		link := filepath.Join(dir, "verdict-link.json")
		if err := os.Symlink(vpath, link); err != nil {
			t.Fatal(err)
		}
		t.Setenv(EnvVerdict, link)
	case "dir":
		t.Setenv(EnvVerdict, dir)
	case "missing":
		t.Setenv(EnvVerdict, filepath.Join(dir, "absent.json"))
	default:
		t.Fatalf("verdict %q", fx.Verdict)
	}
	switch fx.KeyText {
	case "other":
		keyText = strings.Repeat("a5", 32)
	case "upper":
		keyText = strings.ToUpper(keyText)
	case "newline":
		keyText += "\n"
	}
	kpath := filepath.Join(dir, "ctfkit-run.key")
	writeFile(t, kpath, []byte(keyText), fx.KeyMode)
	switch fx.Key {
	case "", "file":
		t.Setenv(EnvKeyFile, kpath)
	case "unset":
		unsetenv(t, EnvKeyFile)
	case "symlink":
		link := filepath.Join(dir, "key-link")
		if err := os.Symlink(kpath, link); err != nil {
			t.Fatal(err)
		}
		t.Setenv(EnvKeyFile, link)
	case "missing":
		t.Setenv(EnvKeyFile, filepath.Join(dir, "absent.key"))
	default:
		t.Fatalf("key %q", fx.Key)
	}
	p := &profile.Profile{OrgID: tOrg, Digest: tProfile, Verdict: &profile.Verdict{PublicKeys: []profile.SignerKey{signer.Signer}}}
	switch fx.Sign {
	case "revoked":
		p.RevokedKIDs = []string{signer.Signer.KID}
	case "wrong_use":
		p.Verdict.PublicKeys[0].Use = "baseline"
	case "no_profile_keys":
		p.Verdict = nil
	}
	now := issued.Add(time.Hour)
	if fx.Now != "" {
		if now, err = time.Parse(time.RFC3339, fx.Now); err != nil {
			t.Fatal(err)
		}
	}
	return Input{Profile: p, Revocations: trust.NoRevocations(), BundleDigest: tBundle, ContentDigest: tContent, WrapperName: "compliancetf/aws", WrapperVersion: tWrapper, UpstreamName: "hashicorp/aws", UpstreamVersion: tUpstream, Now: now}
}

func sign(t *testing.T, k verdicttest.Key, doc map[string]json.RawMessage, mode string) json.RawMessage {
	t.Helper()
	sig := verdicttest.Signature(t, k.Priv, k.Signer.KID, doc)
	switch mode {
	case "unknown_kid":
		sig["kid"] = "sha256:" + strings.Repeat("9", 64)
	case "bad_value":
		sig["value"] += "=" // padding is not base64url raw
	case "alg":
		sig["alg"] = trust.AlgEd25519
	}
	out, err := json.Marshal(sig)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func writeFile(t *testing.T, path string, body []byte, mode string) {
	t.Helper()
	perm := uint64(0o600)
	if mode != "" {
		var err error
		if perm, err = strconv.ParseUint(mode, 8, 32); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, os.FileMode(perm)); err != nil { // WriteFile's mode is masked by umask
		t.Fatal(err)
	}
}
