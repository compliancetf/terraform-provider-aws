package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/compliancetf/terraform-provider-aws/internal/upstream"
)

const testVersion = "6.40.0"

// All keys are generated at test time; no key material is committed.
func newKey(t *testing.T, cfg *packet.Config) *openpgp.Entity {
	t.Helper()
	e, err := openpgp.NewEntity("bobthecorp test", "", "release@bobthecorp.example", cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func armoredPublic(t *testing.T, es ...*openpgp.Entity) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range es {
		if err := e.Serialize(w); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()
	return buf.Bytes()
}

func detachSign(t *testing.T, e *openpgp.Entity, msg []byte, cfg *packet.Config) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := openpgp.DetachSign(&buf, e, bytes.NewReader(msg), cfg); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// withSigVersion returns sig, one new-format signature packet, with its
// version octet set to v; a v3 or v5 packet is rejected on that octet.
func withSigVersion(t *testing.T, sig []byte, v byte) []byte {
	t.Helper()
	b := append([]byte(nil), sig...)
	if len(b) < 3 || b[0] != 0xc2 {
		t.Fatalf("not a new-format signature packet: %x", b[:min(len(b), 3)])
	}
	switch l := b[1]; {
	case l < 192:
		b[2] = v
	case l < 224:
		b[3] = v
	case l == 255:
		b[6] = v
	default:
		t.Fatalf("partial body length %d", l)
	}
	return b
}

// stripSignFlag re-self-signs every identity of e without the sign flag, so
// e keeps its fingerprint but may no longer sign.
func stripSignFlag(t *testing.T, e *openpgp.Entity) {
	t.Helper()
	for _, id := range e.Identities {
		id.SelfSignature.FlagSign = false
		id.SelfSignature.FlagCertify = false
		if err := id.SelfSignature.SignUserId(id.UserId.Id, e.PrimaryKey, e.PrivateKey, nil); err != nil {
			t.Fatal(err)
		}
	}
}

type entry struct {
	name string
	body string
	mode os.FileMode
}

func makeZip(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, en := range entries {
		fh := &zip.FileHeader{Name: en.name, Method: zip.Deflate}
		mode := en.mode
		if mode == 0 {
			mode = 0o755
		}
		fh.SetMode(mode)
		w, err := zw.CreateHeader(fh)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(en.body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// release is a fake releases.hashicorp.com tree for one version.
type release struct{ files map[string][]byte } // URL path -> body

func (r *release) handler(w http.ResponseWriter, req *http.Request) {
	b, ok := r.files[req.URL.Path]
	if !ok {
		http.NotFound(w, req)
		return
	}
	_, _ = w.Write(b)
}

type fixture struct {
	key     *openpgp.Entity
	rel     *release
	zips    map[string][]byte // zip name -> bytes
	binHash map[string]string // os_arch -> sha256 of binary
}

func zipName(osArch string) string {
	goos, goarch, _ := strings.Cut(osArch, "_")
	return awsUpstream.ZipName(testVersion, goos, goarch)
}

func binName(osArch string) string {
	goos, _, _ := strings.Cut(osArch, "_")
	return awsUpstream.BinaryName(testVersion, goos, upstream.PinsProtocol)
}

func sumsFor(zips map[string][]byte) []byte {
	var b strings.Builder
	for _, osArch := range []string{"darwin_arm64", "linux_amd64", "windows_amd64"} {
		n := zipName(osArch)
		if z, ok := zips[n]; ok {
			b.WriteString(hexSum(z) + "  " + n + "\n")
		}
	}
	b.WriteString(hexSum([]byte("{}")) + "  terraform-provider-aws_" + testVersion + "_manifest.json\n")
	return []byte(b.String())
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{key: newKey(t, nil), zips: map[string][]byte{}, binHash: map[string]string{}}
	for _, osArch := range []string{"darwin_arm64", "linux_amd64", "windows_amd64"} {
		bin := "binary for " + osArch
		f.zips[zipName(osArch)] = makeZip(t, entry{name: "LICENSE.txt", body: "MPL"}, entry{name: binName(osArch), body: bin})
		f.binHash[osArch] = hexSum([]byte(bin))
	}
	f.rel = &release{files: map[string][]byte{}}
	for n, z := range f.zips {
		f.rel.files["/"+testVersion+"/"+n] = z
	}
	f.setSums(t, sumsFor(f.zips), f.key)
	return f
}

func (f *fixture) setSums(t *testing.T, sums []byte, signer *openpgp.Entity) {
	t.Helper()
	p := f.sumsPath()
	f.rel.files[p] = sums
	f.rel.files[p+".sig"] = detachSign(t, signer, sums, nil)
}

func (f *fixture) sumsPath() string {
	return "/" + testVersion + "/terraform-provider-aws_" + testVersion + "_SHA256SUMS"
}

func (f *fixture) run(t *testing.T, mutate func(*config)) (string, error) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(f.rel.handler))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pub")
	if err := os.WriteFile(keyPath, armoredPublic(t, f.key), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config{
		version:           testVersion,
		keyPath:           keyPath,
		base:              srv.URL,
		out:               filepath.Join(dir, "pins.json"),
		expectFingerprint: upstream.Fingerprint(f.key),
		allowLoopbackHTTP: true,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return cfg.out, run(t.Context(), cfg)
}

func TestPinUpstreamHappyPath(t *testing.T) {
	f := newFixture(t)
	out, err := f.run(t, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	p, err := upstream.ParsePins(data, awsUpstream, upstream.Fingerprint(f.key))
	if err != nil {
		t.Fatalf("output does not parse: %v\n%s", err, data)
	}
	if p.Version != testVersion || p.Protocol != 5 || len(p.Platforms) != 3 {
		t.Fatalf("unexpected pins: %+v", p)
	}
	if p.SHA256SumsSHA256 != hexSum(f.rel.files[f.sumsPath()]) {
		t.Fatalf("sha256sums_sha256 mismatch")
	}
	for osArch, want := range f.binHash {
		got := p.Platforms[osArch]
		if got.BinarySHA256 != want || got.Binary != binName(osArch) || got.ZipSHA256 != hexSum(f.zips[zipName(osArch)]) {
			t.Fatalf("%s: got %+v", osArch, got)
		}
	}
}

func TestPinUpstreamFailsClosed(t *testing.T) {
	type failCase struct {
		name   string
		setup  func(t *testing.T, f *fixture)
		mutate func(*config)
	}
	cases := []failCase{
		{"bad signature: sums tampered after signing", func(t *testing.T, f *fixture) {
			p := f.sumsPath()
			f.rel.files[p] = append([]byte(nil), f.rel.files[p]...)
			f.rel.files[p][0] ^= 1
		}, nil},
		{"wrong key signed the sums", func(t *testing.T, f *fixture) {
			f.setSums(t, sumsFor(f.zips), newKey(t, nil))
		}, nil},
		{"key file fingerprint differs from pinned constant", nil, func(c *config) {
			c.expectFingerprint = strings.Repeat("A", 40)
		}},
		{"missing signature: no TOFU", func(t *testing.T, f *fixture) {
			delete(f.rel.files, f.sumsPath()+".sig")
		}, nil},
		{"armored signature", func(t *testing.T, f *fixture) {
			var buf bytes.Buffer
			if err := openpgp.ArmoredDetachSign(&buf, f.key, bytes.NewReader(f.rel.files[f.sumsPath()]), nil); err != nil {
				t.Fatal(err)
			}
			f.rel.files[f.sumsPath()+".sig"] = buf.Bytes()
		}, nil},
		{"text signature type", func(t *testing.T, f *fixture) {
			var buf bytes.Buffer
			if err := openpgp.DetachSignText(&buf, f.key, bytes.NewReader(f.rel.files[f.sumsPath()]), nil); err != nil {
				t.Fatal(err)
			}
			f.rel.files[f.sumsPath()+".sig"] = buf.Bytes()
		}, nil},
		{"v3 signature packet", func(t *testing.T, f *fixture) {
			p := f.sumsPath() + ".sig"
			f.rel.files[p] = withSigVersion(t, f.rel.files[p], 3)
		}, nil},
		{"key without the sign flag", func(t *testing.T, f *fixture) {
			stripSignFlag(t, f.key) // the sums stay signed by it; only the published key changes
		}, nil},
		{"trailing bytes after signature packet", func(t *testing.T, f *fixture) {
			p := f.sumsPath() + ".sig"
			f.rel.files[p] = append(append([]byte(nil), f.rel.files[p]...), f.rel.files[p]...)
		}, nil},
		{"revoked key", func(t *testing.T, f *fixture) {
			if err := f.key.RevokeKey(packet.KeyCompromised, "test", nil); err != nil {
				t.Fatal(err)
			}
		}, nil},
		{"expired key", func(t *testing.T, f *fixture) {
			past := func() time.Time { return time.Now().Add(-48 * time.Hour) }
			f.key = newKey(t, &packet.Config{Time: past, KeyLifetimeSecs: 3600})
			p := f.sumsPath()
			f.rel.files[p+".sig"] = detachSign(t, f.key, f.rel.files[p], &packet.Config{Time: past})
		}, nil},
		{"zip mismatch: zip bytes differ from signed sums", func(t *testing.T, f *fixture) {
			f.rel.files["/"+testVersion+"/"+zipName("linux_amd64")] = makeZip(t, entry{name: binName("linux_amd64"), body: "evil"})
		}, nil},
		{"sums with CR", func(t *testing.T, f *fixture) {
			f.setSums(t, bytes.ReplaceAll(sumsFor(f.zips), []byte("\n"), []byte("\r\n")), f.key)
		}, nil},
		{"sums with unknown name", func(t *testing.T, f *fixture) {
			f.setSums(t, append(sumsFor(f.zips), []byte(strings.Repeat("0", 64)+"  terraform-provider-aws_"+testVersion+"_extra.txt\n")...), f.key)
		}, nil},
		{"sums with duplicate name", func(t *testing.T, f *fixture) {
			s := sumsFor(f.zips)
			first := s[:bytes.IndexByte(s, '\n')+1]
			f.setSums(t, append(s, first...), f.key)
		}, nil},
		{"sums with uppercase hex", func(t *testing.T, f *fixture) {
			f.setSums(t, []byte(strings.ToUpper(string(sumsFor(f.zips)[:64]))+string(sumsFor(f.zips)[64:])), f.key)
		}, nil},
		{"http base without loopback test option", nil, func(c *config) { c.allowLoopbackHTTP = false }},
		{"zip larger than cap", func(t *testing.T, _ *fixture) {
			old := maxZipBytes
			maxZipBytes = 64
			t.Cleanup(func() { maxZipBytes = old })
		}, nil},
	}
	zipCases := map[string][]entry{
		"binary missing":       {{name: "LICENSE.txt", body: "x"}},
		"binary duplicated":    {{name: binName("linux_amd64"), body: "a"}, {name: binName("linux_amd64"), body: "b"}},
		"binary case variant":  {{name: strings.ToUpper(binName("linux_amd64")), body: "a"}},
		"binary is a symlink":  {{name: binName("linux_amd64"), body: "/bin/sh", mode: os.ModeSymlink | 0o777}},
		"entry with path":      {{name: binName("linux_amd64"), body: "a"}, {name: "../evil", body: "x"}},
		"case-fold duplicates": {{name: binName("linux_amd64"), body: "a"}, {name: "license", body: "x"}, {name: "LICENSE", body: "x"}},
	}
	for name, entries := range zipCases {
		cases = append(cases, failCase{"zip: " + name, func(t *testing.T, f *fixture) {
			f.zips[zipName("linux_amd64")] = makeZip(t, entries...)
			f.rel.files["/"+testVersion+"/"+zipName("linux_amd64")] = f.zips[zipName("linux_amd64")]
			f.setSums(t, sumsFor(f.zips), f.key)
		}, nil})
	}
	// wantErr is a substring of the error each case must fail with, so a case
	// cannot pass by failing on an earlier, unrelated check.
	wantErr := map[string]string{
		"bad signature: sums tampered after signing":        "SHA256SUMS signature: openpgp: invalid signature",
		"wrong key signed the sums":                         "SHA256SUMS signature: openpgp: signature made by unknown entity",
		"key file fingerprint differs from pinned constant": "is not the pinned " + strings.Repeat("A", 40),
		"key without the sign flag":                         "SHA256SUMS signature: openpgp: signature made by unknown entity", // no sign-capable key matches the issuer
		"missing signature: no TOFU":                        "_SHA256SUMS.sig: status 404",
		"armored signature":                                 "signature: openpgp: invalid data",
		"text signature type":                               "signature type 0x1, want binary",
		"v3 signature packet":                               "signature: openpgp: unsupported feature: signature packet version 3",
		"trailing bytes after signature packet":             "signature file must be exactly one signature packet",
		"revoked key":                                       "SHA256SUMS signature: openpgp: signature made by revoked key",
		"expired key":                                       "SHA256SUMS signature: openpgp: key expired",
		"zip mismatch: zip bytes differ from signed sums":   "does not match signed SHA256SUMS",
		"sums with CR":                                      "SHA256SUMS: must be LF-terminated lines",
		"sums with unknown name":                            "SHA256SUMS: unexpected file terraform-provider-aws_" + testVersion + "_extra.txt",
		"sums with duplicate name":                          "SHA256SUMS: duplicate terraform-provider-aws_" + testVersion + "_darwin_arm64.zip",
		"sums with uppercase hex":                           "SHA256SUMS: bad line",
		"http base without loopback test option":            "must be https",
		"zip larger than cap":                               "larger than 64 bytes",
		"zip: binary missing":                               "zip has no " + binName("linux_amd64"),
		"zip: binary duplicated":                            "zip entry \"" + binName("linux_amd64") + "\" duplicated",
		"zip: binary case variant":                          "zip has no " + binName("linux_amd64"),
		"zip: binary is a symlink":                          "zip entry \"" + binName("linux_amd64") + "\" is not a regular file",
		"zip: entry with path":                              "zip entry name \"../evil\"",
		"zip: case-fold duplicates":                         "zip entry \"LICENSE\" duplicated",
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want, ok := wantErr[tc.name]
			if !ok {
				t.Fatal("no expected error for this case")
			}
			f := newFixture(t)
			if tc.setup != nil {
				tc.setup(t, f)
			}
			out, err := f.run(t, tc.mutate)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("error = %v, want one containing %q", err, want)
			}
			if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
				t.Fatalf("pins written despite failure: %v", err)
			}
		})
	}
}

func TestPinUpstreamRejectsKeyFileShapes(t *testing.T) {
	f := newFixture(t)
	other := newKey(t, nil)
	for name, c := range map[string]struct {
		data []byte
		want string
	}{
		"two entities": {armoredPublic(t, f.key, other), "key file holds 2 keys, want exactly 1"},
		"private key": {func() []byte {
			var buf bytes.Buffer
			w, _ := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
			_ = f.key.SerializePrivate(w, nil)
			_ = w.Close()
			return buf.Bytes()
		}(), "key file contains private key material"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := f.run(t, func(cfg *config) {
				cfg.keyPath = filepath.Join(t.TempDir(), "key.pub")
				if err := os.WriteFile(cfg.keyPath, c.data, 0o600); err != nil {
					t.Fatal(err)
				}
			})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %v, want one containing %q", err, c.want)
			}
		})
	}
}

func TestPinUpstreamRejectsCrossHostRedirect(t *testing.T) {
	f := newFixture(t)
	other := httptest.NewServer(http.HandlerFunc((&release{files: f.rel.files}).handler))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	_, err := f.run(t, func(c *config) { c.base = srv.URL })
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("expected redirect rejection, got %v", err)
	}
}

func TestBaseURLPolicy(t *testing.T) {
	if checkBase(defaultBase, false) != nil || checkBase("http://127.0.0.1:1", true) != nil {
		t.Error("valid base rejected")
	}
	if checkBase("http://releases.hashicorp.com", false) == nil || checkBase("http://10.0.0.1:1", true) == nil {
		t.Error("plain http to a non-loopback host accepted")
	}
}
