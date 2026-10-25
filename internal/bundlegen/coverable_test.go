package bundlegen

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/internal/exceptions"
	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

const (
	coverableDir = "testdata/coverable"
	coverableID  = "rds_bobthecorp_storage_encrypted"
	coverableWS  = "bobthecorp-reporting-prod"
)

var coverableNow = time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)

// coverableInputs are the test inputs with the raw JSON value spliced in as
// id's exemption_coverable in provider_dispositions.json (nil drops the
// field), decoded by LoadCatalog as ctf-bundlegen generate does.
func coverableInputs(t *testing.T, id string, raw []byte) (Inputs, error) {
	t.Helper()
	in := loadInputs(t, inputs, true)
	dir := t.TempDir()
	src := filepath.Join(inputs, "catalog")
	for _, name := range []string{"manifest.json", "controls.json", "frameworks_metadata.json", "provider_dispositions.json"} {
		data, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			t.Fatal(err)
		}
		if name == "provider_dispositions.json" {
			var doc map[string]any
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			d := doc["controls"].(map[string]any)[id].(map[string]any)
			delete(d, "exemption_coverable")
			if raw != nil {
				d["exemption_coverable"] = json.RawMessage(raw)
			}
			if data, err = json.Marshal(doc); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var err error
	in.Catalog, err = LoadCatalog(dir)
	return in, err
}

// TestCoverableLoader: each case's disposition exemption_coverable
// is emitted sorted into every generated control of the id, loads through
// internal/bundle byte-equal to the sorted list, and exceptions.Coverable
// returns exactly those kinds. A signed grant applies on grant_baseline and
// is exception_not_coverable on baseline_only and empty, where the control
// stays enforced. Any other value fails E_COVERABLE_KIND.
func TestCoverableLoader(t *testing.T) {
	kinds := []bundle.ExemptionKind{bundle.CoverBaseline, bundle.CoverBreakGlass, bundle.CoverGrant, bundle.CoverSelfService, "waiver"}
	for _, name := range []string{"grant_baseline", "baseline_only", "empty"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(coverableDir, name, "exemption_coverable.json"))
			if err != nil {
				t.Fatal(err)
			}
			var list []bundle.ExemptionKind
			if err := json.Unmarshal(raw, &list); err != nil {
				t.Fatal(err)
			}
			sorted := slices.Sorted(slices.Values(list))
			want, _ := json.Marshal(append([]bundle.ExemptionKind{}, sorted...))

			in, err := coverableInputs(t, coverableID, raw)
			if err != nil {
				t.Fatal(err)
			}
			files := generate(t, in)
			syncCoverable(t, name, files["soc2-aws/"+bundle.ControlsFile])
			if emitted := emittedCoverable(t, files); len(emitted) == 0 {
				t.Fatalf("no generated control of %s", coverableID)
			} else {
				for _, got := range emitted {
					if !bytes.Equal(got, want) {
						t.Fatalf("emitted exemption_coverable %s, want %s", got, want)
					}
				}
			}

			set, cs := loadCoverable(t, files)
			if got, _ := json.Marshal(set.Coverable()[coverableID]); !bytes.Equal(got, want) {
				t.Fatalf("loaded exemption_coverable %s, want %s", got, want)
			}
			cov, _ := exceptions.NewCoverability(set.Coverable(), nil)
			for _, k := range kinds {
				if got := cov.Coverable(coverableID, string(k)); got != slices.Contains(sorted, k) {
					t.Errorf("Coverable(%s, %s) = %v", coverableID, k, got)
				}
			}

			// A signed grant on the control with a matching selector.
			gs, n := loadCoverableGrant(t, set, cov)
			ctl := controlByID(t, cs, coverableID)
			unencrypted := dbInstance(false)
			d := gs.Lookup(t.Context(), ctl, in.Schemas, &engine.Activation{Resource: unencrypted, Op: engine.OpCreate}, coverableNow)
			if slices.Contains(sorted, bundle.CoverGrant) {
				if !d.Applied || d.Exception == nil || d.Exception.Source != "grant" || len(n.Warnings)+len(n.Events) != 0 {
					t.Fatalf("grant on a grant-coverable control: %+v %+v", d, n)
				}
				return
			}
			wantWarn := []string{"exception bobthecorp-rds-encryption: " + coverableID + " is not exemption-coverable for grant; enforced"}
			if !slices.Equal(n.Warnings, wantWarn) || !slices.Equal(n.Events, []string{"exception_not_coverable"}) {
				t.Fatalf("notices %q %q, want %q and exception_not_coverable", n.Warnings, n.Events, wantWarn)
			}
			if d.Applied || d.Exception == nil || d.Exception.Status != exceptions.StatusNotCoverable || len(gs.Digests()) != 0 {
				t.Fatalf("grant on a non-grant-coverable control must not apply: %+v", d)
			}
			// Not waived, so the generated control's fail decides: enforced.
			if r := evalCoverable(t, files, cs, set, unencrypted); r.State != engine.Fail {
				t.Fatalf("control on storage_encrypted false: %+v, want fail", r)
			}
		})
	}

	// An absent field is the default empty list.
	absent, err := coverableInputs(t, coverableID, nil)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := os.ReadFile(filepath.Join(coverableDir, "empty", bundle.ControlsFile))
	if err != nil {
		t.Fatal(err)
	}
	if got := generate(t, absent)["soc2-aws/"+bundle.ControlsFile]; !bytes.Equal(got, empty) {
		t.Fatal("an absent exemption_coverable must generate the empty case")
	}

	badKind, err := os.ReadFile(filepath.Join(coverableDir, "bad_kind", "exemption_coverable.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{string(badKind), `["grant","grant"]`, `[""]`, `["Grant"]`, `true`, `false`, `null`, `1`, `{}`, `"grant"`,
		`[null]`, `["grant",null]`, `["grant",true]`, `[["grant"]]`} {
		in, err := coverableInputs(t, coverableID, []byte(raw))
		if err == nil {
			_, err = Generate(in, testOpts)
		}
		if e := (*Error)(nil); !errors.As(err, &e) || e.Code != "E_COVERABLE_KIND" {
			t.Errorf("exemption_coverable %s: want E_COVERABLE_KIND, got %v", raw, err)
		}
	}
	// A disposition that emits no control (runtime) is checked too, and so
	// are in-memory inputs that never went through JSON.
	in := loadInputs(t, inputs, true)
	d := in.Catalog.Dispositions.Controls["acct_bobthecorp_contact_set"]
	d.ExemptionCoverable = coverableKinds{"waiver"}
	in.Catalog.Dispositions.Controls["acct_bobthecorp_contact_set"] = d
	if _, err := Generate(in, testOpts); err == nil || !strings.HasPrefix(err.Error(), `E_COVERABLE_KIND: acct_bobthecorp_contact_set: exemption kind "waiver"`) {
		t.Fatalf("runtime disposition with an unknown kind: %v", err)
	}
}

// syncCoverable checks (or with -update writes) the case's golden soc2-aws
// controls.json.
func syncCoverable(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join(coverableDir, name, bundle.ControlsFile)
	if *update {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if want, err := os.ReadFile(p); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%s differs from the generator output (run with -update): %v", p, err)
	}
}

// emittedCoverable returns the compact raw exemption_coverable of every
// generated control of coverableID across all bundles.
func emittedCoverable(t *testing.T, files map[string][]byte) [][]byte {
	t.Helper()
	var out [][]byte
	for _, p := range slices.Sorted(maps.Keys(files)) {
		if !strings.HasSuffix(p, "/"+bundle.ControlsFile) {
			continue
		}
		var cs []map[string]json.RawMessage
		if err := json.Unmarshal(files[p], &cs); err != nil {
			t.Fatal(err)
		}
		for _, c := range cs {
			if string(c["id"]) != `"`+coverableID+`"` {
				continue
			}
			var b bytes.Buffer
			if err := json.Compact(&b, c["exemption_coverable"]); err != nil {
				t.Fatal(err)
			}
			out = append(out, b.Bytes())
		}
	}
	return out
}

// loadCoverable loads the generated soc2-aws controls.json through the
// provider's decoder and NewControlSet (signed-archive loading of the
// coverable map is tested elsewhere).
func loadCoverable(t *testing.T, files map[string][]byte) (*bundle.ControlSet, []bundle.Control) {
	t.Helper()
	data := files["soc2-aws/"+bundle.ControlsFile]
	cs, err := bundle.ParseControls(data)
	if err != nil {
		t.Fatal(err)
	}
	mraw, err := os.ReadFile(filepath.Join(contentDir, "base", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := bundle.DecodeManifest(mraw) // a build source: no files list
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	b := &bundle.Bundle{Manifest: m, Digest: "sha256:" + hex.EncodeToString(sum[:]), Controls: cs, Revocations: trust.NoRevocations()}
	set, _, err := bundle.NewControlSet("bobthecorp", coverableNow, trust.NoRevocations(), b)
	if err != nil {
		t.Fatal(err)
	}
	return set, cs
}

func controlByID(t *testing.T, cs []bundle.Control, id string) *bundle.Control {
	t.Helper()
	for i := range cs {
		if cs[i].ID == id {
			return &cs[i]
		}
	}
	t.Fatalf("no control %s", id)
	return nil
}

// dbInstance is a planned aws_db_instance of the test schema.
func dbInstance(encrypted bool) tftypes.Value {
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{"storage_encrypted": tftypes.Bool}},
		map[string]tftypes.Value{"storage_encrypted": tftypes.NewValue(tftypes.Bool, encrypted)})
}

// loadCoverableGrant verifies one grant signed with the test exception key
// for coverableID, bound to the loaded content, and decides coverability.
func loadCoverableGrant(t *testing.T, set *bundle.ControlSet, cov exceptions.Coverability) (*exceptions.Grants, exceptions.Notices) {
	t.Helper()
	emb, err := trust.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	key := testkeys.Exception()
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	kr, err := trust.ExceptionKeyring(emb, []trust.ExtKey{{KID: trust.KIDFromSPKI(der), Alg: trust.AlgES256, SPKI: der,
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)}})
	if err != nil {
		t.Fatal(err)
	}
	mt, err := profile.ComputeModeTable(profile.TableInput{Resolution: profile.Resolution{OrgID: "bobthecorp", Fallback: profile.ProfileApplied,
		Profile: &profile.Profile{OrgID: "bobthecorp", Scope: &profile.Scope{Workspace: coverableWS}}}})
	if err != nil {
		t.Fatal(err)
	}
	v, err := exceptions.NewVerifier(exceptions.VerifierInput{Compiled: kr, Revocations: trust.NoRevocations(), Table: mt, OrgID: "bobthecorp", Now: coverableNow})
	if err != nil {
		t.Fatal(err)
	}
	digest := set.ContentDigest(cov.Kinds())
	idp := "https://idp.bobthecorp.example"
	body, err := json.Marshal(map[string]any{"format": exceptions.Format, "grant_id": "bobthecorp-rds-encryption", "org_id": "bobthecorp",
		"workspaces": []string{coverableWS}, "controls": []string{coverableID},
		"selector": "type == 'aws_db_instance' && resource.storage_encrypted == false",
		"reason":   "Encrypted copy in progress, OPS-4411", "ticket": "OPS-4411",
		"approvers":      []map[string]string{{"subject": "alice@bobthecorp.example", "issuer": idp}, {"subject": "bob@bobthecorp.example", "issuer": idp + "/oidc"}},
		"content_digest": digest, "floor_epoch": 0, "issued_at": "2026-10-01T00:00:00Z", "expires_at": "2027-03-31T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(trust.PAE(trust.PayloadExceptionGrant, body))
	sig, err := key.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(map[string]any{"payloadType": trust.PayloadExceptionGrant, "payload": base64.StdEncoding.EncodeToString(body),
		"signatures": []map[string]string{{"keyid": trust.KIDFromSPKI(der), "sig": base64.StdEncoding.EncodeToString(sig)}}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "g.dsse.json"), env, 0o600); err != nil {
		t.Fatal(err)
	}
	gs, n, err := exceptions.LoadGrants(exceptions.GrantsInput{Dir: dir, Verifier: v, Coverable: cov, Resolve: set.Resolve, ResolveFold: set.ResolveFold,
		Table: mt, ContentDigest: digest, Revoked: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	return gs, n
}

// evalCoverable evaluates coverableID of the loaded soc2-aws controls on a
// planned instance with the provider's engine.
func evalCoverable(t *testing.T, files map[string][]byte, cs []bundle.Control, set *bundle.ControlSet, res tftypes.Value) celeng.Result {
	t.Helper()
	cat, err := iampolicy.LoadCatalog(files["soc2-aws/"+bundle.IAMActionsFile])
	if err != nil {
		t.Fatal(err)
	}
	s := loadInputs(t, inputs, false).Schemas
	comp, diags, err := VerifyEngine().Load(cs, s.ProviderSchema(), celeng.Content{IAMCatalog: cat, Digest: set.ContentDigest(nil)})
	if err != nil || len(diags) > 0 {
		t.Fatalf("celeng load: %v %v", err, diags)
	}
	return evalOne(comp, celeng.Bindings{Kind: bundle.KindResource, Type: "aws_db_instance", Resource: res, Op: string(engine.OpCreate)}, coverableID)
}
