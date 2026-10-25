package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// second returns a copy of the good bundle as another bundle_id and digest,
// with the given controls.
func second(t *testing.T, id, digest string, controls []Control) *Bundle {
	t.Helper()
	b := goodBundle(t)
	m := *b.Manifest
	m.BundleID = id
	b.Manifest, b.Digest, b.Controls, b.Revocations = &m, digest, controls, trust.NoRevocations()
	return b
}

var now = time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)

func TestControlSet(t *testing.T) {
	a := goodBundle(t)
	guard := Control{ID: "rds_deletion_protection", Version: "1.0.0", Kind: KindDeletionGuard, ResourceType: "aws_db_instance", On: []On{"delete"}}
	b := second(t, "bobthecorp-extra", "sha256:"+strings.Repeat("0", 64), []Control{guard})
	set, warns, err := NewControlSet("bobthecorp", now, trust.NoRevocations(), a, b)
	if err != nil || len(warns) != 0 {
		t.Fatal(err, warns)
	}
	// Normative preimages (Decisions): sorted bundle digests joined
	// by "\n"; VersionsDigest = Digest + "\n" + sorted id@version joined by "\n".
	digest := sha(b.Digest + "\n" + a.Digest)
	if set.Digest() != digest {
		t.Fatalf("Digest %s, want %s", set.Digest(), digest)
	}
	if got, want := set.VersionsDigest("aws_db_instance"), sha(digest+"\nrds_db_instance_encryption_at_rest_enabled@2.1.0\nrds_deletion_protection@1.0.0"); got != want {
		t.Fatalf("VersionsDigest %s, want %s", got, want)
	}
	if got, want := set.VersionsDigest("aws_vpc"), sha(digest+"\n"); got != want {
		t.Fatalf("empty type VersionsDigest %s, want %s", got, want)
	}
	// Golden: one bundle, the committed good.tar.gz.
	solo, _, err := NewControlSet("bobthecorp", now, trust.NoRevocations(), a)
	if err != nil {
		t.Fatal(err)
	}
	if solo.Digest() != sha(a.Digest) {
		t.Fatal("single-bundle digest")
	}
	if c := set.For("aws_db_instance", "delete"); len(c) != 1 || c[0].ID != guard.ID {
		t.Fatalf("For delete: %v", c)
	}
	if c := set.For("aws_db_instance", "create"); len(c) != 1 || c[0].ID != "rds_db_instance_encryption_at_rest_enabled" {
		t.Fatalf("For create: %v", c)
	}
	if c := set.For("aws_s3_bucket_public_access_block", "delete"); len(c) != 0 {
		t.Fatalf("For s3 delete: %v", c)
	}
	if set.Revocations().Epoch() != 1 {
		t.Fatal("merged revocations not exposed")
	}
}

// TestVersionsDigestKinds: the plan-to-apply stamp of a type
// covers its resource and deletion_guard controls only. Bundle digests are
// held fixed so the per-type preimage is what changes.
func TestVersionsDigestKinds(t *testing.T) {
	a := goodBundle(t)
	d := "sha256:" + strings.Repeat("0", 64)
	stamp := func(extra ...Control) string {
		t.Helper()
		set, _, err := NewControlSet("bobthecorp", now, trust.NoRevocations(), a, second(t, "bobthecorp-extra", d, extra))
		if err != nil {
			t.Fatal(err)
		}
		return set.VersionsDigest("aws_db_instance")
	}
	ds := Control{ID: "rds_ds", Version: "1.0.0", Kind: KindDataSource, ResourceType: "aws_db_instance", PresenceMode: PresenceEffective}
	eph := Control{ID: "rds_eph", Version: "1.0.0", Kind: KindEphemeral, ResourceType: "aws_db_instance"}
	guard := Control{ID: "rds_guard", Version: "1.0.0", Kind: KindDeletionGuard, ResourceType: "aws_db_instance", On: []On{OnDelete}}
	res := Control{ID: "rds_res", Version: "1.0.0", Kind: KindResource, ResourceType: "aws_db_instance", PresenceMode: PresenceEffective, On: []On{OnCreate}}
	bump := func(c Control) Control { c.Version = "2.0.0"; return c }

	base := stamp(ds, eph, guard, res)
	if got := stamp(bump(ds), bump(eph), guard, res); got != base {
		t.Error("data source or ephemeral version change moved the resource stamp")
	}
	if stamp(guard, res) != base {
		t.Error("data source or ephemeral control is a stamp input")
	}
	if stamp(ds, eph, bump(guard), res) == base {
		t.Error("deletion_guard version change left the stamp unchanged")
	}
	if stamp(ds, eph, guard, bump(res)) == base {
		t.Error("resource version change left the stamp unchanged")
	}

	// VersionsDigestOf covers exactly the named kinds; VersionsDigest is its
	// resource + deletion_guard case.
	set, _, err := NewControlSet("bobthecorp", now, trust.NoRevocations(), a, second(t, "bobthecorp-extra", d, []Control{ds, eph, guard, res}))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		kinds []Kind
		ids   string
	}{
		{[]Kind{KindEphemeral}, "\nrds_eph@1.0.0"},
		{[]Kind{KindDataSource}, "\nrds_ds@1.0.0"},
		{[]Kind{KindDeletionGuard, KindResource}, "\nrds_db_instance_encryption_at_rest_enabled@2.1.0\nrds_guard@1.0.0\nrds_res@1.0.0"},
	} {
		if got, want := set.VersionsDigestOf("aws_db_instance", c.kinds...), sha(set.Digest()+c.ids); got != want {
			t.Errorf("VersionsDigestOf %v = %s, want %s", c.kinds, got, want)
		}
	}
	if set.VersionsDigest("aws_db_instance") != set.VersionsDigestOf("aws_db_instance", KindResource, KindDeletionGuard) {
		t.Error("VersionsDigest is not the resource + deletion_guard digest")
	}
}

func TestControlSetRejects(t *testing.T) {
	a := goodBundle(t)
	other := sha("other")
	revoker := second(t, "bobthecorp-extra", other, nil)
	var err error
	if revoker.Revocations, err = trust.ParseRevocations([]byte(`{"format":"compliancetf.revocations/v1","epoch":3,"revoked_keys":[],"revoked_bundles":[{"bundle_id":"bobthecorp-soc2","below_version":13}],"revoked_controls":[]}`)); err != nil {
		t.Fatal(err)
	}
	expired := goodBundle(t)
	cases := map[string]struct {
		now     time.Time
		bundles []*Bundle
	}{
		"no bundles":          {now, nil},
		"duplicate bundle_id": {now, []*Bundle{a, second(t, "bobthecorp-soc2", other, nil)}},
		"disagree":            {now, []*Bundle{a, second(t, "bobthecorp-extra", other, bumped(a.Controls[:1]))}},
		"revoked":             {now, []*Bundle{a, revoker}},
		"expired":             {time.Date(2027, 4, 9, 0, 0, 0, 0, time.UTC), []*Bundle{expired}},
	}
	for want, c := range cases {
		if _, _, err := NewControlSet("bobthecorp", c.now, trust.NoRevocations(), c.bundles...); err == nil || !strings.Contains(err.Error(), strings.Fields(want)[0]) {
			t.Errorf("%s: got %v", want, err)
		}
	}
	_, warns, err := NewControlSet("bobthecorp", time.Date(2027, 4, 3, 0, 0, 0, 0, time.UTC), trust.NoRevocations(), a)
	if err != nil || len(warns) != 1 {
		t.Fatalf("grace: %v %v", warns, err)
	}
}

func bumped(cs []Control) []Control {
	out := slices.Clone(cs)
	out[0].Version = "9.9.9"
	return out
}

// TestControlSetDedupe: a control key
// in two bundles loads once when both copies have the same digest and fails
// the set when they differ; copies bound to different iam-actions.json keep
// no catalog, whatever a later bundle carries.
func TestControlSetDedupe(t *testing.T) {
	a := goodBundle(t)
	enc := a.Controls[0]
	dup := second(t, "bobthecorp-cis", sha("cis"), []Control{enc})
	set, _, err := NewControlSet("bobthecorp", now, trust.NoRevocations(), a, dup)
	if err != nil {
		t.Fatal(err)
	}
	solo, _, err := NewControlSet("bobthecorp", now, trust.NoRevocations(), a)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.All()) != len(solo.All()) || len(set.For(enc.ResourceType, OnCreate)) != len(solo.For(enc.ResourceType, OnCreate)) {
		t.Fatalf("same digest must dedupe: %d controls", len(set.All()))
	}
	if got, want := set.VersionsDigest(enc.ResourceType), sha(set.Digest()+"\n"+enc.ID+"@"+enc.Version); got != want {
		t.Fatalf("deduped control counted twice in VersionsDigest")
	}

	// The error names both bundles sorted by bundle_id, whatever the digest order.
	for _, d := range []string{sha("cis"), "sha256:" + strings.Repeat("f", 64)} {
		bad := second(t, "bobthecorp-cis", d, bumped([]Control{enc}))
		_, _, err := NewControlSet("bobthecorp", now, trust.NoRevocations(), a, bad)
		want := "bundles bobthecorp-cis and bobthecorp-soc2 disagree on control " + enc.ID + " (aws_db_instance)"
		if err == nil || err.Error() != want {
			t.Errorf("digest %s: got %v, want %q", d, err, want)
		}
	}

	cat := &iampolicy.Catalog{}
	with := func(id, digest, catDigest string) *Bundle {
		b := second(t, id, digest, []Control{enc})
		b.IAMCatalog, b.content = cat, map[string]string{IAMActionsFile: catDigest}
		if catDigest == "" {
			b.IAMCatalog = nil
		}
		return b
	}
	for name, c := range map[string]struct {
		bundles []*Bundle
		kept    bool
	}{
		"same catalog":      {[]*Bundle{with("b1", sha("1"), "sha256:x"), with("b2", sha("2"), "sha256:x")}, true},
		"catalog and none":  {[]*Bundle{with("b1", sha("1"), "sha256:x"), with("b2", sha("2"), "")}, false},
		"conflict stays":    {[]*Bundle{with("b1", sha("1"), "sha256:x"), with("b2", sha("2"), "sha256:y"), with("b3", sha("3"), "sha256:x")}, false},
		"none then catalog": {[]*Bundle{with("b1", sha("1"), ""), with("b2", sha("2"), "sha256:x")}, false},
	} {
		set, _, err := NewControlSet("bobthecorp", now, trust.NoRevocations(), c.bundles...)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := set.IAMCatalog(&enc) != nil; got != c.kept {
			t.Errorf("%s: catalog kept %v, want %v", name, got, c.kept)
		}
	}
}

// TestControlRevokedEveryKind: revocation lookup sees controls without an
// op (data_source, ephemeral), which the op index does not hold.
func TestControlRevokedEveryKind(t *testing.T) {
	expr := "config.secret_id != ''"
	eph := Control{ID: "secret_version_pinned", Version: "2.0.0", Kind: KindEphemeral, ResourceType: "aws_secretsmanager_secret_version",
		Reads: []string{"secret_id"}, Expr: &expr, Action: ActionDeny, Severity: SeverityHigh, Message: "m", ExemptionCoverable: []ExemptionKind{}}
	b := second(t, "bobthecorp-extra", sha("x"), []Control{eph})
	var err error
	if b.Revocations, err = trust.ParseRevocations([]byte(`{"format":"compliancetf.revocations/v1","epoch":3,"revoked_keys":[],"revoked_bundles":[],"revoked_controls":[{"id":"secret_version_pinned","version":2}]}`)); err != nil {
		t.Fatal(err)
	}
	set, _, err := NewControlSet("bobthecorp", now, trust.NoRevocations(), goodBundle(t), b)
	if err != nil {
		t.Fatal(err)
	}
	if !set.ControlRevoked("secret_version_pinned") {
		t.Fatal("revoked ephemeral control not seen")
	}
}

// TestControlSetOfKind: OfKind returns a type's controls of one kind only;
// an ephemeral control is in no op list and a resource control of the same
// type name is not returned for kind ephemeral. Resolve sees every kind.
func TestControlSetOfKind(t *testing.T) {
	expr := "config.secret_id != ''"
	eph := Control{ID: "secret_version_pinned", Version: "2.0.0", Kind: KindEphemeral, ResourceType: "aws_secretsmanager_secret_version",
		Reads: []string{"secret_id"}, Expr: &expr, Action: ActionDeny, Severity: SeverityHigh, Message: "m", ExemptionCoverable: []ExemptionKind{}}
	res := eph
	res.ID, res.Kind, res.On, res.PresenceMode = "secret_version_set", KindResource, []On{OnCreate}, PresenceConfigured
	set, _, err := NewControlSet("bobthecorp", now, trust.NoRevocations(), second(t, "bobthecorp-extra", sha("x"), []Control{eph, res}))
	if err != nil {
		t.Fatal(err)
	}
	ids := func(cs []Control) (out []string) {
		for _, c := range cs {
			out = append(out, c.ID)
		}
		return out
	}
	typ := "aws_secretsmanager_secret_version"
	if got := ids(set.OfKind(KindEphemeral, typ)); !slices.Equal(got, []string{"secret_version_pinned"}) {
		t.Errorf("OfKind(ephemeral) = %v", got)
	}
	if got := ids(set.OfKind(KindResource, typ)); !slices.Equal(got, []string{"secret_version_set"}) {
		t.Errorf("OfKind(resource) = %v", got)
	}
	if got := ids(set.For(typ, OnCreate)); !slices.Equal(got, []string{"secret_version_set"}) {
		t.Errorf("For(create) = %v", got)
	}
	if got := set.OfKind(KindDataSource, typ); len(got) != 0 {
		t.Errorf("OfKind(data_source) = %v", ids(got))
	}
	// An exception reference resolves an ephemeral control too (it is in no op list).
	if got := set.Resolve("secret_version_pinned"); !slices.Equal(got, []string{"secret_version_pinned"}) {
		t.Errorf("Resolve(ephemeral id) = %v", got)
	}
	if got := set.ResolveFold("SECRET_VERSION_PINNED"); !slices.Equal(got, []string{"secret_version_pinned"}) {
		t.Errorf("ResolveFold(ephemeral id) = %v", got)
	}
}

// TestControlSetEmbeddedExpiry: past its grace a bundle fails the set unless
// the embedded loader marked it, which keeps it with a warning.
func TestControlSetEmbeddedExpiry(t *testing.T) {
	late := now.AddDate(5, 0, 0)
	b := goodBundle(t)
	if _, _, err := NewControlSet("bobthecorp", late, trust.NoRevocations(), b); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired bundle: %v", err)
	}
	b.Embedded = true
	if _, warns, err := NewControlSet("bobthecorp", late, trust.NoRevocations(), b); err != nil || len(warns) != 1 {
		t.Fatalf("embedded expired bundle: %v %v", err, warns)
	}
}

// TestResolveFold: the forbid list resolver folds case and
// unions an id match with alias matches; Resolve stays exact.
func TestResolveFold(t *testing.T) {
	a := goodBundle(t) // rds_db_instance_encryption_at_rest_enabled, tool_refs checkov CKV_AWS_16
	twin := Control{ID: "ckv_aws_16", Version: "1.0.0", Kind: KindDeletionGuard, ResourceType: "aws_db_instance", On: []On{"delete"}}
	set, _, err := NewControlSet("bobthecorp", now, trust.NoRevocations(), a, second(t, "bobthecorp-extra", "sha256:"+strings.Repeat("0", 64), []Control{twin}))
	if err != nil {
		t.Fatal(err)
	}
	const enc = "rds_db_instance_encryption_at_rest_enabled"
	for ref, want := range map[string][]string{
		"RDS_DB_INSTANCE_ENCRYPTION_AT_REST_ENABLED": {enc},
		"Ckv_Aws_16": {"ckv_aws_16", enc}, // id of one control, alias of another: both
		"nope":       nil,
	} {
		if got := set.ResolveFold(ref); !slices.Equal(got, want) {
			t.Errorf("ResolveFold(%q) = %v, want %v", ref, got, want)
		}
	}
	if got := set.Resolve("ckv_aws_16"); !slices.Equal(got, []string{"ckv_aws_16"}) {
		t.Errorf("Resolve stays exact and id-first: %v", got)
	}
	if got := set.Resolve("RDS_DB_INSTANCE_ENCRYPTION_AT_REST_ENABLED"); got != nil {
		t.Errorf("Resolve stays case-sensitive: %v", got)
	}
}

// TestControlRevoked: a revoked_controls entry names a loaded
// control at its semver major; another major or id is not revoked.
func TestControlRevoked(t *testing.T) {
	a := goodBundle(t) // rds_db_instance_encryption_at_rest_enabled@2.1.0
	for _, tc := range []struct {
		entry string
		want  bool
	}{
		{`{"id":"rds_db_instance_encryption_at_rest_enabled","version":2}`, true},
		{`{"id":"rds_db_instance_encryption_at_rest_enabled","version":1}`, false},
		{`{"id":"other","version":2}`, false},
	} {
		revs, err := trust.ParseRevocations([]byte(`{"format":"compliancetf.revocations/v1","epoch":1,"revoked_keys":[],"revoked_bundles":[],"revoked_controls":[` + tc.entry + `]}`))
		if err != nil {
			t.Fatal(err)
		}
		set, _, err := NewControlSet("bobthecorp", now, revs, a)
		if err != nil {
			t.Fatal(err)
		}
		if got := set.ControlRevoked("rds_db_instance_encryption_at_rest_enabled"); got != tc.want {
			t.Errorf("%s: revoked %v, want %v", tc.entry, got, tc.want)
		}
	}
	bad := second(t, "bobthecorp-extra", "sha256:"+strings.Repeat("0", 64), []Control{{ID: "odd", Version: "x.1.0", Kind: KindDeletionGuard,
		ResourceType: "aws_db_instance", On: []On{"delete"}}})
	set, _, err := NewControlSet("bobthecorp", now, trust.NoRevocations(), a, bad)
	if err != nil || !set.ControlRevoked("odd") {
		t.Fatalf("unparsable version must fail closed: %v", err)
	}
}
