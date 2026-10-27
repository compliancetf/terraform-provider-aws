package trust

import (
	"crypto"
	"errors"
	"strings"
	"testing"
	"time"
)

var floorNow = time.Date(2026, 10, 6, 6, 0, 0, 0, time.UTC)

const floorTestDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func loadedState(t *testing.T, floors map[string]FloorMark) State {
	t.Helper()
	s, err := MergeState(State{Floors: floors}, State{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestFloorAcceptance covers the floor statement checks and the high-water
// acceptance table with floor keys of generations 1, 2 and 3.
func TestFloorAcceptance(t *testing.T) {
	k1, k2, k3 := newP256(t), newP256(t), newP256(t)
	kr := mustKeyring(t, keyringBytes(floorEntry(t, k1, 1, nb, na), floorEntry(t, k2, 2, nb, na), floorEntry(t, k3, 3, nb, na)), false)
	kid1, kid2 := KIDFromSPKI(spki(t, k1)), KIDFromSPKI(spki(t, k2))
	issued := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	mark := func(gen, epoch, rev int64, retired ...string) map[string]FloorMark {
		return map[string]FloorMark{"bobthecorp": {Generation: gen, Epoch: epoch, RevocationEpoch: rev, IssuedAt: issued, RetiredKeys: retired}}
	}
	set := func(kv ...any) func(map[string]any) {
		return func(p map[string]any) {
			for i := 0; i < len(kv); i += 2 {
				p[kv[i].(string)] = kv[i+1]
			}
		}
	}
	cases := []struct {
		name    string
		key     crypto.Signer
		mut     func(map[string]any)
		raw     string // payload used instead of floorStatement when set
		marks   map[string]FloorMark
		mode    string
		noState bool
		want    string // error substring; "" accepts
	}{
		{name: "first statement", key: k1},
		{name: "same statement again", key: k1, marks: mark(1, 7, 0)},
		{name: "next generation, newer epoch", key: k2, mut: set("epoch", 8), marks: mark(1, 7, 0)},
		{name: "next generation, same epoch", key: k2, marks: mark(1, 7, 0), want: "floor epoch 7 is below the accepted high-water 7"},
		{name: "generation skip", key: k3, mut: set("epoch", 8), marks: mark(1, 7, 0), want: "below the accepted high-water"},
		{name: "older generation", key: k1, mut: set("epoch", 9), marks: mark(2, 8, 0), want: "is retired for bobthecorp: accepted generation 2"},
		{name: "kid retired in state", key: k2, mut: set("epoch", 8), marks: mark(1, 7, 0, kid2), want: "floor key " + kid2 + " (generation 2) is retired"},
		{name: "older epoch", key: k1, mut: set("epoch", 6), marks: mark(1, 7, 0), want: "floor epoch 6 is below the accepted high-water 7 for bobthecorp"},
		{name: "issued earlier", key: k1, mut: set("epoch", 8, "issued_at", "2026-10-05T23:00:00Z", "expires_at", "2026-10-06T23:00:00Z"), marks: mark(1, 7, 0), want: "is earlier than the accepted 2026-10-06T00:00:00Z"},
		{name: "issued before a pending statement", key: k1, mut: set("issued_at", "2026-10-05T23:00:00Z", "expires_at", "2026-10-06T23:00:00Z"),
			marks: map[string]FloorMark{"bobthecorp": {Generation: 1, Epoch: 7, IssuedAt: issued.Add(-2 * time.Hour), PendingIssuedAt: issued}},
			want:  "is earlier than the accepted 2026-10-06T00:00:00Z"},
		{name: "drops retired key", key: k1, mut: set("epoch", 8), marks: mark(1, 7, 0, kid2), want: "drops retired key " + kid2},
		{name: "next generation retires the old key", key: k2, mut: set("epoch", 8, "retired_keys", []string{kid1}), marks: mark(1, 7, 0)},
		{name: "old key retires the next", key: k1, mut: set("epoch", 8, "retired_keys", []string{kid2}), marks: mark(1, 7, 0), want: "signed by generation 1 retires a key of generation 2"},
		{name: "own key listed retired", key: k2, mut: set("epoch", 8, "retired_keys", []string{kid2}), want: "which it lists as retired"},
		{name: "revocation epoch below high-water", key: k1, mut: set("revocation_epoch", 1), marks: mark(1, 7, 2), want: "below the accepted high-water"},
		{name: "revocation epoch pending", key: k1, mut: set("revocation_epoch", 3), want: "needs revocation epoch 3, provider has 0"},
		{name: "corrupt mark", key: k1, marks: mark(0, 0, 0), want: "corrupt"},
		{name: "state not loaded", key: k1, noState: true, want: "not loaded"},
		{name: "no mode", key: k1, mode: "none", want: "floor_mode"},
		{name: "wrong org", key: k1, mut: set("org_id", "alicecorp"), want: `floor is for another org, not "bobthecorp"`},
		{name: "issued in the future", key: k1, mut: set("issued_at", "2026-10-06T07:00:00Z"), want: "in the future"},
		{name: "unsorted retired keys", key: k1, mut: set("retired_keys", []string{kid2, kid2}), want: "sorted, unique"},
		{name: "unknown field", key: k1, mut: set("floor_mode", "airgap"), want: "wrong shape"},
		{name: "missing field", key: k1, mut: func(p map[string]any) { delete(p, "retired_keys") }, want: "required"},
		{name: "duplicate member", key: k1, raw: strings.Replace(string(floorStatement(floorTestDigest, nil)), `"epoch":7`, `"epoch":7,"Epoch":9`, 1), want: "duplicate"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			payload := floorStatement(floorTestDigest, c.mut)
			if c.raw != "" {
				payload = []byte(c.raw)
			}
			in := FloorInput{OrgID: "bobthecorp", Mode: FloorOnline, ProviderVersion: "2.0.0", Now: floorNow, Revs: NoRevocations()}
			if !c.noState {
				in.State = loadedState(t, c.marks)
			}
			if c.mode != "" {
				in.Mode = c.mode
			}
			f, delta, err := kr.verifyFloor(sign(t, PayloadFloor, payload, c.key), in, floorTestDigest)
			if c.want != "" {
				if err == nil || !strings.Contains(err.Error(), c.want) {
					t.Fatalf("err = %v, want %q", err, c.want)
				}
				// A pending statement keeps only its high-water.
				if f != nil || delta.Floors != nil && !errors.Is(err, ErrFloorRevocationPending) {
					t.Fatal("rejected statement returned a floor or delta")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			m := delta.Floors["bobthecorp"]
			if m.Generation != f.Generation || m.Epoch != f.Epoch || !m.IssuedAt.Equal(issued) ||
				delta.Bundles["cis-aws"] != 5 || delta.Profiles["bobthecorp"] != 7 {
				t.Fatalf("delta %+v", delta)
			}
		})
	}
	t.Run("pending is a sentinel", func(t *testing.T) {
		in := FloorInput{OrgID: "bobthecorp", Mode: FloorOnline, ProviderVersion: "2.0.0", Now: floorNow, Revs: NoRevocations(), State: loadedState(t, nil)}
		_, delta, err := kr.verifyFloor(sign(t, PayloadFloor, floorStatement(floorTestDigest, set("revocation_epoch", 1)), k1), in, floorTestDigest)
		if !errors.Is(err, ErrFloorRevocationPending) {
			t.Fatal(err)
		}
		// The pending delta pins (generation, epoch, pending issued_at) only:
		// its issued_at never becomes the accepted one (the air-gap time).
		if m := delta.Floors["bobthecorp"]; m.Generation != 1 || m.Epoch != 7 || !m.IssuedAt.IsZero() || !m.PendingIssuedAt.Equal(issued) ||
			m.RevocationEpoch != 0 || m.RetiredKeys != nil || delta.Bundles != nil || delta.Profiles != nil {
			t.Fatalf("pending delta %+v", delta)
		}
	})
}

func TestFloorReleaseFloorAndPin(t *testing.T) {
	if rf, err := EmbeddedReleaseFloor(); err != nil || rf.Bundles == nil {
		t.Fatal(rf, err)
	}
	for _, bad := range []string{``, `{}`, `{"bundles":{},"min_profile_version":-1}`, `{"bundles":{"CIS":1},"min_profile_version":0}`,
		`{"bundles":{"cis-aws":0},"min_profile_version":0}`, `{"bundles":{},"min_profile_version":0,"x":1}`} {
		if _, err := parseReleaseFloor([]byte(bad)); err == nil {
			t.Errorf("release floor %s accepted", bad)
		}
	}
	if p, err := parseOrgPin([]byte(`{"org_id":"bobthecorp","governed":true}`)); err != nil || p.OrgID != "bobthecorp" {
		t.Fatal(p, err)
	}
	for _, bad := range []string{``, `{}`, `{"org_id":"bobthecorp"}`, `{"org_id":"bobthecorp","governed":false}`,
		`{"org_id":"bobthecorp","governed":true,"x":1}`, `{"org_id":"Bob","governed":true}`} {
		if _, err := parseOrgPin([]byte(bad)); err == nil {
			t.Errorf("org pin %s accepted", bad)
		}
	}
	if p, err := OrgPin(); p != nil || err != nil {
		t.Fatal("default build has an org pin")
	}
}

func TestGovernedNeedsFloor(t *testing.T) {
	s := loadedState(t, nil)
	verified := &Floor{OrgID: "bobthecorp", MinProfileVersion: 3, Bundles: map[string]int64{"cis-aws": 5}, mode: FloorOnline}
	forged := *verified
	forged.mode = ""
	for name, f := range map[string]Floors{
		"governed":         {OrgID: "bobthecorp", Mode: FloorOnline, Governed: true},
		"bundles required": {OrgID: "bobthecorp", Mode: FloorAirgap, FloorRequired: true},
		"not from Verify":  {OrgID: "bobthecorp", Mode: FloorOnline, Governed: true, Statement: &forged},
		"other mode":       {OrgID: "bobthecorp", Mode: FloorAirgap, Governed: true, Statement: verified},
		"other org":        {OrgID: "alicecorp", Mode: FloorOnline, Governed: true, Statement: verified},
	} {
		if _, err := s.EffectiveBundleMin("cis-aws", f); err == nil || !strings.Contains(err.Error(), "governed runs need a signed floor statement") {
			t.Errorf("%s: %v", name, err)
		}
	}
	f := Floors{OrgID: "bobthecorp", Mode: FloorOnline, Governed: true, Statement: verified,
		Release: ReleaseFloor{Bundles: map[string]int64{"cis-aws": 4}}, Profile: map[string]int64{"cis-aws": 2}, Manifest: map[string]int64{"cis-aws": 6}}
	if v, err := s.EffectiveBundleMin("cis-aws", f); err != nil || v != 6 {
		t.Fatal(v, err)
	}
	if v, err := s.EffectiveProfileMin(f); err != nil || v != 3 {
		t.Fatal(v, err)
	}
	if v, err := s.EffectiveBundleMin("cis-aws", Floors{OrgID: "bobthecorp"}); err != nil || v != 0 {
		t.Fatal("free run:", v, err)
	}
}
