package trust

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const kidA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func revFile(epoch int, kid, bundle string, below int) []byte {
	return fmt.Appendf(nil, `{"format":"compliancetf.revocations/v1","epoch":%d,
		"revoked_keys":[{"kid":%q,"revoked_at":"2026-05-01T00:00:00Z"}],
		"revoked_bundles":[{"bundle_id":%q,"below_version":%d}],
		"revoked_controls":[{"id":"c-%d","version":1}]}`, epoch, kid, bundle, below, epoch)
}

func mustRev(t testing.TB, epoch int, kid, bundle string, below int) Revocations {
	t.Helper()
	r, err := ParseRevocations(revFile(epoch, kid, bundle, below))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// stateDelta is what writer i contributes.
func stateDelta(t testing.TB, i int) State {
	kid := fmt.Sprintf("sha256:%064x", i)
	return State{
		Bundles:     map[string]int64{"bobthecorp-cis": int64(i), fmt.Sprintf("b%d", i): 1},
		Profiles:    map[string]int64{"bobthecorp": int64(i)},
		Revocations: mustRev(t, i, kid, "bobthecorp-cis", i),
		Floors: map[string]FloorMark{"bobthecorp": {Generation: 1, Epoch: int64(i), RevocationEpoch: int64(i),
			IssuedAt: time.Date(2026, 10, 1, 0, i, 0, 0, time.UTC), RetiredKeys: []string{kid}}},
	}
}

// TestStateHelperProcess is a writer process for TestStateMonotonicConcurrent.
func TestStateHelperProcess(t *testing.T) {
	dir, n := os.Getenv("CTF_STATE_HELPER_DIR"), os.Getenv("CTF_STATE_HELPER_N")
	if dir == "" {
		t.Skip("helper process only")
	}
	i, _ := strconv.Atoi(n)
	if _, err := UpdateState(dir, stateDelta(t, i)); err != nil {
		t.Fatal(err)
	}
}

func TestStateMonotonicConcurrent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	const goroutines, procs = 24, 6
	var wg sync.WaitGroup
	errs := make(chan error, goroutines+procs)
	for i := 1; i <= goroutines; i++ {
		wg.Go(func() {
			if _, err := UpdateState(dir, stateDelta(t, i)); err != nil {
				errs <- err
			}
		})
	}
	for p := 1; p <= procs; p++ {
		i := goroutines + p
		wg.Go(func() {
			cmd := exec.Command(os.Args[0], "-test.run=^TestStateHelperProcess$")
			cmd.Env = append(os.Environ(), "CTF_STATE_HELPER_DIR="+dir, "CTF_STATE_HELPER_N="+strconv.Itoa(i))
			if out, err := cmd.CombinedOutput(); err != nil {
				errs <- fmt.Errorf("helper %d: %v: %s", i, err, out)
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	// A late writer with lower values must not lower anything.
	if _, err := UpdateState(dir, stateDelta(t, 1)); err != nil {
		t.Fatal(err)
	}

	s, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	const top = goroutines + procs
	if got := s.Bundles["bobthecorp-cis"]; got != top {
		t.Errorf("bundle max = %d, want %d", got, top)
	}
	if got := s.Profiles["bobthecorp"]; got != top {
		t.Errorf("profile max = %d, want %d", got, top)
	}
	if got := s.Revocations.Epoch(); got != top {
		t.Errorf("revocation epoch = %d, want %d", got, top)
	}
	f := s.Floors["bobthecorp"]
	if f.Epoch != top || f.RevocationEpoch != top || f.Generation != 1 || len(f.RetiredKeys) != top ||
		!f.IssuedAt.Equal(time.Date(2026, 10, 1, 0, top, 0, 0, time.UTC)) {
		t.Errorf("floor mark = %+v", f)
	}
	for i := 1; i <= top; i++ {
		if s.Bundles[fmt.Sprintf("b%d", i)] != 1 {
			t.Errorf("lost bundle b%d", i)
		}
		if !s.Revocations.KeyRevoked(fmt.Sprintf("sha256:%064x", i)) || !s.Revocations.ControlRevoked(fmt.Sprintf("c-%d", i), 1) {
			t.Errorf("lost revocation from writer %d", i)
		}
	}
	if !s.Revocations.BundleRevoked("bobthecorp-cis", top-1) || s.Revocations.BundleRevoked("bobthecorp-cis", top) {
		t.Error("bundle below_version not merged by max")
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(dir, stateFileName))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("state mode = %v, want 0600", fi.Mode().Perm())
		}
	}
	tmps, _ := filepath.Glob(filepath.Join(dir, ".trust-state-*"))
	if len(tmps) != 0 {
		t.Errorf("leftover temp files: %v", tmps)
	}
}

func TestStateMissingIsEmpty(t *testing.T) {
	s, err := LoadState(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Bundles) != 0 || s.Revocations.Epoch() != 0 || s.Revocations.KeyRevoked(kidA) {
		t.Errorf("missing state not empty: %+v", s)
	}
}

func TestStateCorruptIsKept(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, stateFileName)
	for _, bad := range []string{`{`, "\xff", `{"bundles":{"a":1},"extra":1}`, `{"bundles":{"a":-1}}`,
		`{"revocations":{"epoch":1,"keys":{"nokid":"2026-01-01T00:00:00Z"}}}`} {
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadState(dir); err == nil {
			t.Errorf("LoadState(%s) accepted", bad)
		}
		if _, err := UpdateState(dir, stateDelta(t, 3)); err == nil || errors.Is(err, ErrStateNotSaved) {
			t.Errorf("UpdateState over %s: err = %v, want fatal", bad, err)
		}
		if got, _ := os.ReadFile(path); string(got) != bad {
			t.Errorf("corrupt state overwritten: %s", got)
		}
	}
}

// TestStateCorruptFloorMarks: a stored floor mark that no accepted floor
// statement could have produced fails the load (fail closed) and is never
// overwritten, like any other corrupt state.
func TestStateCorruptFloorMarks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, stateFileName)
	mark := func(org, fields string) string {
		return `{"floors":{"` + org + `":{"generation":1,"epoch":7,"revocation_epoch":0,` +
			`"issued_at":"2026-10-06T00:00:00Z","retired_keys":[]` + fields + `}}}`
	}
	for name, bad := range map[string]string{
		"org id":           mark("Bob The Corp", ""),
		"generation 0":     strings.Replace(mark("bobthecorp", ""), `"generation":1`, `"generation":0`, 1),
		"epoch 0":          strings.Replace(mark("bobthecorp", ""), `"epoch":7`, `"epoch":0`, 1),
		"revocation epoch": strings.Replace(mark("bobthecorp", ""), `"revocation_epoch":0`, `"revocation_epoch":-1`, 1),
		"retired key":      strings.Replace(mark("bobthecorp", ""), `"retired_keys":[]`, `"retired_keys":["nokid"]`, 1),
		"wrapper minimum":  mark("bobthecorp", `,"min_wrapper_version":"latest"`),
		"unrecorded type":  mark("bobthecorp", `,"reset_issued_at":"2026-10-06T01:00:00Z","reset_unrecorded":"yes"`),
		"unrecorded alone": mark("bobthecorp", `,"reset_unrecorded":true`),
		"unrecorded null":  mark("bobthecorp", `,"reset_issued_at":"2026-10-06T01:00:00Z","reset_unrecorded":null`),
		"unrecorded case":  mark("bobthecorp", `,"reset_issued_at":"2026-10-06T01:00:00Z","RESET_Unrecorded":null`),
	} {
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadState(dir); err == nil {
			t.Errorf("%s: LoadState accepted %s", name, bad)
		}
		if _, err := UpdateState(dir, stateDelta(t, 3)); err == nil || errors.Is(err, ErrStateNotSaved) {
			t.Errorf("%s: UpdateState err = %v, want fatal", name, err)
		}
		if got, _ := os.ReadFile(path); string(got) != bad {
			t.Errorf("%s: corrupt state overwritten", name)
		}
	}
	if err := os.WriteFile(path, []byte(mark("bobthecorp", `,"min_wrapper_version":"1.5.0"`)), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := LoadState(dir); err != nil || s.Floors["bobthecorp"].MinWrapperVersion != "1.5.0" {
		t.Fatalf("good mark: %v, %v", s.Floors, err)
	}
}

// TestStateInvalidFloorDelta: a delta whose floor mark could not have come
// from an accepted statement is fatal, never merged-but-not-saved.
func TestStateInvalidFloorDelta(t *testing.T) {
	dir := t.TempDir()
	s, err := UpdateState(dir, State{Floors: map[string]FloorMark{"bobthecorp": {Generation: 1}}})
	if err == nil || errors.Is(err, ErrStateNotSaved) || s.loaded {
		t.Fatalf("invalid floor delta: err = %v, loaded %v; want fatal", err, s.loaded)
	}
}

func TestStateUnwritableDir(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// Not a directory: the existing state cannot be read either, so fatal.
	// Windows reports a path under a regular file as not found: no state,
	// warn and continue, as for a missing dir that cannot be created.
	_, err := UpdateState(filepath.Join(file, "sub"), stateDelta(t, 2))
	if runtime.GOOS == "windows" {
		if !errors.Is(err, ErrStateNotSaved) {
			t.Fatalf("write under a regular file: err = %v, want not saved", err)
		}
	} else if err == nil || errors.Is(err, ErrStateNotSaved) {
		t.Fatalf("write under a regular file: err = %v, want fatal", err)
	}
	// Missing dir that cannot be created: no state exists, so warn and continue.
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions as non-root")
	}
	ro := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	merged, err := UpdateState(filepath.Join(ro, "state"), stateDelta(t, 2))
	if !errors.Is(err, ErrStateNotSaved) {
		t.Fatalf("err = %v, want ErrStateNotSaved", err)
	}
	if merged.Profiles["bobthecorp"] != 2 {
		t.Error("in-memory merge lost the delta")
	}
}

func TestStateRevocationCap(t *testing.T) {
	r := NoRevocations()
	for i := range maxStateRevocations + 1 {
		r.controls[controlRef{"c", int64(i + 1)}] = true
	}
	r.epoch = 1
	dir := t.TempDir()
	if _, err := UpdateState(dir, State{Revocations: r}); err == nil {
		t.Fatal("over-cap revocation set stored")
	}
	if _, err := os.Stat(filepath.Join(dir, stateFileName)); !os.IsNotExist(err) {
		t.Error("over-cap state written")
	}
}

func TestStateDir(t *testing.T) {
	t.Setenv("COMPLIANCETF_STATE_DIR", "/x/y")
	if d, err := StateDir(); err != nil || d != "/x/y" {
		t.Errorf("StateDir = %q, %v", d, err)
	}
	t.Setenv("COMPLIANCETF_STATE_DIR", "")
	d, err := StateDir()
	if err != nil {
		t.Skip(err)
	}
	if filepath.Base(d) != "compliancetf" {
		t.Errorf("default StateDir = %q", d)
	}
}

func TestStateEnvMinimumsRaiseOnly(t *testing.T) {
	s, err := MergeState(State{Bundles: map[string]int64{"cis": 5}, Profiles: map[string]int64{"bobthecorp": 4}}, State{})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		env             string
		bundle, profile int64
		wantErr         bool
	}{
		{"", 5, 4, false},
		{"3", 5, 4, false}, // lower than state: no effect
		{"9", 9, 9, false}, // raises
		{"0", 5, 4, false},
		{"-1", 5, 4, true},
		{"abc", 5, 4, true}, // malformed never silently weakens: error
	}
	for _, c := range cases {
		t.Setenv("COMPLIANCETF_MIN_BUNDLE_VERSION", c.env)
		t.Setenv("COMPLIANCETF_MIN_PROFILE_VERSION", c.env)
		b, errB := s.MinBundleVersion("cis")
		p, errP := s.MinProfileVersion("bobthecorp")
		if (errB != nil || errP != nil) != c.wantErr {
			t.Errorf("env %q: errors %v %v", c.env, errB, errP)
			continue
		}
		if b != c.bundle || p != c.profile {
			t.Errorf("env %q: min bundle %d profile %d, want %d %d", c.env, b, p, c.bundle, c.profile)
		}
	}
	t.Setenv("COMPLIANCETF_MIN_BUNDLE_VERSION", "")
	if b, _ := s.MinBundleVersion("cis", 7, 2); b != 7 {
		t.Errorf("extra floors not applied: %d", b)
	}
}

func TestStateEntryCapNotWritten(t *testing.T) {
	big := State{Bundles: map[string]int64{}}
	for i := range maxStateEntries + 1 {
		big.Bundles[fmt.Sprintf("b%d", i)] = 1
	}
	dir := t.TempDir()
	if _, err := UpdateState(dir, big); err == nil {
		t.Fatal("over-cap state stored")
	}
	if _, err := LoadState(dir); err != nil {
		t.Fatalf("state unreadable after refused write: %v", err)
	}
}

func TestStateReadOnlyDir(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions as non-root")
	}
	dir := t.TempDir()
	if _, err := UpdateState(dir, stateDelta(t, 4)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, stateLockName), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	s, err := LoadState(dir)
	if err != nil || s.Profiles["bobthecorp"] != 4 {
		t.Fatalf("LoadState on read-only dir = %v, %v", s.Profiles, err)
	}
}

func TestStateCaseDistinctIDsReload(t *testing.T) {
	dir := t.TempDir()
	r, err := ParseRevocations([]byte(`{"format":"compliancetf.revocations/v1","epoch":1,
		"revoked_controls":[{"id":"CIS","version":1},{"id":"cis","version":1}]}`))
	if err != nil {
		t.Fatal(err)
	}
	d := State{Bundles: map[string]int64{"CIS": 1, "cis": 2}, Revocations: r}
	if _, err := UpdateState(dir, d); err != nil {
		t.Fatal(err)
	}
	s, err := LoadState(dir)
	if err != nil || s.Bundles["CIS"] != 1 || s.Bundles["cis"] != 2 || !s.Revocations.ControlRevoked("CIS", 1) {
		t.Fatalf("reload = %v, %v", s.Bundles, err)
	}
}

func TestStateLockFailureKeepsDiskState(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions as non-root")
	}
	dir := t.TempDir()
	if _, err := UpdateState(dir, stateDelta(t, 4)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, stateLockName), 0o400); err != nil {
		t.Fatal(err)
	}
	merged, err := UpdateState(dir, State{Bundles: map[string]int64{"new": 1}})
	if !errors.Is(err, ErrStateNotSaved) {
		t.Fatalf("write with unwritable lock: err = %v, want ErrStateNotSaved", err)
	}
	if merged.Profiles["bobthecorp"] != 4 || merged.Bundles["new"] != 1 || !merged.Revocations.KeyRevoked(fmt.Sprintf("sha256:%064x", 4)) {
		t.Errorf("returned state dropped disk state: %+v", merged.Profiles)
	}
}

// TestStateUnreadableFailsClosed: when the existing state cannot be read, no
// error path may hand back a state lower than what is on disk. The returned
// state is unusable (every key revoked, minimums error) and the error is not
// ErrStateNotSaved, so warn-and-continue is impossible.
func TestStateUnreadableFailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions as non-root")
	}
	assertUnusable := func(t *testing.T, s State, err error) {
		t.Helper()
		if err == nil || errors.Is(err, ErrStateNotSaved) {
			t.Fatalf("err = %v, want a fatal (non-ErrStateNotSaved) error", err)
		}
		if !s.Revocations.KeyRevoked("sha256:" + strings.Repeat("e", 64)) {
			t.Error("returned state has a usable (empty) revocation set")
		}
		if _, err := s.MinBundleVersion("bobthecorp-cis"); err == nil {
			t.Error("returned state yields a minimum bundle version")
		}
	}
	t.Run("lock unreadable", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := UpdateState(dir, stateDelta(t, 10)); err != nil {
			t.Fatal(err)
		}
		lock := filepath.Join(dir, stateLockName)
		if err := os.Chmod(lock, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(lock, 0o600) }) //nolint:errcheck // cleanup
		s, err := UpdateState(dir, State{})
		assertUnusable(t, s, err)
	})
	t.Run("state corrupt", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, stateFileName), []byte(`{`), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := UpdateState(dir, stateDelta(t, 3))
		assertUnusable(t, s, err)
	})
}

// TestStateResetUnrecorded: a mark without reset_unrecorded loads
// as false; the flag survives a merge only when every side at the latest
// reset carries it, so a stale delta cannot set it again after a clear;
// ClearUnrecordedReset clears only the named reset.
func TestStateResetUnrecorded(t *testing.T) {
	dir := t.TempDir()
	reset := time.Date(2026, 10, 6, 1, 0, 0, 0, time.UTC)
	base := `{"floors":{"bobthecorp":{"generation":1,"epoch":2,"revocation_epoch":0,` +
		`"issued_at":"2026-10-06T00:00:00Z","retired_keys":[],"reset_issued_at":"2026-10-06T01:00:00Z"%s}}}`
	write := func(extra string) {
		if err := os.WriteFile(filepath.Join(dir, stateFileName), fmt.Appendf(nil, base, extra), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	flag := func() bool {
		s, err := LoadState(dir)
		if err != nil {
			t.Fatal(err)
		}
		return s.Floors["bobthecorp"].ResetUnrecorded
	}
	write("")
	if flag() {
		t.Fatal("missing reset_unrecorded loaded as true")
	}
	write(`,"reset_unrecorded":true`)
	stale, err := LoadState(dir)
	if err != nil || !stale.Floors["bobthecorp"].ResetUnrecorded {
		t.Fatalf("flag not loaded: %v", err)
	}
	if err := ClearUnrecordedReset(dir, "bobthecorp", reset.Add(time.Hour)); err != nil || !flag() {
		t.Fatalf("clear of another reset: %v, flag %v; want kept", err, flag())
	}
	if err := ClearUnrecordedReset(dir, "bobthecorp", reset); err != nil || flag() {
		t.Fatalf("clear: %v, flag %v; want cleared", err, flag())
	}
	if _, err := UpdateState(dir, stale); err != nil || flag() {
		t.Fatalf("stale delta merge: %v, flag %v; want still cleared", err, flag())
	}
	newer := FloorMark{Generation: 1, Epoch: 1, IssuedAt: reset, ResetIssuedAt: reset.Add(time.Hour), ResetUnrecorded: true}
	if m := mergeFloor(FloorMark{Generation: 1, Epoch: 2, ResetIssuedAt: reset}, newer); !m.ResetUnrecorded {
		t.Errorf("newer reset's flag dropped: %+v", m)
	}
}

// TestStatePendingIssuedAt: a revocation-pending statement's issued_at is
// kept apart from the accepted one, so it never advances IssuedAt (the
// air-gap time) but still bounds later statements; an accepted statement at
// or after it clears it. A state file written before the field existed loads
// with IssuedAt as stored, and a state without a pending time encodes
// without the field, so older providers can still read it.
func TestStatePendingIssuedAt(t *testing.T) {
	accepted := time.Date(2026, 10, 6, 1, 0, 0, 0, time.UTC)
	pending := accepted.Add(time.Hour)
	dir := t.TempDir()
	old := `{"floors":{"bobthecorp":{"generation":1,"epoch":7,"revocation_epoch":0,"issued_at":"2026-10-06T01:00:00Z","retired_keys":[]}}}`
	if err := os.WriteFile(filepath.Join(dir, stateFileName), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadState(dir)
	if m := s.Floors["bobthecorp"]; err != nil || !m.IssuedAt.Equal(accepted) || !m.PendingIssuedAt.IsZero() {
		t.Fatalf("old state file: %+v, %v", m, err)
	}
	s, err = UpdateState(dir, State{Floors: map[string]FloorMark{"bobthecorp": {Generation: 1, Epoch: 8, PendingIssuedAt: pending}}})
	if err != nil {
		t.Fatal(err)
	}
	if m := s.Floors["bobthecorp"]; m.Epoch != 8 || !m.IssuedAt.Equal(accepted) || !m.PendingIssuedAt.Equal(pending) || !m.highIssuedAt().Equal(pending) {
		t.Fatalf("after pending: %+v", m)
	}
	if s, err = LoadState(dir); err != nil || !s.Floors["bobthecorp"].PendingIssuedAt.Equal(pending) {
		t.Fatalf("pending not persisted: %+v, %v", s.Floors, err)
	}
	// An older pending delta does not lower it.
	if s, err = UpdateState(dir, State{Floors: map[string]FloorMark{"bobthecorp": {Generation: 1, Epoch: 8, PendingIssuedAt: accepted.Add(time.Minute)}}}); err != nil ||
		!s.Floors["bobthecorp"].PendingIssuedAt.Equal(pending) {
		t.Fatalf("older pending: %+v, %v", s.Floors, err)
	}
	if _, err = UpdateState(dir, State{Floors: map[string]FloorMark{"bobthecorp": {Generation: 1, Epoch: 8, IssuedAt: pending}}}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, stateFileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "pending_issued_at") {
		t.Fatalf("accepted statement at the pending time left the field: %s", data)
	}
	// The epoch of a pending side issued after a reset survives the reset
	// guard, as when the pending time was stored as issued_at.
	reset := accepted.Add(30 * time.Minute)
	m := mergeFloor(FloorMark{Generation: 1, Epoch: 2, IssuedAt: accepted, ResetIssuedAt: reset}, FloorMark{Generation: 1, Epoch: 3, PendingIssuedAt: pending})
	if m.Epoch != 3 || !m.IssuedAt.Equal(accepted) || !m.PendingIssuedAt.Equal(pending) {
		t.Fatalf("pending after reset: %+v", m)
	}
}
