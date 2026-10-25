package verdict

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func unsetenv(t *testing.T, name string) {
	t.Helper()
	t.Setenv(name, "") // restores the old value on cleanup
	if err := os.Unsetenv(name); err != nil {
		t.Fatal(err)
	}
}

// TestLazyLoadsOnce: the first Load reads the environment and files, later
// Loads return the same outcome even after the environment changes, and
// concurrent first applies load once.
func TestLazyLoadsOnce(t *testing.T) {
	t.Setenv(EnvVerdict, filepath.Join(t.TempDir(), "absent.json"))
	var z Lazy
	calls := 0
	in := func() Input { calls++; return Input{} }
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); z.Load(in) }() //nolint:errcheck // checked below
	}
	wg.Wait()
	unsetenv(t, EnvVerdict)
	v, err := z.Load(in)
	if calls != 1 || v != nil || err == nil || err.(*Error).Summary != SummaryInvalid {
		t.Fatalf("calls %d, verdict %v, err %v", calls, v, err)
	}
}

// TestLazyPanicFailsClosed: a panic during the first load is a sticky load
// failure, never verdict none on later applies.
func TestLazyPanicFailsClosed(t *testing.T) {
	var z Lazy
	v, err := z.Load(func() Input { panic("boom") })
	want := &Error{Summary: SummaryInvalid, Detail: "The verdict could not be loaded."}
	for i := range 2 {
		if e, ok := err.(*Error); v != nil || !ok || *e != *want {
			t.Fatalf("load %d: verdict %v, err %v", i, v, err)
		}
		v, err = z.Load(func() Input { return Input{} })
	}
}
