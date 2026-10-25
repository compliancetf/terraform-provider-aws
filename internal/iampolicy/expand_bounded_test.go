//go:build !windows

package iampolicy

import (
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestGrantsAllBounded: grants_all answers from the expanded sets, so a
// statement of many patterns costs one lookup per service action, not a
// glob per pattern (5,000 x 5,000 globs took ~200 ms in one CEL call).
// It bounds process CPU time, not wall time: other load on the machine
// stretches wall time but not the CPU this call uses.
func TestGrantsAllBounded(t *testing.T) {
	c := genCatalog(t, 5000)
	pats := make([]string, 5000)
	for i := range pats {
		pats[i] = fmt.Sprintf(`"svc:a%05d"`, i)
	}
	p, err := Normalize(policy(`{"Effect":"Allow","Action":[`+strings.Join(pats, ",")+`],"Resource":"*"}`), Options{Catalog: c})
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC() // no mark work from the setup inside the measurement
	start := cpuTime(t)
	ok, err := GrantsAll(p.Statements[0], c, "svc")
	if took := cpuTime(t) - start; !ok || err != nil || took > 50*time.Millisecond {
		t.Fatalf("GrantsAll = %v, %v in %v CPU", ok, err, took)
	}
}

// cpuTime is the user and system CPU time this process has used.
func cpuTime(t *testing.T) time.Duration {
	t.Helper()
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		t.Fatal(err)
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}
