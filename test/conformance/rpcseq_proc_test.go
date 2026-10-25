package conformance

import (
	"fmt"
	"regexp"
	"slices"
	"testing"
)

var pidRE = regexp.MustCompile(`"pid":(\d+)`)

// procOrdinals replaces each line's "pid" with "proc", the 1-based order in
// which that provider process first called the hook in the step.
//
// Lines are in file order: each process appends whole lines with O_APPEND, so
// lines never mix, and Core runs its walks of a step (validate, plan, apply)
// one after another, each with its own provider process. The file order is
// then the call order, and the ordinals are deterministic. That holds only
// while processes do not overlap, so a process that calls again after a later
// one started is an error, not a flaky golden.
func procOrdinals(lines []string) ([]string, error) {
	procs := map[string]int{}
	out := make([]string, 0, len(lines))
	for i, l := range lines {
		m := pidRE.FindString(l)
		if m == "" {
			return nil, fmt.Errorf("call %d has no pid: %s", i+1, l)
		}
		n, seen := procs[m]
		switch {
		case !seen:
			n = len(procs) + 1
			procs[m] = n
		case n != len(procs):
			return nil, fmt.Errorf("call %d: provider process %d called again after process %d started; the call order is not deterministic", i+1, n, len(procs))
		}
		out = append(out, pidRE.ReplaceAllLiteralString(l, fmt.Sprintf(`"proc":%d`, n)))
	}
	return out, nil
}

// TestProcOrdinals: pids become first-seen ordinals, and a process that calls
// the hook again after a later process started fails the step.
func TestProcOrdinals(t *testing.T) {
	got, err := procOrdinals([]string{`{"stage":"validate","pid":71}`, `{"stage":"read","pid":90}`, `{"stage":"plan","pid":90}`, `{"stage":"apply_pre","pid":12}`})
	want := []string{`{"stage":"validate","proc":1}`, `{"stage":"read","proc":2}`, `{"stage":"plan","proc":2}`, `{"stage":"apply_pre","proc":3}`}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("got %q, %v; want %q", got, err, want)
	}
	if _, err := procOrdinals([]string{`{"pid":1}`, `{"pid":2}`, `{"pid":1}`}); err == nil {
		t.Fatal("overlapping processes accepted")
	}
	if _, err := procOrdinals([]string{`{"stage":"plan"}`}); err == nil {
		t.Fatal("line without pid accepted")
	}
}
