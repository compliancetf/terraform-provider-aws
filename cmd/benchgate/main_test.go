package main

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// bench is go test -bench output: one BenchmarkP99 line per p99, with
// noise lines around it.
func bench(p99s ...time.Duration) string {
	var b strings.Builder
	b.WriteString("goos: darwin\ngoarch: arm64\npkg: github.com/compliancetf/terraform-provider-aws/test/bench\n")
	for _, p := range p99s {
		fmt.Fprintf(&b, "BenchmarkP99-12   \t       3\t 412345678 ns/op\t       103 controls\t        17 not-evaluable\t   %d p99-ns/resource\t       500 resources\n", p)
	}
	b.WriteString("PASS\nok  \tgithub.com/compliancetf/terraform-provider-aws/test/bench\t12.3s\n")
	return b.String()
}

func writeBaseline(t *testing.T, p99 time.Duration) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "x.json")
	raw := fmt.Sprintf(`{"runner_class":"x","p99_ns":%d,"resources":500,"controls":103}`, p99)
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func gateRun(t *testing.T, base string, out string, extra ...string) (int, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(append([]string{"-baseline", base, "-in", "-"}, extra...), strings.NewReader(out), &stdout, &stderr)
	return code, stdout.String() + stderr.String()
}

// TestGateRule is the oracle on synthetic numbers, so it does not
// depend on machine load: the median of the runs passes at 1.19x and 1.20x
// the baseline and fails at 1.21x; at any ratio a p99 above 50 ms fails.
func TestGateRule(t *testing.T) {
	for _, c := range []struct {
		name      string
		base, p99 time.Duration
		pass      bool
	}{
		{"1.00x", time.Millisecond, time.Millisecond, true},
		{"1.19x", time.Millisecond, 1190 * time.Microsecond, true},
		{"1.20x", time.Millisecond, 1200 * time.Microsecond, true},
		{"1.21x", time.Millisecond, 1210 * time.Microsecond, false},
		{"1.25x", time.Millisecond, 1250 * time.Microsecond, false},
		{"50 ms at 1.11x", 45 * time.Millisecond, 50 * time.Millisecond, true},
		{"above 50 ms at 1.02x", 49 * time.Millisecond, 50*time.Millisecond + time.Microsecond, false},
		{"above 50 ms at 1.00x", 60 * time.Millisecond, 60 * time.Millisecond, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			// nine runs: four far below, four far above, the median is c.p99
			runs := []time.Duration{c.p99}
			for range 4 {
				runs = append(runs, c.p99/4, c.p99*4)
			}
			code, out := gateRun(t, writeBaseline(t, c.base), bench(runs...), "-count", "9")
			if (code == 0) != c.pass {
				t.Errorf("exit %d, want pass %v: %s", code, c.pass, out)
			}
		})
	}
	if Check(time.Millisecond, Baseline{}) == nil {
		t.Error("a zero baseline must fail the gate")
	}
}

// TestGateInput: no results, another benchmark, a malformed row, a row
// without positive iterations, a non-integral or non-positive count, the wrong
// run count, disagreeing runs, a count mismatch with the baseline and a
// missing baseline fail; a name-only line and a name without the -N suffix
// are fine; an even run count takes the mean of the middle two.
func TestGateInput(t *testing.T) {
	base := writeBaseline(t, time.Millisecond)
	ten := bench(time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond,
		time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond)
	if code, out := gateRun(t, base, ten); code != 0 {
		t.Fatalf("ten runs, default -count: exit %d: %s", code, out)
	}
	one := bench(time.Millisecond)
	row := strings.Split(one, "\n")[3]
	cut, _, _ := strings.Cut(row, "p99-ns")
	for _, c := range []struct{ name, in, want string }{
		{"no results", "PASS\n", "0 BenchmarkP99 runs"},
		{"nine of ten runs", strings.Replace(ten, row+"\n", "", 1), "9 BenchmarkP99 runs in the benchmark output, want 10"},
		{"another benchmark", ten + strings.Replace(row, "BenchmarkP99-12", "BenchmarkLargePlan-12", 1) + "\n", "a result of BenchmarkLargePlan"},
		{"a prefixed name", ten + strings.Replace(row, "BenchmarkP99-12", "BenchmarkP99Old-12", 1) + "\n", "a result of BenchmarkP99Old"},
		{"truncated row", strings.Replace(ten, row, cut, 1), "malformed"},
		{"zero iterations", strings.Replace(ten, row, strings.Replace(row, "\t       3\t", "\t       0\t", 1), 1), "malformed"},
		{"negative iterations", strings.Replace(ten, row, strings.Replace(row, "\t       3\t", "\t      -3\t", 1), 1), "malformed"},
		{"fractional resources", strings.Replace(ten, "500 resources", "500.5 resources", 1), "resources 500.5 is not a positive integer"},
		{"zero controls", strings.Replace(ten, "103 controls", "0 controls", 1), "controls 0 is not a positive integer"},
		{"negative resources", strings.Replace(ten, "500 resources", "-500 resources", 1), "resources -500 is not a positive integer"},
		{"NaN controls", strings.Replace(ten, "103 controls", "NaN controls", 1), "controls NaN is not a positive integer"},
		{"zero p99", strings.Replace(ten, "1000000 p99-ns", "0 p99-ns", 1), "is not a positive duration"},
		{"NaN p99", strings.Replace(ten, "1000000 p99-ns", "NaN p99-ns", 1), "is not a positive duration"},
		{"negative p99", strings.Replace(ten, "1000000 p99-ns", "-1000000 p99-ns", 1), "is not a positive duration"},
		{"2^63 p99", strings.Replace(ten, "1000000 p99-ns", "9223372036854775808 p99-ns", 1), "is not a positive duration"},
		{"Inf p99", strings.Replace(ten, "1000000 p99-ns", "+Inf p99-ns", 1), "is not a positive duration"},
		{"no p99 metric", strings.Replace(ten, row, strings.Replace(row, "p99-ns/resource", "x-ns/resource", 1), 1), "want p99-ns/resource"},
		{"disagreeing runs", strings.Replace(ten, "500 resources", "499 resources", 1), "run 2"},
		{"control count mismatch", strings.ReplaceAll(ten, "103 controls", "104 controls"), "re-record"},
	} {
		if code, out := gateRun(t, base, c.in); code != 1 || !strings.Contains(out, c.want) {
			t.Errorf("%s: exit %d, want 1 and %q: %s", c.name, code, c.want, out)
		}
	}
	if code, out := gateRun(t, filepath.Join(t.TempDir(), "none.json"), one, "-count", "1"); code != 1 || !strings.Contains(out, "this run: p99 1ms") {
		t.Errorf("missing baseline: exit %d: %s", code, out)
	}
	lenient := "BenchmarkP99\n" + strings.Replace(one, "BenchmarkP99-12", "BenchmarkP99", 1)
	if code, out := gateRun(t, base, lenient, "-count", "1"); code != 0 {
		t.Errorf("name-only line and no -N suffix: exit %d: %s", code, out)
	}
	got, err := Summarize([]Sample{{P99: 1, Resources: 1}, {P99: 4, Resources: 1}, {P99: 2, Resources: 1}, {P99: 100, Resources: 1}})
	if err != nil || got.P99 != 3 {
		t.Errorf("median of 1, 2, 4, 100: %v (%v), want 3", got.P99, err)
	}
	big := time.Duration(math.MaxInt64)
	got, err = Summarize([]Sample{{P99: big - 1, Resources: 1}, {P99: big - 3, Resources: 1}})
	if err != nil || got.P99 != big-2 {
		t.Errorf("median of MaxInt64-1 and MaxInt64-3: %v (%v), want %v", got.P99, err, big-2)
	}
}

// TestGateUpdate: -update writes a baseline the gate then passes against,
// and refuses to record a p99 above 50 ms.
func TestGateUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "darwin-arm64.json")
	runs := bench(2*time.Millisecond, time.Millisecond, 3*time.Millisecond)
	if code, out := gateRun(t, path, runs, "-count", "3", "-update", "-note", "idle laptop"); code != 0 {
		t.Fatalf("update: exit %d: %s", code, out)
	}
	b, err := LoadBaseline(path)
	if err != nil || b != (Baseline{RunnerClass: "darwin-arm64", P99Ns: int64(2 * time.Millisecond), Resources: 500, Controls: 103, Note: "idle laptop"}) {
		t.Fatalf("baseline %+v (%v)", b, err)
	}
	if code, out := gateRun(t, path, runs, "-count", "3"); code != 0 {
		t.Errorf("gate against the new baseline: exit %d: %s", code, out)
	}
	slow := filepath.Join(t.TempDir(), "slow.json")
	if code, out := gateRun(t, slow, bench(51*time.Millisecond), "-count", "1", "-update"); code != 1 || !strings.Contains(out, "not recording") {
		t.Errorf("update above 50 ms: exit %d: %s", code, out)
	}
	if _, err := os.Stat(slow); !os.IsNotExist(err) {
		t.Errorf("update above 50 ms wrote %s (%v)", slow, err)
	}
}

// TestGateBaselines: every committed baseline loads and is named after its
// runner class.
func TestGateBaselines(t *testing.T) {
	files, _ := filepath.Glob("../../test/bench/baseline/*.json")
	if len(files) == 0 {
		t.Fatal("no committed baseline")
	}
	for _, f := range files {
		b, err := LoadBaseline(f)
		if err != nil {
			t.Fatal(err)
		}
		if b.RunnerClass+".json" != filepath.Base(f) || b.Resources <= 0 || b.Controls <= 0 || b.Note == "" {
			t.Errorf("%s: runner_class %q, %d resources, %d controls, note %q", f, b.RunnerClass, b.Resources, b.Controls, b.Note)
		}
		if err := Check(time.Duration(b.P99Ns), b); err != nil {
			t.Errorf("%s: the baseline fails its own gate: %v", f, err)
		}
	}
	bad := filepath.Join(t.TempDir(), "x.json")
	if err := os.WriteFile(bad, []byte(`{"runner_class":"x","p99_ns":0}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBaseline(bad); err == nil || !strings.Contains(err.Error(), "p99_ns") {
		t.Errorf("zero p99_ns baseline: %v", err)
	}
}

// TestMakeBenchNote: make bench-gate UPDATE=1 hands BENCH_NOTE to benchgate
// as one argument, quotes and dollar signs included, from the command line or
// the environment. A stub go on PATH records the benchgate arguments, so no
// benchmark runs.
func TestMakeBenchNote(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("no make")
	}
	dir := t.TempDir()
	args := filepath.Join(dir, "args")
	stub := "#!/bin/sh\nif [ \"$2\" = ./cmd/benchgate ]; then printf '%s\\n' \"$@\" > \"$ARGS_OUT\"; fi\n"
	if err := os.WriteFile(filepath.Join(dir, "go"), []byte(stub), 0o700); err != nil {
		t.Fatal(err)
	}
	pwned := filepath.Join(dir, "pwned")
	note := `idle M3 "quoted" $HOME $$ $(x) $(shell touch ` + pwned + `) ` + "`echo x` it's"
	t.Cleanup(func() {
		if _, err := os.Stat(pwned); err == nil {
			t.Error("make expanded $(shell ...) in BENCH_NOTE")
		}
	})
	env := []string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "ARGS_OUT=" + args, "HOME=" + dir}
	for _, c := range []struct {
		name     string
		env, cli []string
	}{
		{"command line", nil, []string{"BENCH_NOTE=" + note}},
		{"environment", []string{"BENCH_NOTE=" + note}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			// A stale file from the previous subtest must not pass this one.
			if err := os.Remove(args); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			cmd := exec.Command("make", append([]string{"-s", "-C", "../..", "bench-gate", "UPDATE=1"}, c.cli...)...)
			cmd.Env = append(slices.Clone(env), c.env...)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("make bench-gate: %v: %s", err, out)
			}
			raw, err := os.ReadFile(args)
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
			if i := slices.Index(got, "-note"); i < 0 || i+1 >= len(got) || got[i+1] != note {
				t.Errorf("benchgate args %q, want -note %q", got, note)
			}
		})
	}
}

// TestMakeRawVars: RUN, TF, BENCH_COUNT and AWS_SCHEMA_VERSION reach the
// conformance, bench-gate and schema-subset recipes as typed, from the command
// line or the environment; make expands none of them. Stub go and jq on PATH
// record what the recipes pass and a failing terraform stub stops the capture
// script, so no test, benchmark or download runs.
func TestMakeRawVars(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("no make")
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	stubs := map[string]string{
		"go": "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$STUB_OUT\"\n",
		"jq": "#!/bin/sh\nprintf '%s\\n' \"$AWS_SCHEMA_VERSION\" >> \"$STUB_OUT\"\n",
		// A valid version gets past the check; the capture stops at init.
		"terraform": "#!/bin/sh\nexit 1\n",
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	pwned := filepath.Join(dir, "pwned")
	val := `a 'q' "d" $HOME $$ $(x) $(shell touch ` + pwned + `) ` + "`echo x`"
	t.Cleanup(func() {
		if _, err := os.Stat(pwned); err == nil {
			t.Error("make expanded $(shell ...) in a variable")
		}
	})
	env := []string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "STUB_OUT=" + out, "HOME=" + dir}
	tf := filepath.Join(dir, "terraform") // the default TF is terraform on PATH
	for _, c := range []struct {
		target, name string
		vars         []string
		want         [][]string // consecutive lines the stubs record
		failOK       bool
		noUpdate     bool // the recorded lines must not hold -update
	}{
		{"conformance", "RUN TF", []string{"RUN=" + val, "TF=" + val}, [][]string{{"-run", "(?i)" + val}, {"-tf", val}}, false, false},
		{"conformance", "defaults", nil, [][]string{{"./test/conformance/...", "-tf", tf}}, false, true},
		{"conformance", "UPDATE=1", []string{"UPDATE=1"}, [][]string{{"-tf", tf, "-update"}}, false, false},
		// Any non-empty UPDATE rewrites the conformance goldens, as before.
		{"conformance", "UPDATE", []string{"UPDATE=" + val}, [][]string{{"-tf", tf, "-update"}}, false, false},
		{"bench-gate", "BENCH_COUNT", []string{"BENCH_COUNT=" + val}, [][]string{{"-count", val}}, false, false},
		{"bench-gate", "defaults", nil, [][]string{{"-count", "10"}}, false, true},
		{"bench-gate", "UPDATE=1", []string{"UPDATE=1"}, [][]string{{"-count", "10", "-update", "-note", ""}}, false, false},
		// Only UPDATE=1 rewrites the bench baseline, as before.
		{"bench-gate", "UPDATE", []string{"UPDATE=" + val}, [][]string{{"-count", "10"}}, false, true},
		{"schema-subset", "AWS_SCHEMA_VERSION", []string{"AWS_SCHEMA_VERSION=" + val}, [][]string{{val}}, true, false},
		{"schema-subset", "defaults", nil, [][]string{{"6.67.0"}}, true, false},
	} {
		for _, from := range []string{"command line", "environment"} {
			if c.vars == nil && from == "environment" {
				continue
			}
			t.Run(c.target+" "+c.name+" "+from, func(t *testing.T) {
				// A stale file from the previous subtest must not pass this one.
				if err := os.Remove(out); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
				args := []string{"-s", "-C", "../..", c.target}
				cmdEnv := slices.Clone(env)
				if from == "command line" {
					args = append(args, c.vars...)
				} else {
					cmdEnv = append(cmdEnv, c.vars...)
				}
				cmd := exec.Command("make", args...)
				cmd.Env = cmdEnv
				if b, err := cmd.CombinedOutput(); err != nil && !c.failOK {
					t.Fatalf("make %s: %v: %s", c.target, err, b)
				}
				raw, err := os.ReadFile(out)
				if err != nil {
					t.Fatal(err)
				}
				got := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
				if c.noUpdate && slices.Contains(got, "-update") {
					t.Errorf("recorded %q, want no -update", got)
				}
				for _, w := range c.want {
					if !hasRun(got, w) {
						t.Errorf("recorded %q, want the lines %q", got, w)
					}
				}
			})
		}
	}
}

// hasRun reports whether want appears in got as consecutive elements.
func hasRun(got, want []string) bool {
	for i := range got {
		if i+len(want) <= len(got) && slices.Equal(got[i:i+len(want)], want) {
			return true
		}
	}
	return false
}
