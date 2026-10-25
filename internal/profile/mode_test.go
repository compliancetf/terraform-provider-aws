package profile

import "testing"

func TestParseMode(t *testing.T) {
	order := []string{"advisory", "soft_fail", "grandfather", "hard_fail"}
	for i, s := range order {
		m, err := ParseMode(s)
		if err != nil || m != Mode(i) || m.String() != s {
			t.Errorf("ParseMode(%q) = %v, %v", s, m, err)
		}
	}
	if max(SoftFail, Advisory, HardFail) != HardFail {
		t.Error("mode order broken")
	}
	_, err := ParseMode("HARD_FAIL")
	want := `enforcement_mode "HARD_FAIL": want advisory, soft_fail, grandfather or hard_fail`
	if err == nil || err.Error() != want {
		t.Errorf("err = %v, want %s", err, want)
	}
}
