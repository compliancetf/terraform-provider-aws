// Package profile holds the org profile and the normative mode table
// (modetable.go). Mode lives here so lifecycle can import it
// without a cycle.
package profile

import "fmt"

// Mode is an enforcement mode. The numeric order is the strictness order
// advisory < soft_fail < grandfather < hard_fail, so the builtin max raises.
type Mode uint8

const (
	Advisory Mode = iota
	SoftFail
	Grandfather
	HardFail
)

var modeNames = [...]string{Advisory: "advisory", SoftFail: "soft_fail", Grandfather: "grandfather", HardFail: "hard_fail"}

// ParseMode parses an enforcement_mode string.
func ParseMode(s string) (Mode, error) {
	for i, n := range modeNames {
		if n == s {
			return Mode(i), nil
		}
	}
	return 0, fmt.Errorf("enforcement_mode %q: want advisory, soft_fail, grandfather or hard_fail", s)
}

// ParseDataSources parses a data_sources setting: unset
// and advisory are false, deny is true.
func ParseDataSources(s string) (bool, error) {
	switch s {
	case "", "advisory":
		return false, nil
	case "deny":
		return true, nil
	}
	return false, fmt.Errorf("data_sources %q: want advisory or deny", s)
}

func (m Mode) String() string {
	if int(m) < len(modeNames) {
		return modeNames[m]
	}
	return fmt.Sprintf("Mode(%d)", uint8(m))
}

func (m Mode) MarshalText() ([]byte, error) {
	if int(m) >= len(modeNames) {
		return nil, fmt.Errorf("invalid mode %d", uint8(m))
	}
	return []byte(modeNames[m]), nil
}

func (m *Mode) UnmarshalText(b []byte) error {
	v, err := ParseMode(string(b))
	if err != nil {
		return err
	}
	*m = v
	return nil
}
