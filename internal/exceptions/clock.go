package exceptions

import (
	"fmt"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// CodeAirgapTimeUnknown rejects every grant when floor_mode is airgap and no
// accepted floor statement gives the air-gap time (GrantError code only).
const CodeAirgapTimeUnknown = "exception_airgap_time_unknown"

// Clock is the time exceptions are checked against.
// The zero Clock is the local run clock (online). Under
// floor_mode airgap it is the issued_at of the latest accepted floor
// statement in the trust state, and the process clock is never read: key
// window, expiry, the issued_at skew, max_lifetime_days and the plan-time
// re-check all use it. An unknown Clock applies no exception.
type Clock struct {
	airgap bool
	at     time.Time
	why    string // non-empty: unknown
}

// NewClock builds the run's exceptions clock from the floor modes (the
// resolved profile's floor_mode and the mode the floor was obtained in), the
// trust state returned after the floor and the run org. A value other than
// "", online or airgap makes it unknown; else any airgap makes it airgap,
// timed by Floors[orgID].IssuedAt (never ResetIssuedAt); no org, no mark or a
// zero issued_at is unknown.
func NewClock(st trust.State, orgID string, modes ...string) Clock {
	airgap, invalid := floorModes(modes...)
	if invalid != "" {
		return Clock{why: fmt.Sprintf("floor_mode %q is not online or airgap; check the org profile and the floor statement", invalid)}
	}
	if !airgap {
		return Clock{}
	}
	if m, ok := st.Floors[orgID]; orgID != "" && ok && !m.IssuedAt.IsZero() {
		return Clock{airgap: true, at: m.IssuedAt.UTC()}
	}
	return Clock{airgap: true, why: "air-gap time unknown; import a floor statement"}
}

// floorModes classifies the run's floor modes: invalid is
// the first value other than "", online or airgap; airgap is true when any
// value is airgap. NewClock and NewCoverability share it.
func floorModes(modes ...string) (airgap bool, invalid string) {
	for _, m := range modes {
		switch m {
		case "", trust.FloorOnline:
		case trust.FloorAirgap:
			airgap = true
		default:
			if invalid == "" {
				invalid = m
			}
		}
	}
	return airgap, invalid
}

// resolve returns the check time for the local run clock, or why when the
// clock is unknown (the time is then zero and must not be compared).
func (c Clock) resolve(local time.Time) (time.Time, string) {
	switch {
	case c.why != "":
		return time.Time{}, c.why
	case c.airgap:
		return c.at, ""
	}
	return local, ""
}

// ref names the check time in error text: "" for the local clock.
func (c Clock) ref() string {
	if c.airgap && c.why == "" {
		return " at the air-gap time " + c.at.Format(time.RFC3339) + " (import a newer floor statement to advance it)"
	}
	return ""
}
