package lifecycle

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/exceptions"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

// exceptionGolden is the self-service setup of stages/exception_*.json: a
// profile scope workspace (empty: untrusted), its self_service list and a
// sidecar file under testdata/stages.
type exceptionGolden struct {
	Sidecar     string   `json:"sidecar"`
	Workspace   string   `json:"workspace"`
	SelfService []string `json:"self_service"`
	NoProfile   bool     `json:"no_profile"`
	// NotCoverable leaves self_service out of the bundle-declared lists of
	// the self_service ids, so no list names self_service for them.
	NotCoverable bool `json:"not_coverable"`
}

// TestExceptionStages runs stages/exception_*.json: an applied self-service
// exception waives fail, unknown and not_evaluable with no diagnostic and an
// excepted evidence result; the sidecar is ignored for non-self-service
// controls, without a profile and without a trusted workspace.
func TestExceptionStages(t *testing.T) {
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	runStages(t, "exception_*.json", func(t *testing.T, g *stageGolden, l *Lifecycle) {
		e := g.Exception
		if e == nil {
			t.Fatal("exception golden without exception setup")
		}
		l.opt.Now = func() time.Time { return now }
		c := *l.cfg
		c.Block.ExceptionsFile = filepath.Join("testdata", "stages", e.Sidecar)
		declared := c.Controls.Coverable()
		if !e.NoProfile {
			c.Table.Exceptions = &profile.Exceptions{SelfService: e.SelfService, MaxLifetimeDays: 180}
			c.Table.SidecarControls = e.SelfService
			if !e.NotCoverable {
				declared = withSelfService(c.Controls, e.SelfService...)
			}
		}
		if e.Workspace != "" {
			c.Table.Workspace = profile.Dim{Value: e.Workspace, Source: "profile"}
		}
		cov, _ := exceptions.NewCoverability(declared, c.Table.Exceptions)
		side, _, err := loadSidecar(c.Block, c.Table, c.Controls, cov, now, exceptions.Clock{})
		if err != nil {
			t.Fatal(err)
		}
		c.Sidecar = side
		l.cfg = &c
	})
}
