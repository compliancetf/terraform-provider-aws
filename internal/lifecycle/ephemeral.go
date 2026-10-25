package lifecycle

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
)

// ephemeralOpen evaluates the ephemeral controls of the type on the
// OpenEphemeralResource request config, before the proxy forwards it
// An error diagnostic blocks the open, so no
// secret is opened; the result is never an input. The record is written
// before the forward, fsynced under evidence.required, and a required write
// failure blocks the open as at apply_pre.
func (l *Lifecycle) ephemeralOpen(ctx context.Context, c *Configured, req *hook.Request) (*hook.Result, error) {
	if c == nil || c.Controls == nil {
		return nil, errors.New("lifecycle: ephemeral open before Configure")
	}
	if req.Config == nil {
		return nil, errors.New("lifecycle: ephemeral open request without config")
	}
	config, err := req.Config.Get()
	if err != nil {
		return nil, fmt.Errorf("lifecycle: config: %w", err)
	}
	// Resource binds the config, as for a configured control: the program
	// compiles against its type, and ephemeral controls read config only.
	null := tftypes.NewValue(tftypes.DynamicPseudoType, nil)
	col := &collected{}
	controls := c.Controls.OfKind(bundle.KindEphemeral, req.TypeName)
	for i := range controls {
		a := &engine.Activation{Resource: config, Config: config, Prior: null, Op: engine.OpOpen}
		l.check(ctx, c, StageEphemeralOpen, &controls[i], a, "", "", col)
	}
	col.diags = append(col.diags, l.record(c, req, StageEphemeralOpen, engine.OpOpen, null, col.results, false, evidenceRequired(c))...)
	return &hook.Result{Diagnostics: col.diags}, nil
}
