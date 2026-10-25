package lifecycle

import (
	"context"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
)

// dataSource evaluates the data_source controls of a read:
// configured controls on Config, effective controls on New. A control's
// effective action is warn unless it is deny and data_sources is deny; the
// mode table and the plan column then apply to that action. A value that is
// absent, null or does not decode makes the controls bound to it
// not_evaluable (fail row): a Go error here only warns, so it must
// not stand in for a failure.
func (l *Lifecycle) dataSource(ctx context.Context, c *Configured, req *hook.Request) (*hook.Result, error) {
	if c == nil || c.Controls == nil {
		// An error diagnostic, not a Go error: the proxy turns that into a
		// warning at data_source, and the read would pass unchecked.
		return &hook.Result{Diagnostics: []hook.Diagnostic{{Severity: hook.SeverityError,
			Summary: "Compliance not configured",
			Detail:  "Data source " + req.TypeName + " was read before the compliance configuration loaded; the read is blocked."}}}, nil
	}
	null := tftypes.NewValue(tftypes.DynamicPseudoType, nil)
	value := func(v *hook.Value) (tftypes.Value, bool) {
		got, err := get(v)
		if v == nil || err != nil {
			return null, false
		}
		return got, !got.IsNull()
	}
	config, configOK := value(req.Config)
	newState, newOK := value(req.New)
	unbound := engine.Outcome{State: engine.NotEvaluable, Err: engine.ErrUnresolved}
	col := &collected{}
	controls := c.Controls.OfKind(bundle.KindDataSource, req.TypeName)
	for i := range controls {
		ctl := controls[i] // a copy: the effective action never reaches the set
		if ctl.Action != bundle.ActionDeny || !c.Table.DataSourcesDeny {
			ctl.Action = bundle.ActionWarn
		}
		a := &engine.Activation{Resource: newState, Config: config, Prior: null, Op: engine.OpRead}
		ok := newOK
		if ctl.PresenceMode == bundle.PresenceConfigured {
			a.Resource, ok = config, configOK
		}
		col.preset = nil
		if !ok {
			col.preset = &unbound
		}
		l.check(ctx, c, StageDataSource, &ctl, a, "", "", col)
	}
	// The record names no resource id: a data source result is no managed
	// object (never an inventory source) and its id can echo query values.
	col.diags = append(col.diags, l.record(c, req, StageDataSource, engine.OpRead, null, col.results, false, false)...)
	return &hook.Result{Diagnostics: col.diags}, nil
}
