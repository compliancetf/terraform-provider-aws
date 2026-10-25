//go:build !record

package proxy

import (
	"context"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

// recordApply is the instance_key fixture recorder; release builds carry none.
func recordApply(context.Context, *server5, *tfplugin5.ApplyResourceChange_Request, *hook.EnvelopeHeader) {
}
