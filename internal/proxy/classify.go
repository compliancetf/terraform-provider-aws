package proxy

// classify.go derives the resource change operation from the nullness of the
// prior and planned values (no decode) and combines the plan-time op from the
// envelope with the one apply sees. The result is evidence for the hook; 0B
// selects blocking controls from the RPC shape, never from the op alone.

import (
	"bytes"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

// isNull reports whether dv is absent or encodes a null value.
func isNull(dv *tfplugin5.DynamicValue) bool {
	if dv == nil {
		return true
	}
	if len(dv.Msgpack) > 0 {
		return len(dv.Msgpack) == 1 && dv.Msgpack[0] == 0xc0 // msgpack nil
	}
	j := bytes.TrimSpace(dv.Json)
	return len(j) == 0 || string(j) == "null"
}

// planOp classifies a change; requiresReplace is the number of
// requires_replace paths (0 at apply). Both null gives "": Terraform never
// applies such an instance, so nothing is stamped.
func planOp(prior, planned *tfplugin5.DynamicValue, requiresReplace int) hook.Op {
	switch p, n := isNull(prior), isNull(planned); {
	case p && n:
		return ""
	case p:
		return hook.OpCreate
	case n:
		return hook.OpDelete
	case requiresReplace > 0:
		return hook.OpReplace
	default:
		return hook.OpUpdate
	}
}

// applyOp combines the envelope op with the apply-derived op: equal -> that
// op; a planned replace seen as its create or delete half -> replace;
// anything else -> change. Without an envelope the apply op stands. A
// planned import is the update of a pre-existing object, so it combines as
// update: the stamp never changes the op the hook sees.
func applyOp(env *hook.EnvelopeHeader, op hook.Op) hook.Op {
	if env == nil {
		return op
	}
	e := env.CTF.Op
	if e == hook.OpImport {
		e = hook.OpUpdate
	}
	switch {
	case e == op:
		return op
	case e == hook.OpReplace && (op == hook.OpCreate || op == hook.OpDelete):
		return hook.OpReplace
	default:
		return hook.OpChange
	}
}
