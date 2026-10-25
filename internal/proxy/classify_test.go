package proxy

import (
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

var (
	dvNull     = &tfplugin5.DynamicValue{Msgpack: []byte{0xc0}}
	dvJSONNull = &tfplugin5.DynamicValue{Json: []byte(" null ")}
	dvObj      = &tfplugin5.DynamicValue{Msgpack: []byte{0x80}} // empty fixmap
	dvJSONObj  = &tfplugin5.DynamicValue{Json: []byte(`{}`)}
)

func TestClassifyNull(t *testing.T) {
	for _, tc := range []struct {
		dv   *tfplugin5.DynamicValue
		want bool
	}{{nil, true}, {&tfplugin5.DynamicValue{}, true}, {dvNull, true}, {dvJSONNull, true}, {dvObj, false}, {dvJSONObj, false}} {
		if got := isNull(tc.dv); got != tc.want {
			t.Errorf("isNull(%v) = %v, want %v", tc.dv, got, tc.want)
		}
	}
}

func TestClassifyPlan(t *testing.T) {
	for _, tc := range []struct {
		prior, planned *tfplugin5.DynamicValue
		rr             int
		want           hook.Op
	}{
		{dvNull, dvObj, 0, hook.OpCreate},
		{nil, dvJSONObj, 1, hook.OpCreate},
		{dvObj, dvNull, 0, hook.OpDelete},
		{dvObj, dvJSONNull, 1, hook.OpDelete},
		{dvObj, dvObj, 1, hook.OpReplace},
		{dvObj, dvObj, 0, hook.OpUpdate},
		{dvNull, nil, 0, ""},
	} {
		if got := planOp(tc.prior, tc.planned, tc.rr); got != tc.want {
			t.Errorf("planOp(%v, %v, %d) = %q, want %q", tc.prior, tc.planned, tc.rr, got, tc.want)
		}
	}
}

func TestClassifyApply(t *testing.T) {
	env := func(op hook.Op) *hook.EnvelopeHeader {
		h := &hook.EnvelopeHeader{V: 1}
		h.CTF.Op = op
		return h
	}
	for _, tc := range []struct {
		env   *hook.EnvelopeHeader
		apply hook.Op
		want  hook.Op
	}{
		{nil, hook.OpCreate, hook.OpCreate},
		{nil, hook.OpDelete, hook.OpDelete},
		{env(hook.OpUpdate), hook.OpUpdate, hook.OpUpdate},
		{env(hook.OpCreate), hook.OpCreate, hook.OpCreate},
		{env(hook.OpDelete), hook.OpDelete, hook.OpDelete},
		{env(hook.OpReplace), hook.OpCreate, hook.OpReplace},
		{env(hook.OpReplace), hook.OpDelete, hook.OpReplace},
		{env(hook.OpReplace), hook.OpUpdate, hook.OpChange},
		{env(hook.OpUpdate), hook.OpCreate, hook.OpChange},
		{env(hook.OpCreate), hook.OpUpdate, hook.OpChange},
		{env(hook.OpDelete), hook.OpUpdate, hook.OpChange},
		{env(hook.OpImport), hook.OpUpdate, hook.OpUpdate}, // an import combines as update
		{env(hook.OpImport), hook.OpCreate, hook.OpChange},
		{env(hook.OpImport), hook.OpDelete, hook.OpChange},
	} {
		if got := applyOp(tc.env, tc.apply); got != tc.want {
			t.Errorf("applyOp(%v, %q) = %q, want %q", tc.env, tc.apply, got, tc.want)
		}
	}
	if got := planOp(dvObj, dvNull, 0); got != hook.OpDelete {
		t.Errorf("apply-time derivation of delete = %q", got)
	}
}
