package evidence

import (
	"slices"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/fetch"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict"
)

// The evidence enums are plain strings; they must equal the names of the
// engine and profile types they record, in order. State and Mode are iota
// enums from zero whose MarshalText fails past the last value; a gap would
// truncate the walk and show up as a mismatch against the full list.
func TestEnumsMatchEngineAndProfile(t *testing.T) {
	var gotStates []string
	for s := engine.State(0); ; s++ {
		b, err := s.MarshalText()
		if err != nil {
			break
		}
		gotStates = append(gotStates, string(b))
	}
	if !slices.Equal(gotStates, states) {
		t.Errorf("engine states %v, evidence states %v", gotStates, states)
	}

	var gotModes []string
	for m := profile.Mode(0); ; m++ {
		b, err := m.MarshalText()
		if err != nil {
			break
		}
		gotModes = append(gotModes, string(b))
	}
	if !slices.Equal(gotModes, modes) {
		t.Errorf("profile modes %v, evidence modes %v", gotModes, modes)
	}

	// Go cannot enumerate string constants, so these lists name every
	// engine constant; a new one fails to match until it is added both here
	// and in the evidence enum.
	engineOps := []engine.Op{engine.OpCreate, engine.OpUpdate, engine.OpReplace, engine.OpDelete,
		engine.OpNoOp, engine.OpImport, engine.OpRefresh, engine.OpChange, engine.OpOpen, engine.OpRead}
	if !slices.Equal(toStrings(engineOps), ops) {
		t.Errorf("engine ops %v, evidence ops %v", engineOps, ops)
	}
	engineClasses := []engine.ErrClass{engine.ErrTypeError, engine.ErrLimit, engine.ErrTimeout,
		engine.ErrNoSuchAttribute, engine.ErrUnresolved, engine.ErrScopeUntrusted}
	if !slices.Equal(toStrings(engineClasses), errClasses) {
		t.Errorf("engine err classes %v, evidence err classes %v", engineClasses, errClasses)
	}
	if !slices.Equal(fetch.SkipReasons, skipReasons) {
		t.Errorf("fetch skip reasons %v, evidence skip reasons %v", fetch.SkipReasons, skipReasons)
	}
	if src := []string{bundle.SourceEmbedded, bundle.SourceLocal, bundle.SourceFetched, bundle.SourceCache}; !slices.Equal(src, bundleSources) {
		t.Errorf("bundle sources %v, evidence bundle sources %v", src, bundleSources)
	}
	sit := []string{verdict.SitPass, verdict.SitFail, verdict.SitNotEvaluable, verdict.SitPending, verdict.SitExcepted,
		verdict.SitUnproven, verdict.SitMissing, verdict.SitNoMatch, verdict.SitCollision, verdict.SitNoVerdict}
	if !slices.Equal(sit, situations) {
		t.Errorf("verdict situations %v, evidence situations %v", sit, situations)
	}
}

func toStrings[T ~string](vs []T) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = string(v)
	}
	return out
}
