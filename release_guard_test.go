//go:build !conformance

package main

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/embedded"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/lifecycle"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/wrapper"
)

// releaseBlocker returns why ev must not ship in a release: anything but
// the lifecycle evaluator enforces no compliance control.
func releaseBlocker(ev hook.Evaluator) error {
	if h, ok := ev.(lifecycle.Hook); !ok || h.Lifecycle == nil {
		return fmt.Errorf("main.go serves %T, not the compliance lifecycle: this build enforces no compliance control; wire lifecycle.Hook before tagging a release", ev)
	}
	return nil
}

func TestReleaseBlocker(t *testing.T) {
	for _, ev := range []hook.Evaluator{nil, hook.Noop{}, &hook.Noop{}, struct{ hook.Noop }{}, lifecycle.Hook{}} {
		if releaseBlocker(ev) == nil {
			t.Errorf("%T passed the release guard", ev)
		}
	}
	if err := releaseBlocker(lifecycle.Hook{Lifecycle: lifecycle.New(lifecycle.Options{})}); err != nil {
		t.Errorf("the lifecycle failed the release guard: %v", err)
	}
}

// keyringBlocker returns why a release keyring must not ship: without a
// bundle key the embedded CIS bundle cannot verify, so every Configure fails
// closed.
func keyringBlocker(keys []trust.Key) error {
	for _, k := range keys {
		if k.Purpose == trust.PurposeBundle {
			return nil
		}
	}
	return errors.New("the release keyring (internal/trust/keyring.json) has no bundle key: the embedded CIS bundle cannot verify and every Configure fails; add the production bundle key and re-sign internal/embedded/cis.tar.gz before tagging a release")
}

func TestKeyringBlocker(t *testing.T) {
	for name, keys := range map[string][]trust.Key{
		"empty":        nil,
		"floor only":   {{Purpose: trust.PurposeFloor, Generation: 1}, {Purpose: trust.PurposeFloor, Generation: 2}},
		"no bundle":    {{Purpose: trust.PurposeProfile}, {Purpose: trust.PurposeException}},
		"purpose typo": {{Purpose: "bundles"}},
	} {
		if keyringBlocker(keys) == nil {
			t.Errorf("%s: keyring without a bundle key passed the release guard", name)
		}
	}
	if err := keyringBlocker([]trust.Key{{Purpose: trust.PurposeFloor}, {Purpose: trust.PurposeBundle}}); err != nil {
		t.Errorf("keyring with a bundle key failed the release guard: %v", err)
	}
}

// TestReleaseGuard fails unless the release inputs load, the release build
// wires the compliance lifecycle and the release keyring verifies the
// embedded CIS bundle.
// release.yml and releasegate run it with COMPLIANCETF_RELEASE_GUARD=1.
func TestReleaseGuard(t *testing.T) {
	if os.Getenv("COMPLIANCETF_RELEASE_GUARD") != "1" {
		t.Skip("set COMPLIANCETF_RELEASE_GUARD=1 (release.yml does)")
	}
	cfg, err := wrapper.Load(wrapperJSON, pins, [][]byte{hashicorpKey}, embedded.Archive())
	if err != nil {
		t.Fatalf("wrapper.Load of the embedded inputs: %v", err)
	}
	ev, err := wrapper.Evaluator(cfg, "", "")
	if err != nil {
		t.Fatalf("evaluator: %v", err)
	}
	if err := releaseBlocker(ev); err != nil {
		t.Fatal(err)
	}
	kr, err := trust.Embedded()
	if err != nil {
		t.Fatalf("release keyring: %v", err)
	}
	if err := keyringBlocker(kr.Keys()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := embedded.CIS(time.Now(), trust.NoRevocations()); err != nil {
		t.Fatalf("the release keyring does not verify the embedded CIS bundle, so every Configure fails: %v", err)
	}
}
