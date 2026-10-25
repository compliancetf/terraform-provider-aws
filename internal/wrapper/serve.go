package wrapper

import (
	"context"
	"fmt"
	"log"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/lifecycle"
	"github.com/compliancetf/terraform-provider-aws/internal/proxy"
	"github.com/compliancetf/terraform-provider-aws/internal/upstream"
)

// Serve finds, verifies and starts the pinned cfg.Upstream, then serves the
// provider until Terraform ends it, when it returns nil. Any error is
// returned before serving starts. cfg must come from Load.
func Serve(cfg Config, version, commit string) error {
	log.Printf("[INFO] %s %s (commit: %s), upstream %s", cfg.Address.ForDisplay(), version, commit, cfg.Upstream.ForDisplay())
	src, err := upstream.NewSource(cfg.Upstream)
	if err != nil {
		return err
	}
	bin, err := upstream.Discover(context.Background(), src, cfg.UpstreamPins, cfg.TrustAnchors)
	if err != nil {
		return err
	}
	log.Printf("[INFO] Starting upstream provider: %s", bin.Path())
	u, err := upstream.Launch(context.Background(), bin, nil)
	if err != nil {
		return fmt.Errorf("failed to start upstream provider: %w", err)
	}
	defer u.Close()
	if u.Protocol != cfg.Protocol {
		return fmt.Errorf("upstream %s %s speaks protocol %d; this release serves protocol %d", u.Name, u.Version, u.Protocol, cfg.Protocol)
	}
	ev, err := Evaluator(cfg, version, u.Version)
	if err != nil {
		return err
	}
	proxy.Serve(proxy.Backends{Upstream: u.Conn, UpstreamName: u.Name, UpstreamSHA256: u.SHA256, OnTransportErr: u.TransportErr, Evaluator: ev})
	return nil
}

// lifecycleHook is the lifecycle evaluator for cfg, the evaluator release
// builds serve.
func lifecycleHook(cfg Config, version, upstreamVersion string) hook.Evaluator {
	return lifecycle.Hook{Lifecycle: lifecycle.New(lifecycle.Options{
		ProviderVersion: version,
		ProviderAddress: cfg.Address.String(),
		WrapperName:     cfg.Address.Namespace + "/" + cfg.Address.Type,
		UpstreamName:    cfg.Upstream.Namespace + "/" + cfg.Upstream.Type,
		UpstreamVersion: upstreamVersion,
		CISBundle:       cfg.CISBundle,
	})}
}
