package main

import (
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/embedded"
	"github.com/compliancetf/terraform-provider-aws/internal/wrapper"
)

// TestEmbeddedInputsLoad: the inputs main embeds pass wrapper.Load,
// so a build that serves anything has a valid aws wrapper config.
func TestEmbeddedInputsLoad(t *testing.T) {
	cfg, err := wrapper.Load(wrapperJSON, pins, [][]byte{hashicorpKey}, embedded.Archive())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Address.String() != "registry.compliance.tf/compliancetf/aws" || cfg.Upstream.String() != "registry.terraform.io/hashicorp/aws" || cfg.EvidenceSink != wrapper.SinkS3ObjectLock {
		t.Fatalf("config %s / %s / %s", cfg.Address, cfg.Upstream, cfg.EvidenceSink)
	}
}
