package main

import (
	_ "embed"
	"log"

	"github.com/compliancetf/terraform-provider-aws/internal/embedded"
	"github.com/compliancetf/terraform-provider-aws/internal/wrapper"
)

// The wrapper inputs: wrapper.Load checks them together before anything is
// served. The CIS archive is the build's copy (release or ctftest signed).
// pins.json and keys/ sit at the repo root, both protected paths.
var (
	//go:embed wrapper.json
	wrapperJSON []byte
	//go:embed pins.json
	pins []byte
	//go:embed keys/hashicorp-security.asc
	hashicorpKey []byte
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	log.Printf("compliance.tf provider %s (commit: %s, built: %s)", version, commit, date)
	cfg, err := wrapper.Load(wrapperJSON, pins, [][]byte{hashicorpKey}, embedded.Archive())
	if err != nil {
		log.Fatalf("[FATAL] %s", err)
	}
	if err := wrapper.Serve(cfg, version, commit); err != nil {
		log.Fatalf("[FATAL] %s", err)
	}
}
