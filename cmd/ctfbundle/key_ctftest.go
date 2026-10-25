//go:build ctftest

package main

import (
	"crypto"
	"fmt"

	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

func testKey(name string) (crypto.Signer, error) {
	switch name {
	case "bundle":
		return testkeys.Bundle(), nil
	case "profile":
		return testkeys.Profile(), nil
	case "floor":
		return testkeys.Floor(), nil
	}
	return nil, fmt.Errorf("unknown test key %q (want bundle, profile or floor)", name)
}
