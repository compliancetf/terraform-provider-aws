// Command ctfbundle builds, signs and verifies compliance.tf bundles and
// signed payloads (profiles, floor statements, floor resets, exception grants).
//
//	ctfbundle build  -src DIR -key KEY -out NAME.tar.gz
//	ctfbundle sign   -type profile|floor|floor-reset|exception-grant -in FILE -key KEY -out FILE.dsse.json
//	ctfbundle verify FILE.tar.gz|FILE.dsse.json
//	ctfbundle tamper -src DIR -key test:bundle -out DIR   (ctftest builds: oracle fixtures)
//	ctfbundle sigbugs -src DIR -out DIR                   (ctftest builds: signature rejection set)
//
// KEY is a PKCS#8 PEM private key (ES256, or Ed25519 for dev), or in ctftest
// builds a derived test key: test:bundle, test:profile, test:floor. verify checks against
// the embedded keyring (plus keyring_test.json under ctftest); it applies no
// revocations, which reach the provider only through merged trust state.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "ctfbundle:", err)
		os.Exit(1)
	}
}

const usage = "usage: ctfbundle build|sign|verify (see go doc ./cmd/ctfbundle)"

func run(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	src := fs.String("src", "", "bundle source directory (build)")
	in := fs.String("in", "", "payload JSON file (sign)")
	kind := fs.String("type", "", "payload kind (sign)")
	keySpec := fs.String("key", "", "signing key")
	out := fs.String("out", "", "output file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "build", "sign":
		key, err := loadKey(*keySpec)
		if err != nil {
			return fmt.Errorf("-key: %w", err)
		}
		if *out == "" {
			return errors.New("-out is required")
		}
		var data []byte
		if args[0] == "build" {
			data, err = build(*src, key)
		} else {
			var payload []byte
			if payload, err = os.ReadFile(*in); err == nil {
				data, err = signPayload(*kind, payload, key)
			}
		}
		if err != nil {
			return err
		}
		return os.WriteFile(*out, data, 0o644) //nolint:gosec // signed artifacts are public
	case "tamper":
		return tamperCmd(*src, *keySpec, *out)
	case "sigbugs":
		return sigbugsCmd(*src, *out)
	case "verify":
		if fs.NArg() != 1 {
			return errors.New("verify takes one file")
		}
		return verifyFile(fs.Arg(0), stdout)
	}
	return errors.New(usage)
}
