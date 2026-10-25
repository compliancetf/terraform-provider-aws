//go:build !ctftest

package main

import (
	"crypto"
	"errors"
)

func testKey(string) (crypto.Signer, error) {
	return nil, errors.New("test keys need a ctftest build (go run -tags ctftest)")
}

func tamperCmd(string, string, string) error {
	return errors.New("tamper needs a ctftest build (go run -tags ctftest)")
}

func sigbugsCmd(string, string) error {
	return errors.New("sigbugs needs a ctftest build (go run -tags ctftest)")
}
