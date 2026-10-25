// Package lib holds the CEL function libraries of the control engine.
// Functions return these sentinels wrapped
// in a CEL error; celeng classifies by identity, never by text.
package lib

import "errors"

var (
	// ErrLimit: a document or expansion bound was hit (class limit).
	ErrLimit = errors.New("lib: limit exceeded")
	// ErrInvalid: invalid CIDR, JSON, policy or duplicate JSON key (class type_error).
	ErrInvalid = errors.New("lib: invalid input")
	// ErrUnresolved: IAM catalog miss, identity alias, partial wildcard or
	// unknown queried identity (class unresolved).
	ErrUnresolved = errors.New("lib: unresolved")
)
