// Package iampolicy normalizes AWS IAM policy documents into the fixed shape
// that CEL controls read through iam.parse. Stdlib only, no CEL import: internal/engine/lib imports
// this package. Error text carries constant reason codes, never document
// content (value-free output invariant).
package iampolicy

import "errors"

var (
	// ErrInvalid: malformed or ambiguous document (engine class type_error).
	ErrInvalid = errors.New("iampolicy: invalid")
	// ErrLimit: a size, depth, count, expansion or admission bound was hit
	// (engine class limit).
	ErrLimit = errors.New("iampolicy: limit")
	// ErrUnresolved: a catalog miss in Grants / GrantsAll (engine class
	// unresolved). internal/engine/lib maps it to lib.ErrUnresolved.
	ErrUnresolved = errors.New("iampolicy: unresolved")
)

// Reason codes. Closed list: goldens pin them and FuzzNormalize checks that
// every error Normalize returns uses one of these.
const (
	rPartition          = "partition_invalid"
	rDocSize            = "doc_size"
	rDepth              = "depth"
	rStatementCount     = "statement_count"
	rJSON               = "json_invalid"
	rDuplicateKey       = "duplicate_key"
	rUTF8               = "invalid_utf8"
	rTopLevel           = "top_level"
	rVersion            = "version"
	rStatement          = "statement"
	rStatementKey       = "statement_key"
	rSid                = "sid"
	rEffect             = "effect"
	rActionElement      = "action_element"
	rActionValue        = "action_value"
	rAction             = "action"
	rPrincipalElement   = "principal_element"
	rPrincipalValue     = "principal_value"
	rPrincipalType      = "principal_type"
	rPrincipalWildcard  = "principal_wildcard"
	rPrincipalVariable  = "principal_variable"
	rNotPrincipalStar   = "not_principal_wildcard"
	rResourceElement    = "resource_element"
	rResourceValue      = "resource_value"
	rCondition          = "condition"
	rConditionOperator  = "condition_operator"
	rConditionOpDup     = "condition_operator_dup"
	rConditionKey       = "condition_key"
	rConditionKeyDup    = "condition_key_dup"
	rConditionValue     = "condition_value"
	rAdmission          = "admission"
	rExpanded           = "expanded_actions"
	rCatalog            = "catalog_invalid"
	rCatalogMiss        = "catalog_miss"
	rCatalogMismatch    = "catalog_mismatch"
	rUnresolvedActions  = "unresolved_actions"
	rUnresolvedIdentity = "unresolved_identity"
)

var reasons = []string{
	rPartition, rDocSize, rDepth, rStatementCount, rJSON, rDuplicateKey, rUTF8,
	rTopLevel, rVersion, rStatement, rStatementKey, rSid, rEffect,
	rActionElement, rActionValue, rAction, rPrincipalElement, rPrincipalValue,
	rPrincipalType, rPrincipalWildcard, rPrincipalVariable, rNotPrincipalStar,
	rResourceElement, rResourceValue, rCondition, rConditionOperator,
	rConditionOpDup, rConditionKey, rConditionKeyDup, rConditionValue,
	rAdmission, rExpanded, rCatalog, rCatalogMiss, rCatalogMismatch, rUnresolvedActions, rUnresolvedIdentity,
}

// Error is a failure of this package: ErrInvalid, ErrLimit or ErrUnresolved
// plus a reason code.
type Error struct {
	err    error
	Reason string
}

func (e *Error) Error() string { return e.err.Error() + ": " + e.Reason }
func (e *Error) Unwrap() error { return e.err }

// Class is the engine error class: "limit", "unresolved" or "type_error".
func (e *Error) Class() string {
	switch e.err {
	case ErrLimit:
		return "limit"
	case ErrUnresolved:
		return "unresolved"
	}
	return "type_error"
}

func invalid(reason string) error { return &Error{ErrInvalid, reason} }
func limit(reason string) error   { return &Error{ErrLimit, reason} }

func unresolved(reason string) error { return &Error{ErrUnresolved, reason} }
