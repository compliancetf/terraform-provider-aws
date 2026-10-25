// Package breakglass verifies the compliance.tf-signed break-glass consume
// receipts a verified verdict embeds and answers which (control, action key)
// decisions they downgrade. It
// replaces the "no override is honored" stub; the
// COMPLIANCETF_BREAK_GLASS rejection stays.
//
// Fail closed: a receipt that fails any check is dropped with a value-free
// warning and its controls stay enforced; it never fails the verdict. No
// check reads the local clock (E10): times are the receipt's consumed_at and
// expires_at against the verdict's issued_at and expires_at.
//
// Decisions of the design panel beyond the spec's honor list, all
// stricter: the receipt carries format compliancetf.consume-receipt/v1 (the
// same key signs approvals and approver statements); the receipt key must be
// valid at both consumed_at and the verdict issued_at; receipt plan_digest
// equals the verdict's; consumed_at is no later than the verdict issued_at
// plus Skew; the floor must have been obtained online; a duplicate
// override_id drops every receipt carrying it; the post-drop coverability
// gate is checked in Honor. run_id, override_digest and
// predecessor_receipt_digest are signed and shape-checked only.
package breakglass

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict"
)

// Format is the receipt format.
const Format = "compliancetf.consume-receipt/v1"

var (
	reDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// reToken is the evidence record token: override_id becomes
	// results[].break_glass_id, control ids are evidence controls.
	reToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// Receipt is a compliancetf.consume-receipt/v1 document. Every member is
// strict: an unknown, missing or case-variant member, a number, bool or
// null, or a duplicate member rejects it.
type Receipt struct {
	Format                   string            `json:"format"`
	OverrideID               string            `json:"override_id"`
	OverrideDigest           string            `json:"override_digest"`
	OrgID                    string            `json:"org_id"`
	RunID                    string            `json:"run_id"`
	RequestDigest            string            `json:"request_digest"`
	Controls                 []string          `json:"controls"`
	InstanceKeys             []string          `json:"instance_keys"`
	PlanDigest               string            `json:"plan_digest"`
	ConsumedAt               string            `json:"consumed_at"`
	ExpiresAt                string            `json:"expires_at"`
	PredecessorReceiptDigest string            `json:"predecessor_receipt_digest,omitempty"`
	Signature                verdict.Signature `json:"signature"`
}

// Policy is the run's break-glass context, built at Configure.
type Policy struct {
	Profile   *profile.Profile // the floor-validated profile; nil honors nothing
	FloorMode string           // the mode the floor was obtained in ("" when none)
	// Revocations is the merged bundle revocations: a receipt kid listed
	// there is revoked as one in revoked_kids; the zero value
	// revokes every kid.
	Revocations trust.Revocations
	// Coverable is the post-drop Coverability.Coverable(id, "break_glass"),
	// the only break-glass coverability gate; nil covers nothing.
	Coverable func(control string) bool
}

// Unavailable is "" when receipts can be honored, else why not (fixed
// text): break_glass.enabled, profile floor_mode online (or unset under a
// governed online floor), the floor obtained online, and receipt_keys.
func (p Policy) Unavailable() string {
	switch pr := p.Profile; {
	case pr == nil:
		return "no signed profile applies"
	case pr.BreakGlass == nil || !pr.BreakGlass.Enabled:
		return "the profile does not enable break_glass"
	case pr.FloorMode != "" && pr.FloorMode != profile.FloorOnline:
		return "the profile floor_mode is not online"
	case p.FloorMode != profile.FloorOnline:
		return "the floor was not obtained online"
	case len(pr.BreakGlass.ReceiptKeys) == 0:
		return "the profile lists no break_glass.receipt_keys"
	}
	return ""
}

// Enabled reports whether the signed profile enables break_glass under
// floor_mode online (the profile's, and the mode the floor was obtained in):
// plan eligibility. Unlike Unavailable it needs no receipt key, as
// plan never needs the artifact.
func (p Policy) Enabled() bool {
	pr := p.Profile
	return pr != nil && pr.BreakGlass != nil && pr.BreakGlass.Enabled &&
		(pr.FloorMode == "" || pr.FloorMode == profile.FloorOnline) && p.FloorMode == profile.FloorOnline
}

// Override is an honored receipt: ID is its override_id (evidence
// results[].break_glass_id), ReceiptDigest the sha256 over JCS of the whole
// receipt.
type Override struct{ ID, ReceiptDigest string }

type scope struct{ control, key string }

// Set is the honored scope of one verified verdict. The zero Set and a nil
// *Set honor nothing.
type Set struct {
	by        map[scope][]Override // every honored receipt of the scope, in verdict order
	coverable func(string) bool
}

// Honor returns the overrides, in verdict order, of every honored receipt
// that lists the control and the action key (instance_key, or delete_key
// for a destroy half), when the control's signed coverable list holds
// break_glass after the airgap drop and result is fail, not_evaluable or
// provisional; none for pass, pending and any other result. Every candidate
// is kept, so the caller picks the first one the matched entries list and
// an unlisted receipt never shadows a listed one.
func (s *Set) Honor(control, actionKey, result string) []Override {
	switch {
	case s == nil || s.coverable == nil:
		return nil
	case result != "fail" && result != "not_evaluable" && result != "provisional":
		return nil
	case !s.coverable(control):
		return nil
	}
	return slices.Clone(s.by[scope{control, actionKey}])
}

// Len is the number of (control, action key) pairs some honored receipt
// covers.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.by)
}

type parsed struct {
	r      Receipt
	signed []byte
	digest string
}

// Verify checks the receipts v embeds under p. It returns the honored set
// and one warning per dropped receipt (or one when p honors none). v must
// be a verified verdict; nil honors nothing.
func Verify(p Policy, v *verdict.Verdict) (*Set, []string) {
	set := &Set{by: map[scope][]Override{}, coverable: p.Coverable}
	if v == nil || len(v.Doc.BreakGlassReceipts) == 0 {
		return set, nil
	}
	n := len(v.Doc.BreakGlassReceipts)
	if why := p.Unavailable(); why != "" {
		return set, []string{fmt.Sprintf("The verdict embeds %d break-glass receipt(s); none is honored because %s. Their controls stay enforced.", n, why)}
	}
	issued, err1 := parseUTC(v.Doc.IssuedAt)
	expires, err2 := parseUTC(v.Doc.ExpiresAt)
	if err1 != nil || err2 != nil || slices.Contains([]string{v.Doc.OrgID, v.Doc.Workspace, v.Doc.Environment, v.Doc.PlanDigest, v.Doc.ContentDigest, v.Doc.FloorEpoch}, "") {
		return set, []string{fmt.Sprintf("The verdict embeds %d break-glass receipt(s); none is honored because the verdict lacks the break-glass context (org, workspace, environment, plan, content, floor epoch or lifetime). Their controls stay enforced.", n)}
	}
	recs := make([]*parsed, n)
	ids := map[string]int{}
	for i, raw := range v.Doc.BreakGlassReceipts {
		recs[i], _ = parse(raw) //nolint:errcheck // nil: dropped below
		// Counted before and apart from the strict parse, so a malformed
		// copy of an override_id still drops the well-formed one.
		for id := range overrideIDs(raw) {
			ids[id]++
		}
	}
	var warns []string
	for i, pr := range recs {
		why := ""
		switch {
		case pr == nil:
			why = "it is not a valid " + Format + " document"
		case ids[pr.r.OverrideID] > 1:
			why = "another embedded receipt has the same override_id"
		default:
			why = check(p, &v.Doc, pr, issued, expires)
		}
		if why != "" {
			warns = append(warns, fmt.Sprintf("Break-glass receipt %d of the verdict is not honored: %s. Its controls stay enforced.", i+1, why))
			continue
		}
		for _, c := range pr.r.Controls {
			for _, k := range pr.r.InstanceKeys {
				set.by[scope{c, k}] = append(set.by[scope{c, k}], Override{ID: pr.r.OverrideID, ReceiptDigest: pr.digest})
			}
		}
	}
	return set, warns
}

// overrideIDs is every string value of a top-level member whose name is
// override_id in any case, read token by token so a duplicate or
// case-variant member, or a malformed sibling value, hides none. A document
// that stops parsing keeps the ids read before the error.
func overrideIDs(raw []byte) map[string]bool {
	ids := map[string]bool{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return ids
	}
	for dec.More() {
		t, err := dec.Token()
		name, isName := t.(string)
		var val json.RawMessage
		if err != nil || !isName || dec.Decode(&val) != nil {
			return ids
		}
		var id string
		if strings.EqualFold(name, "override_id") && json.Unmarshal(val, &id) == nil && id != "" {
			ids[id] = true
		}
	}
	return ids
}

// check is the per-receipt verification after parse; "" honors it.
func check(p Policy, d *verdict.Document, pr *parsed, issued, expires time.Time) string {
	r := &pr.r
	consumed, err1 := parseUTC(r.ConsumedAt)
	rexp, err2 := parseUTC(r.ExpiresAt)
	if err1 != nil || err2 != nil {
		return "consumed_at and expires_at must be RFC 3339 UTC times"
	}
	// The key must be valid when the Evidence API consumed the override and
	// when the gate signed the verdict; never at the local clock.
	for _, at := range []time.Time{consumed, issued} {
		if why := verdict.VerifySignature(r.Signature, pr.signed, p.Profile, p.Revocations, verdict.UseReceipt, at); why != "" {
			return "receipt signature invalid: " + why
		}
	}
	switch {
	case r.OrgID != d.OrgID:
		return "it was issued for another org"
	case r.PlanDigest != d.PlanDigest:
		return "it was issued for another plan"
	case r.RequestDigest != RequestDigest(d, r):
		return "its request_digest does not match this verdict's scope"
	case rexp.Before(issued) || rexp.After(expires):
		return "its expires_at lies outside the verdict lifetime"
	case consumed.After(rexp) || consumed.After(issued.Add(verdict.Skew)):
		return "its consumed_at lies after its expiry or after the verdict was issued"
	}
	return ""
}

// RequestDigest is B9: "sha256:" hex of sha256 over JCS of {org_id,
// workspace, environment, plan_digest, content_digest, floor_epoch} of the
// verdict and {override_id, controls, instance_keys} (sorted) of r.
func RequestDigest(d *verdict.Document, r *Receipt) string {
	b, err := json.Marshal(map[string]any{
		"org_id": d.OrgID, "workspace": d.Workspace, "environment": d.Environment, "plan_digest": d.PlanDigest,
		"content_digest": d.ContentDigest, "floor_epoch": d.FloorEpoch, "override_id": r.OverrideID,
		"controls": sorted(r.Controls), "instance_keys": sorted(r.InstanceKeys),
	})
	if err == nil {
		b, err = bundle.CanonicalJSON(b)
	}
	if err != nil {
		return "" // never equals a well-formed request_digest
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func sorted(s []string) []string {
	c := slices.Clone(s)
	slices.Sort(c)
	return c
}

var errMalformed = errors.New("malformed " + Format)

// parse decodes raw as the verdict is decoded (I-JSON, only strings, arrays
// and objects, typed re-encode equal to the JCS bytes), then checks the
// member shapes. It returns the receipt, its signed bytes (JCS minus the
// top-level signature, B1) and its digest.
func parse(raw []byte) (*parsed, error) {
	canon, err := bundle.CanonicalJSON(raw)
	if err != nil || !onlyStringsArraysObjects(canon) {
		return nil, errMalformed
	}
	var r Receipt
	if json.Unmarshal(canon, &r) != nil {
		return nil, errMalformed
	}
	re, err := json.Marshal(&r)
	if err == nil {
		re, err = bundle.CanonicalJSON(re)
	}
	if err != nil || !bytes.Equal(re, canon) || !wellFormed(&r) {
		return nil, errMalformed
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(canon, &top) != nil {
		return nil, errMalformed
	}
	delete(top, "signature")
	signed, err := json.Marshal(top)
	if err == nil {
		signed, err = bundle.CanonicalJSON(signed)
	}
	if err != nil {
		return nil, errMalformed
	}
	sum := sha256.Sum256(canon)
	return &parsed{r: r, signed: signed, digest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

// wellFormed checks member shapes: format, token override_id, digests,
// non-empty org and run, and non-empty, duplicate-free control and key lists.
func wellFormed(r *Receipt) bool {
	ok := r.Format == Format && reToken.MatchString(r.OverrideID) && r.OrgID != "" && r.RunID != "" &&
		reDigest.MatchString(r.OverrideDigest) && reDigest.MatchString(r.RequestDigest) && reDigest.MatchString(r.PlanDigest) &&
		(r.PredecessorReceiptDigest == "" || reDigest.MatchString(r.PredecessorReceiptDigest))
	return ok && list(r.Controls, reToken) && list(r.InstanceKeys, reDigest)
}

func list(s []string, re *regexp.Regexp) bool {
	if len(s) == 0 {
		return false
	}
	c := sorted(s)
	for i, v := range c {
		if !re.MatchString(v) || i > 0 && c[i-1] == v {
			return false
		}
	}
	return true
}

func onlyStringsArraysObjects(b []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return true
		}
		if err != nil {
			return false
		}
		switch tok.(type) {
		case json.Delim, string:
		default:
			return false
		}
	}
}

func parseUTC(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || !strings.HasSuffix(s, "Z") {
		return time.Time{}, errMalformed
	}
	return t, nil
}
