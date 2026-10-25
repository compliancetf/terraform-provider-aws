//go:build record

package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"

	"github.com/hashicorp/go-hclog"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

// recordApply dumps, for the instance_key fixtures, one apply
// request under $COMPLIANCETF_RECORD_DIR: apply/<name>.msgpack (PlannedState),
// apply/<name>.type.json (its schema type) and envelope/<name>.json (the
// envelope header, null without one). <name> is <type>.<16 hex of
// sha256(prior msgpack, NUL, planned msgpack)>; the provider never sees the
// resource address, so the recording script maps names to addresses. Only
// PlannedState and the header are written: no config, no prior state, no
// upstream private bytes. Files are 0600 in 0700 directories; a failed write
// is logged and the apply goes on. The recorder trusts the directory: it is
// for a maintainer's fresh directory in the fixture sandbox, never real data.
func recordApply(ctx context.Context, s *server5, req *tfplugin5.ApplyResourceChange_Request, env *hook.EnvelopeHeader) {
	dir := os.Getenv("COMPLIANCETF_RECORD_DIR")
	if dir == "" {
		return
	}
	if err := writeRecord(ctx, s, dir, req, env); err != nil {
		hclog.Default().Named("record").Error("apply record failed", "type", req.TypeName, "error", err)
	}
}

// recordType is a type name safe as a file name component.
var recordType = regexp.MustCompile(`^[a-z0-9_]{1,128}$`)

func writeRecord(ctx context.Context, s *server5, dir string, req *tfplugin5.ApplyResourceChange_Request, env *hook.EnvelopeHeader) error {
	if !recordType.MatchString(req.TypeName) {
		return errors.New("type name is not a plain identifier")
	}
	planned := req.GetPlannedState().GetMsgpack()
	if len(planned) == 0 {
		return errors.New("planned state is not msgpack")
	}
	sch, ok, err := s.schemaOf(ctx, req.TypeName, schemasOf[hook.KindResource])
	if err != nil || !ok {
		return errors.Join(errors.New("no schema"), err)
	}
	typ, err := sch.ValueType().MarshalJSON() //nolint:staticcheck // the wire form of a schema type
	if err != nil {
		return err
	}
	header, err := json.Marshal(env) // nil marshals as null
	if err != nil {
		return err
	}
	sum := sha256.Sum256(append(append(append([]byte{}, req.GetPriorState().GetMsgpack()...), 0), planned...))
	name := req.TypeName + "." + hex.EncodeToString(sum[:8])
	for _, f := range []struct {
		sub, file string
		b         []byte
	}{{"apply", name + ".msgpack", planned}, {"apply", name + ".type.json", typ}, {"envelope", name + ".json", header}} {
		d := filepath.Join(dir, f.sub)
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(d, f.file), f.b, 0o600); err != nil {
			return err
		}
	}
	return nil
}
