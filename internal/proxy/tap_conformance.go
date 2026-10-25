//go:build conformance

package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/hashicorp/go-hclog"
)

var tapMu sync.Mutex

// tapApply records upstream's new_state msgpack for one forwarded apply and
// returns the function that, given the bytes the proxy returns, appends
// {"rpc","type","upstream_sha256","returned_sha256"} as one JSON line to
// $COMPLIANCETF_CONFORMANCE_TAP. The conformance runner fails on any pair
// that differs or on a missing line.
func tapApply(typ string, upstream []byte) func([]byte) {
	path := os.Getenv("COMPLIANCETF_CONFORMANCE_TAP")
	if path == "" {
		return func([]byte) {}
	}
	up := sha256.Sum256(upstream)
	return func(returned []byte) {
		ret := sha256.Sum256(returned)
		line, err := json.Marshal(map[string]string{
			"rpc":             "ApplyResourceChange",
			"type":            typ,
			"upstream_sha256": hex.EncodeToString(up[:]),
			"returned_sha256": hex.EncodeToString(ret[:]),
		})
		tapWrite(path, line, err)
	}
}

// tapRPC appends {"rpc":"GetMetadata"} to $COMPLIANCETF_CONFORMANCE_TAP when
// Core calls GetMetadata. No Terraform or OpenTofu in the matrix calls it as a
// client, which is why the v5 actions field drift (8 in core, 9 in
// plugin-go) is accepted; the runner fails on the line.
func tapRPC(method string) {
	path := os.Getenv("COMPLIANCETF_CONFORMANCE_TAP")
	if path == "" || method != providerService+"GetMetadata" {
		return
	}
	line, err := json.Marshal(map[string]string{"rpc": "GetMetadata"})
	tapWrite(path, line, err)
}

// tapWrite appends line to path. On failure it records the error in
// path+".failed", which fails the runner's checkTap, and the RPC goes on; only
// a failure to write that file too goes unseen.
func tapWrite(path string, line []byte, err error) {
	tapMu.Lock()
	defer tapMu.Unlock()
	var f *os.File
	if err == nil {
		f, err = os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	}
	if err == nil {
		_, err = f.Write(append(line, '\n'))
		err = errors.Join(err, f.Close())
	}
	if err != nil {
		hclog.Default().Named("conformance").Error("tap write failed", "error", err)
		if f, ferr := os.OpenFile(path+".failed", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); ferr == nil {
			_, werr := f.WriteString(err.Error() + "\n")
			if werr = errors.Join(werr, f.Close()); werr != nil {
				hclog.Default().Named("conformance").Error("tap failure marker write failed", "error", werr)
			}
		}
	}
}

// editEnvelope applies the envelope_mutation edit in the JSON file
// $COMPLIANCETF_CONFORMANCE_ENVELOPE names, when it exists, to an apply's
// planned_private: "v" and "ctf" members replace the header's (a null ctf
// member deletes it), "strip" drops the envelope and keeps upstream's bytes.
// The frame is rebuilt by hand, so the edit may break any v1 rule.
func editEnvelope(b []byte) []byte {
	raw, err := os.ReadFile(os.Getenv("COMPLIANCETF_CONFORMANCE_ENVELOPE"))
	if errors.Is(err, os.ErrNotExist) || !bytes.HasPrefix(b, envelopeMagic) || len(b) < len(envelopeMagic)+5 {
		return b
	}
	var edit struct {
		V     *int           `json:"v"`
		CTF   map[string]any `json:"ctf"`
		Strip bool           `json:"strip"`
	}
	var h struct {
		V   int            `json:"v"`
		CTF map[string]any `json:"ctf"`
	}
	rest := b[len(envelopeMagic):]
	n := int(binary.BigEndian.Uint32(rest[1:5]))
	if err == nil && len(rest) >= 5+n {
		err = errors.Join(json.Unmarshal(raw, &edit), json.Unmarshal(rest[5:5+n], &h))
	}
	if err != nil || h.CTF == nil {
		hclog.Default().Named("conformance").Error("envelope edit failed", "error", err)
		return b
	}
	if edit.Strip {
		return rest[5+n:]
	}
	if edit.V != nil {
		h.V = *edit.V
	}
	for k, v := range edit.CTF {
		if v == nil {
			delete(h.CTF, k)
		} else {
			h.CTF[k] = v
		}
	}
	hj, err := json.Marshal(h)
	if err != nil {
		hclog.Default().Named("conformance").Error("envelope edit failed", "error", err)
		return b
	}
	out := binary.BigEndian.AppendUint32(append(bytes.Clone(envelopeMagic), rest[0]), uint32(len(hj))) //nolint:gosec // a small header
	return append(append(out, hj...), rest[5+n:]...)
}
