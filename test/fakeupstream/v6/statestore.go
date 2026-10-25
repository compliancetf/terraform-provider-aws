package main

//go:generate sh -c "sh gen.sh > provider_gen.go"

import (
	"context"
	"slices"
	"sync"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// chunkSize is small so a few hundred bytes of state cross the wire as
// several chunks in both stream directions.
const chunkSize = 64

// states is the in-memory state store fake_store: it lives as long as the
// process, which is enough for passthrough tests.
var states = struct {
	sync.Mutex
	m map[string][]byte
}{m: map[string][]byte{}}

// withStateStoreMetadata and withStateStoreSchema list fake_store, which
// Terraform requires before it accepts a state_store block; the v5 fake
// (v5/nostatestore.go) returns its responses unchanged.
func withStateStoreMetadata(r *tfprotov6.GetMetadataResponse) *tfprotov6.GetMetadataResponse {
	r.StateStores = []tfprotov6.StateStoreMetadata{{TypeName: "fake_store"}}
	return r
}

func withStateStoreSchema(r *tfprotov6.GetProviderSchemaResponse) *tfprotov6.GetProviderSchemaResponse {
	r.StateStoreSchemas = map[string]*tfprotov6.Schema{"fake_store": schema()}
	return r
}

func (p *provider) ValidateStateStoreConfig(context.Context, *tfprotov6.ValidateStateStoreConfigRequest) (*tfprotov6.ValidateStateStoreConfigResponse, error) {
	return &tfprotov6.ValidateStateStoreConfigResponse{}, nil
}

func (p *provider) ConfigureStateStore(context.Context, *tfprotov6.ConfigureStateStoreRequest) (*tfprotov6.ConfigureStateStoreResponse, error) {
	return &tfprotov6.ConfigureStateStoreResponse{Capabilities: &tfprotov6.StateStoreServerCapabilities{ChunkSize: chunkSize}}, nil
}

func (p *provider) ReadStateBytes(_ context.Context, req *tfprotov6.ReadStateBytesRequest) (*tfprotov6.ReadStateBytesStream, error) {
	states.Lock()
	b := states.m[req.StateID]
	states.Unlock()
	var chunks []tfprotov6.ReadStateByteChunk
	for start := 0; start < len(b); start += chunkSize {
		end := min(start+chunkSize, len(b))
		chunks = append(chunks, tfprotov6.ReadStateByteChunk{StateByteChunk: tfprotov6.StateByteChunk{
			Bytes: b[start:end], TotalLength: int64(len(b)), Range: tfprotov6.StateByteRange{Start: int64(start), End: int64(end)},
		}})
	}
	return &tfprotov6.ReadStateBytesStream{Chunks: slices.Values(chunks)}, nil
}

func (p *provider) WriteStateBytes(_ context.Context, req *tfprotov6.WriteStateBytesStream) (*tfprotov6.WriteStateBytesResponse, error) {
	var id string
	var b []byte
	for chunk, d := range req.Chunks {
		if len(d) > 0 {
			return &tfprotov6.WriteStateBytesResponse{Diagnostics: d}, nil
		}
		if chunk.Meta != nil {
			id = chunk.Meta.StateID
		}
		b = append(b, chunk.Bytes...)
	}
	states.Lock()
	states.m[id] = b
	states.Unlock()
	return &tfprotov6.WriteStateBytesResponse{}, nil
}

func (p *provider) GetStates(context.Context, *tfprotov6.GetStatesRequest) (*tfprotov6.GetStatesResponse, error) {
	states.Lock()
	defer states.Unlock()
	ids := []string{}
	for id := range states.m {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return &tfprotov6.GetStatesResponse{StateIDs: ids}, nil
}

func (p *provider) DeleteState(_ context.Context, req *tfprotov6.DeleteStateRequest) (*tfprotov6.DeleteStateResponse, error) {
	states.Lock()
	delete(states.m, req.StateID)
	states.Unlock()
	return &tfprotov6.DeleteStateResponse{}, nil
}

// LockState always succeeds: one Terraform process per test.
func (p *provider) LockState(_ context.Context, req *tfprotov6.LockStateRequest) (*tfprotov6.LockStateResponse, error) {
	return &tfprotov6.LockStateResponse{LockID: "lock-" + req.StateID}, nil
}

func (p *provider) UnlockState(context.Context, *tfprotov6.UnlockStateRequest) (*tfprotov6.UnlockStateResponse, error) {
	return &tfprotov6.UnlockStateResponse{}, nil
}
