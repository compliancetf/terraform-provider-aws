// Package rawgrpc forwards gRPC calls to the upstream provider as undecoded
// bytes: a codec that passes *Frame through untouched and a generic stream
// handler that copies frames, metadata and status between the two sides.
package rawgrpc

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
	_ "google.golang.org/grpc/encoding/proto" // registers the "proto" codec read below
	"google.golang.org/grpc/mem"
)

// Frame carries an undecoded gRPC message.
type Frame struct{ Bytes []byte }

// protoCodec is captured once so Codec never looks itself up.
var protoCodec = func() encoding.CodecV2 {
	c := encoding.GetCodecV2("proto")
	if c == nil {
		panic("rawgrpc: grpc proto codec not registered")
	}
	return c
}()

// Codec marshals *Frame as raw bytes and falls back to proto for every other
// value (go-plugin's health, broker, stdio and controller services). Its name
// is "proto", so the content-subtype on the wire does not change.
type Codec struct{}

var _ encoding.CodecV2 = Codec{}

// Marshal implements encoding.CodecV2.
func (Codec) Marshal(v any) (mem.BufferSlice, error) {
	if f, ok := v.(*Frame); ok {
		return mem.BufferSlice{mem.SliceBuffer(f.Bytes)}, nil
	}
	return protoCodec.Marshal(v)
}

// Unmarshal implements encoding.CodecV2. Materialize copies, so a Frame never
// aliases a pooled receive buffer.
func (Codec) Unmarshal(data mem.BufferSlice, v any) error {
	if f, ok := v.(*Frame); ok {
		f.Bytes = data.Materialize()
		return nil
	}
	return protoCodec.Unmarshal(data, v)
}

// Name implements encoding.CodecV2.
func (Codec) Name() string { return "proto" }

// MaxMsgSize bounds every message the proxy sends or receives on either side,
// the terraform-plugin-go limit (256 MiB): the hashicorp/aws GetSchema
// response is larger than gRPC's 4 MiB default.
const MaxMsgSize = 256 << 20

// CallSizes sets MaxMsgSize as a client conn's default receive and send limit.
func CallSizes() grpc.DialOption {
	return grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(MaxMsgSize), grpc.MaxCallSendMsgSize(MaxMsgSize))
}
