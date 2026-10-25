package rawgrpc

import (
	"context"
	"errors"
	"io"
	"maps"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin"
)

// Forwarder is a grpc.StreamHandler for grpc.UnknownServiceHandler. gRPC
// sends it every method that has no registered handler, including unknown
// methods of a registered service. A method absent from routes, or one whose
// class is not passthrough, returns codes.Unimplemented and never reaches
// upstream. Otherwise it opens a stream on upstream with the same full method
// and copies frames, headers and trailers both ways until upstream ends the
// call; upstream's status is returned unchanged. Handles unary, server,
// client and bidi streams.
//
// onTransportErr, when not nil, receives every codes.Unavailable error from
// upstream and returns the error to send instead; a nil return keeps the
// original.
func Forwarder(upstream *grpc.ClientConn, routes tfplugin.Routes, onTransportErr func(method string, err error) error) grpc.StreamHandler {
	routes = maps.Clone(routes)
	return func(_ any, ss grpc.ServerStream) error {
		method, _ := grpc.MethodFromServerStream(ss)
		r, ok := routes[method]
		if !ok {
			return status.Errorf(codes.Unimplemented, "tfplugin method %s is not in the pinned protocol of this provider release", method)
		}
		if r.Class != tfplugin.Passthrough {
			return status.Errorf(codes.Unimplemented, "tfplugin method %s is intercepted and has no handler", method)
		}

		ctx, cancel := context.WithCancel(ss.Context())
		defer cancel()
		md, _ := metadata.FromIncomingContext(ctx)
		ctx = metadata.NewOutgoingContext(ctx, appMetadata(md))

		cs, err := upstream.NewStream(ctx, &grpc.StreamDesc{ClientStreams: r.ClientStream, ServerStreams: r.ServerStream}, method, grpc.ForceCodecV2(Codec{}))
		if err != nil {
			return mapErr(method, err, onTransportErr)
		}

		// Not joined: once this handler returns, gRPC ends ss and its RecvMsg
		// returns; cancel ends a blocked upstream SendMsg.
		go clientToUpstream(ss, cs, cancel)

		// Header blocks until upstream sends headers or ends the call, so
		// headers reach the client before any message. It returns nil for a
		// trailers-only response; sending nothing keeps that response
		// trailers-only downstream too.
		if hdr, err := cs.Header(); err == nil && hdr != nil {
			if err := ss.SendHeader(appMetadata(hdr)); err != nil {
				return err
			}
		}
		for {
			f := &Frame{}
			err := cs.RecvMsg(f)
			if err != nil {
				ss.SetTrailer(appMetadata(cs.Trailer()))
				if errors.Is(err, io.EOF) {
					return nil
				}
				return mapErr(method, err, onTransportErr)
			}
			if err := ss.SendMsg(f); err != nil {
				return err
			}
		}
	}
}

func clientToUpstream(ss grpc.ServerStream, cs grpc.ClientStream, cancel context.CancelFunc) {
	for {
		f := &Frame{}
		if err := ss.RecvMsg(f); err != nil {
			if !errors.Is(err, io.EOF) || cs.CloseSend() != nil {
				cancel()
			}
			return
		}
		if err := cs.SendMsg(f); err != nil {
			// io.EOF: upstream ended the call; its status comes from RecvMsg.
			if !errors.Is(err, io.EOF) {
				cancel()
			}
			return
		}
	}
}

func mapErr(method string, err error, onTransportErr func(string, error) error) error {
	if onTransportErr != nil && status.Code(err) == codes.Unavailable {
		if mapped := onTransportErr(method, err); mapped != nil {
			return mapped
		}
	}
	return err
}

// appMetadata drops pseudo-headers and the "grpc-" keys the gRPC protocol
// reserves (grpc-accept-encoding, grpc-status-details-bin, ...). Each hop
// sets its own; forwarding them could select a compressor this proxy lacks
// or send status details twice. Status travels in the returned error.
func appMetadata(md metadata.MD) metadata.MD {
	out := metadata.MD{}
	for k, v := range md {
		if !strings.HasPrefix(k, ":") && !strings.HasPrefix(k, "grpc-") {
			out[k] = v
		}
	}
	return out
}
