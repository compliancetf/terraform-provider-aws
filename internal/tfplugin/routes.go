// Package tfplugin holds the pinned Terraform plugin protocol: the vendored
// protos (proto/), their generated Go types (tfplugin5, tfplugin6; make proto)
// and the route table (routes_gen.go; go generate) that names, per RPC of the
// pinned proto, whether the proxy intercepts it or forwards it as raw bytes.
//
// The generated tfplugin5 package is the only registrant of "tfplugin5.proto"
// in the provider binary: terraform-plugin-go's internal copy comes in only
// with tf5server, which internal/proxy.TestNoPluginGoServerLinked keeps out.
package tfplugin

//go:generate go run ./internal/genroutes

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// Class says what the proxy does with an RPC.
type Class string

const (
	// Intercept: a typed handler in the proxy serves the RPC.
	Intercept Class = "intercept"
	// Passthrough: the generic forwarder copies the RPC to upstream as raw bytes.
	Passthrough Class = "passthrough"
)

// Route is one RPC of the pinned proto.
type Route struct {
	FullMethod   string // gRPC full method, "/tfplugin5.Provider/GetSchema"
	ClientStream bool
	ServerStream bool
	Class        Class
}

// Routes maps a gRPC full method to its route. A method absent from the map
// is not in the pinned proto and must not be forwarded.
type Routes map[string]Route

// V5 returns a copy of the tfplugin5.proto route table. Each call returns a
// fresh map, so no caller can change the table another caller sees.
func V5() Routes { return maps.Clone(v5) }

// V6 returns a copy of the tfplugin6.proto route table.
func V6() Routes { return maps.Clone(v6) }

// ParseClasses decodes classes.json: an object mapping each full method to
// "intercept" or "passthrough".
func ParseClasses(data []byte) (map[string]Class, error) {
	var classes map[string]Class
	if err := json.Unmarshal(data, &classes); err != nil {
		return nil, fmt.Errorf("classes.json: %w", err)
	}
	for m, c := range classes {
		if c != Intercept && c != Passthrough {
			return nil, fmt.Errorf("classes.json: %s has class %q, want %q or %q", m, c, Intercept, Passthrough)
		}
	}
	return classes, nil
}

// Build returns the routes of every RPC in file, classed by classes. It fails
// when a method of file has no class, or when classes names a method of
// file's proto package that file does not declare.
func Build(file protoreflect.FileDescriptor, classes map[string]Class) (Routes, error) {
	routes := Routes{}
	var missing []string
	services := file.Services()
	for i := range services.Len() {
		svc := services.Get(i)
		methods := svc.Methods()
		for j := range methods.Len() {
			m := methods.Get(j)
			full := fmt.Sprintf("/%s/%s", svc.FullName(), m.Name())
			class, ok := classes[full]
			if !ok {
				missing = append(missing, full)
				continue
			}
			routes[full] = Route{FullMethod: full, ClientStream: m.IsStreamingClient(), ServerStream: m.IsStreamingServer(), Class: class}
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return nil, fmt.Errorf("no class in classes.json for %s", strings.Join(missing, ", "))
	}

	prefix := "/" + string(file.Package()) + "."
	var stale []string
	for m := range classes {
		if _, ok := routes[m]; !ok && strings.HasPrefix(m, prefix) {
			stale = append(stale, m)
		}
	}
	if len(stale) > 0 {
		slices.Sort(stale)
		return nil, fmt.Errorf("classes.json names methods absent from %s: %s", file.Path(), strings.Join(stale, ", "))
	}
	return routes, nil
}
