//go:build !conformance

package proxy

// tapApply is the conformance NewState tap; release builds carry none.
func tapApply(string, []byte) func([]byte) { return tapNoop }

func tapNoop([]byte) {}

// tapRPC is the conformance client-call tap; release builds carry none.
func tapRPC(string) {}

// editEnvelope is the conformance envelope_mutation seam; release builds
// apply no edit.
func editEnvelope(b []byte) []byte { return b }
