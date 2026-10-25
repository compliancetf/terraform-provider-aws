package proxy

import "strings"

// VerdictGated reports whether the verdict gate scope gates a full method
// (Provider service only; provisioners stay out of scope).
func VerdictGated(method string) bool {
	return strings.HasPrefix(method, providerService) && scopeOf(method).gated()
}
