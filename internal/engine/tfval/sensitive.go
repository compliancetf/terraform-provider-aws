package tfval

import (
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
)

// SensitivePaths indexes the schema attributes marked Sensitive, nested
// blocks included, as dotted attribute paths ("logging.secret"). The engine
// evaluates sensitive values in plaintext; the index keeps them out of every
// message, result and memo key output and sets Control.ReadsSensitive.
type SensitivePaths struct {
	paths []string // sorted
}

// NewSensitivePaths builds the index for a resource schema block.
func NewSensitivePaths(b *tfprotov5.SchemaBlock) SensitivePaths {
	var paths []string
	var walk func(*tfprotov5.SchemaBlock, string)
	walk = func(b *tfprotov5.SchemaBlock, prefix string) {
		if b == nil {
			return
		}
		for _, a := range b.Attributes {
			if a.Sensitive {
				paths = append(paths, prefix+a.Name)
			}
		}
		for _, nb := range b.BlockTypes {
			walk(nb.Block, prefix+nb.TypeName+".")
		}
	}
	walk(b, "")
	slices.Sort(paths)
	return SensitivePaths{paths: paths}
}

// Paths returns the sorted sensitive attribute paths.
func (s SensitivePaths) Paths() []string { return slices.Clone(s.paths) }

// Overlaps reports whether a read path (dotted attribute names, element keys
// dropped; "" is the whole value) touches a sensitive value: the read is a
// sensitive path, lies under one, or contains one.
func (s SensitivePaths) Overlaps(read string) bool {
	for _, p := range s.paths {
		if read == "" || p == read || strings.HasPrefix(p, read+".") || strings.HasPrefix(read, p+".") {
			return true
		}
	}
	return false
}
