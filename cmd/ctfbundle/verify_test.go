package main

import (
	"strings"
	"testing"
)

// The reader rules are tested in internal/bundle (TestArchiveTampered); here
// only the writer side: build never emits an archive the reader limits refuse.
func TestWriteArchiveLimits(t *testing.T) {
	if _, err := writeArchive([]string{"big"}, [][]byte{make([]byte, maxDecompressed)}); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("tar above 32 MiB written: %v", err)
	}
}
