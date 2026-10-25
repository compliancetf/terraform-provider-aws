//go:build !windows

package upstream

import (
	"context"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestUnpackZipRejectsFIFO(t *testing.T) {
	r := newRelease(t)
	fifo := filepath.Join(t.TempDir(), "fifo.zip")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := unpackZip(context.Background(), fifo, r.pins, testOSArch, filepath.Join(t.TempDir(), "cache"))
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("fifo: err = %v", err)
	}
}
