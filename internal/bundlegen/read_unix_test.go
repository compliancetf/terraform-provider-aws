//go:build unix

package bundlegen

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestReadRegularFIFO: a FIFO input fails E_SPECIAL_FILE at once instead of
// blocking on open or read.
func TestReadRegularFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "intents.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readRegular(fifo)
		done <- err
	}()
	select {
	case err := <-done:
		var e *Error
		if !errors.As(err, &e) || e.Code != "E_SPECIAL_FILE" {
			t.Fatalf("err = %v, want E_SPECIAL_FILE", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readRegular blocked on a FIFO")
	}
}
