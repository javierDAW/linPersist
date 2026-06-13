package core

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestOpenRegularNoBlockRejectsFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "trap")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		f, err := OpenRegularNoBlock(fifo)
		if f != nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("OpenRegularNoBlock returned nil error on a FIFO (would hang on read)")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("OpenRegularNoBlock BLOCKED on a FIFO — the agent-hang bug is not fixed")
	}
	// And a regular file still opens fine.
	reg := filepath.Join(dir, "ok")
	os.WriteFile(reg, []byte("x"), 0o644)
	f, err := OpenRegularNoBlock(reg)
	if err != nil {
		t.Fatalf("regular file rejected: %v", err)
	}
	f.Close()
}
