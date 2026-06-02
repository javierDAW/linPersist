package core

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestReadFileCappedRegular(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	want := []byte("hello world\n")
	if err := os.WriteFile(p, want, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFileCapped(p, 1<<20)
	if err != nil {
		t.Fatalf("ReadFileCapped: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestReadFileCappedExactlyMax(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	want := bytes.Repeat([]byte("A"), 100)
	if err := os.WriteFile(p, want, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFileCapped(p, 100)
	if err != nil {
		t.Fatalf("ReadFileCapped at exactly max: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %d bytes, want 100", len(got))
	}
}

func TestReadFileCappedTooLarge(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, bytes.Repeat([]byte("A"), 101), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadFileCapped(p, 100)
	if !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("got %v, want ErrFileTooLarge", err)
	}
}

func TestReadFileCappedSymlinkFollowed(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	want := []byte("real payload")
	if err := os.WriteFile(target, want, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	// Symlink-following is intentional: modules hash the resolved target.
	got, err := ReadFileCapped(link, 1<<20)
	if err != nil {
		t.Fatalf("ReadFileCapped(symlink): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestReadFileCappedMissingMapsToNotExist(t *testing.T) {
	_, err := ReadFileCapped(filepath.Join(t.TempDir(), "nope"), 1<<20)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("got %v, want fs.ErrNotExist (so errno mapping at call sites still works)", err)
	}
}

func TestReadFileCappedDirectoryRejected(t *testing.T) {
	_, err := ReadFileCapped(t.TempDir(), 1<<20)
	if !errors.Is(err, ErrNotRegular) {
		t.Fatalf("got %v, want ErrNotRegular for a directory", err)
	}
}

// TestOpenRegularNoBlockFIFO is the core safety property of F3: a FIFO
// that races into a scanned path must be rejected without blocking. With
// a blocking open this test would hang until the test timeout (no writer
// ever appears); O_NONBLOCK makes it return ErrNotRegular at once.
func TestOpenRegularNoBlockFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	f, err := OpenRegularNoBlock(fifo)
	if err == nil {
		f.Close()
		t.Fatal("opened a FIFO as a regular file")
	}
	if !errors.Is(err, ErrNotRegular) {
		t.Fatalf("got %v, want ErrNotRegular for a FIFO", err)
	}
}

func TestReadFileCappedNonPositiveMaxFailsClosed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("AB"), 0o600); err != nil {
		t.Fatal(err)
	}
	// max <= 0 must not read unbounded; it is treated as a 1-byte cap, so
	// any non-empty file trips ErrFileTooLarge.
	if _, err := ReadFileCapped(p, 0); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("got %v, want ErrFileTooLarge for max=0", err)
	}
}
