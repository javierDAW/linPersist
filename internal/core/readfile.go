package core

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// ErrFileTooLarge is returned by ReadFileCapped when the opened file
// holds more than the caller's byte budget. Modules translate this into
// the same SIZE_LIMIT envelope they emit for the pre-read Lstat check.
var ErrFileTooLarge = errors.New("file exceeds size cap")

// ErrNotRegular is returned by ReadFileCapped / OpenRegularNoBlock when
// the path (after symlink resolution) is not a regular file — a FIFO,
// device, socket or directory. A persistence collector must never read
// those: a FIFO open blocks until a writer appears, and /dev/zero-style
// devices stream without end.
var ErrNotRegular = errors.New("not a regular file")

// OpenRegularNoBlock opens path read-only for a root collector walking
// attacker-influenced paths. It hardens os.Open in two ways:
//
//   - O_NONBLOCK: a path that races into a FIFO between an earlier Lstat
//     and this call returns immediately instead of blocking the module
//     until its deadline. (O_NONBLOCK is a no-op for regular files.)
//   - The descriptor is fstat'd and rejected with ErrNotRegular unless
//     it is a regular file. Because the check is on the OPEN descriptor,
//     not a pre-open Lstat, there is no TOCTOU window: whatever is read
//     next comes from the same inode that was just type-checked.
//
// Symlinks are intentionally followed (no O_NOFOLLOW): several modules
// resolve a symlinked locus to hash its real target, which is legitimate
// behaviour. The fstat-after-open check still guarantees the resolved
// target is a regular file. On error the descriptor is closed.
//
// Callers that stream the file (bufio.Scanner, io.ReadAll) should still
// bound their reads with io.LimitReader; ReadFileCapped does this for
// the common read-all case.
func OpenRegularNoBlock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s: %w", path, ErrNotRegular)
	}
	return f, nil
}

// ReadFileCapped reads up to max bytes from path and returns its
// contents. It is the hardened replacement for os.ReadFile at every
// module read site: it opens via OpenRegularNoBlock (O_NONBLOCK +
// fstat regular-check, symlinks followed) and bounds the read with
// io.LimitReader so a file that grew past the caller's pre-check — or
// lied about its size — cannot drive unbounded memory growth. A file
// larger than max returns ErrFileTooLarge; a non-regular target returns
// ErrNotRegular; ENOENT/EACCES surface as the usual *os.PathError so
// errno mapping at the call site still works.
//
// max must be > 0 (every module sets a positive MaxFileSize before
// reading); a non-positive max is treated as "1 byte" to fail closed
// rather than read unbounded.
func ReadFileCapped(path string, max int64) ([]byte, error) {
	if max <= 0 {
		max = 1
	}
	f, err := OpenRegularNoBlock(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read one byte past the cap so "exactly max" is distinguishable
	// from "larger than max" without trusting the stat size.
	buf, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > max {
		return nil, fmt.Errorf("%s (>%d bytes): %w", path, max, ErrFileTooLarge)
	}
	return buf, nil
}
