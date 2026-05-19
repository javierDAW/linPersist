// Package core: proclive.go
//
// LiveProcessSet is the live-process correlation primitive: the agent
// snapshots /proc once at startup and exposes a path-membership check
// to every module that emits an exec_target. The check answers
// "is this exec_target a process running on the host right now?".
//
// See docs/adr/0010-proc-live-correlation.md for the design rationale
// (one-shot snapshot, hidepid degrade, symlink resolution at lookup,
// container namespace semantics).
package core

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// LiveProcessSet is the small read interface every module consumes.
// Implementations MUST be safe to call concurrently.
type LiveProcessSet interface {
	// Warmup performs the one-shot /proc walk. Idempotent. Safe to
	// call concurrently; only the first invocation does work.
	Warmup(ctx context.Context)

	// Has returns true if path is the resolved executable of at
	// least one process visible to the agent when Warmup ran.
	// Implementations MAY perform a single EvalSymlinks fallback on
	// miss (mirrors the provenance resolver's policy).
	Has(path string) bool
}

// NoopLiveProcessSet always returns false. Used as the default in
// module Options when no scanner is wired (e.g. tests).
type NoopLiveProcessSet struct{}

// Compile-time interface conformance.
var _ LiveProcessSet = NoopLiveProcessSet{}

// Warmup is a no-op.
func (NoopLiveProcessSet) Warmup(context.Context) {}

// Has always returns false.
func (NoopLiveProcessSet) Has(string) bool { return false }

// DefaultProcLiveBuildTimeout caps the /proc walk wall-clock time.
// Observed cost is in the low milliseconds on a quiet host and tens
// of milliseconds on a busy container host. Five seconds is a
// conservative ceiling; misconfigured hidepid filesystems or
// massively oversubscribed namespaces are the only realistic ways
// to exceed it.
const DefaultProcLiveBuildTimeout = 5 * time.Second

// procDeletedSuffix is what Linux appends to /proc/<pid>/exe when the
// underlying binary has been unlinked while the process still holds
// it open. The scanner strips this before inserting into the set so
// a persistence record pointing at the pre-unlink path still matches.
const procDeletedSuffix = " (deleted)"

// ProcLiveScanner is the production LiveProcessSet implementation.
//
// The zero value is NOT usable; construct via NewProcLiveScanner.
type ProcLiveScanner struct {
	logger *slog.Logger

	// procRoot is the directory the scanner walks. Production
	// callers leave it as "/proc"; tests override via
	// WithProcLiveRoot(t.TempDir()/proc).
	procRoot string

	// buildTimeout caps the walk wall-clock. Zero means
	// DefaultProcLiveBuildTimeout.
	buildTimeout time.Duration

	warmupOnce sync.Once
	warmedUp   atomic.Bool
	set        map[string]struct{}
	buildErr   error
}

// ProcLiveScannerOption tunes a ProcLiveScanner at construction.
type ProcLiveScannerOption func(*ProcLiveScanner)

// WithProcLiveRoot overrides /proc. Intended for tests; production
// code leaves this alone.
func WithProcLiveRoot(root string) ProcLiveScannerOption {
	return func(s *ProcLiveScanner) { s.procRoot = root }
}

// WithProcLiveBuildTimeout overrides the default 5 s ceiling.
func WithProcLiveBuildTimeout(d time.Duration) ProcLiveScannerOption {
	return func(s *ProcLiveScanner) { s.buildTimeout = d }
}

// NewProcLiveScanner constructs a production ProcLiveScanner.
func NewProcLiveScanner(logger *slog.Logger, opts ...ProcLiveScannerOption) *ProcLiveScanner {
	if logger == nil {
		logger = slog.Default()
	}
	s := &ProcLiveScanner{
		logger:       logger,
		procRoot:     "/proc",
		buildTimeout: DefaultProcLiveBuildTimeout,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Compile-time interface conformance.
var _ LiveProcessSet = (*ProcLiveScanner)(nil)

// Warmup walks /proc once and freezes the resulting set.
func (s *ProcLiveScanner) Warmup(ctx context.Context) {
	s.warmupOnce.Do(func() {
		defer s.warmedUp.Store(true)

		timeout := s.buildTimeout
		if timeout <= 0 {
			timeout = DefaultProcLiveBuildTimeout
		}
		buildCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		start := time.Now()
		set, err := s.buildSet(buildCtx)
		elapsed := time.Since(start)

		if err != nil {
			s.buildErr = err
			s.logger.Warn("proclive build failed",
				"proc_root", s.procRoot,
				"elapsed", elapsed,
				"err", err)
			return
		}
		s.set = set
		s.logger.Info("proclive built",
			"proc_root", s.procRoot,
			"entries", len(set),
			"elapsed", elapsed)
	})
}

// Has returns true if path is in the live-executable set.
func (s *ProcLiveScanner) Has(path string) bool {
	if !s.warmedUp.Load() {
		return false
	}
	if path == "" || s.set == nil {
		return false
	}
	if _, ok := s.set[path]; ok {
		return true
	}
	// Second probe: resolve a symlink once. Bounded by best-effort
	// host I/O; a hostile/hung symlink degrades to "not found"
	// rather than blocking the caller.
	if resolved, err := filepath.EvalSymlinks(path); err == nil && resolved != path {
		if _, ok := s.set[resolved]; ok {
			return true
		}
	}
	return false
}

// Size returns the number of distinct exe paths captured by the
// scanner. Useful for tests and metrics. Returns 0 before Warmup or
// on build failure.
func (s *ProcLiveScanner) Size() int { return len(s.set) }

// BuildErr returns the error recorded during Warmup, if any. Useful
// for tests to assert on degrade paths.
func (s *ProcLiveScanner) BuildErr() error { return s.buildErr }

// buildSet walks s.procRoot once, reading every /proc/<pid>/exe
// symlink it can. EACCES / ENOENT / ESRCH are non-fatal and silently
// drop the offending entry from the result. A walker-level error
// (e.g. EACCES on the root) returns the error so Warmup degrades to
// "no membership" rather than partial membership.
func (s *ProcLiveScanner) buildSet(ctx context.Context) (map[string]struct{}, error) {
	entries, err := os.ReadDir(s.procRoot)
	if err != nil {
		return nil, err
	}

	out := make(map[string]struct{}, 256)
	for _, e := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		name := e.Name()
		if !isPIDDirName(name) {
			continue
		}
		exeLink := filepath.Join(s.procRoot, name, "exe")
		target, err := os.Readlink(exeLink)
		if err != nil {
			// EACCES (hidepid), ENOENT/ESRCH (process exited
			// mid-walk), EPERM (kernel hides) are all "skip silently".
			// Anything else is also non-fatal at this loop level.
			if !errors.Is(err, fs.ErrNotExist) &&
				!errors.Is(err, fs.ErrPermission) &&
				!errors.Is(err, os.ErrPermission) {
				s.logger.Debug("proclive readlink skip",
					"path", exeLink, "err", err)
			}
			continue
		}
		target = strings.TrimSuffix(target, procDeletedSuffix)
		if target == "" {
			continue
		}
		out[target] = struct{}{}
	}
	return out, nil
}

// isPIDDirName returns true if name is composed entirely of decimal
// digits (i.e. it is a numeric PID directory under /proc).
func isPIDDirName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if c < '0' || c > '9' {
			return false
		}
	}
	// Reject pathologically long "numbers" that overflow a reasonable
	// PID space. Real PIDs fit in int32.
	if len(name) > 10 {
		return false
	}
	if _, err := strconv.Atoi(name); err != nil {
		return false
	}
	return true
}

// AnnotateLiveProcess is the helper every module calls right after
// AnnotateExecTargetProvenance. If target is in the live-process
// set, the helper appends SignalLiveProcessAttached to rec.Signals.
//
// rec is modified in place. Callers that already de-duplicated
// rec.Signals can rely on this helper not introducing duplicates:
// SignalLiveProcessAttached is unique to this helper and is never
// emitted by any other code path.
func AnnotateLiveProcess(rec *Record, lps LiveProcessSet, target string) {
	if rec == nil || lps == nil || target == "" {
		return
	}
	if lps.Has(target) {
		rec.Signals = append(rec.Signals, SignalLiveProcessAttached)
	}
}
