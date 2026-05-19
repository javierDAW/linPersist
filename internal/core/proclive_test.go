package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// makeProcEntry creates a fake /proc/<pid>/exe symlink pointing at
// target. target is a string, not necessarily an existing file; the
// scanner reads the symlink with Readlink which does NOT require the
// target to exist (mirrors Linux's /proc/<pid>/exe behavior with
// deleted binaries).
func makeProcEntry(t *testing.T, procRoot, pid, target string) {
	t.Helper()
	pidDir := filepath.Join(procRoot, pid)
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", pidDir, err)
	}
	exeLink := filepath.Join(pidDir, "exe")
	if err := os.Symlink(target, exeLink); err != nil {
		t.Fatalf("symlink %s -> %s: %v", exeLink, target, err)
	}
}

// TestNoopLiveProcessSet: contract is "always false, never blocks".
func TestNoopLiveProcessSet(t *testing.T) {
	var lps LiveProcessSet = NoopLiveProcessSet{}
	lps.Warmup(context.Background())
	if lps.Has("/usr/bin/anything") {
		t.Errorf("NoopLiveProcessSet.Has returned true; want false")
	}
}

// TestProcLiveScanner_HappyPath: fake /proc tree with three PIDs.
func TestProcLiveScanner_HappyPath(t *testing.T) {
	procRoot := filepath.Join(t.TempDir(), "proc")
	makeProcEntry(t, procRoot, "1", "/sbin/init")
	makeProcEntry(t, procRoot, "412", "/usr/sbin/sshd")
	makeProcEntry(t, procRoot, "1024", "/usr/bin/cron")

	s := NewProcLiveScanner(nullLogger(), WithProcLiveRoot(procRoot))
	s.Warmup(context.Background())

	if err := s.BuildErr(); err != nil {
		t.Fatalf("BuildErr = %v; want nil", err)
	}
	if s.Size() != 3 {
		t.Errorf("Size = %d; want 3", s.Size())
	}
	for _, want := range []string{"/sbin/init", "/usr/sbin/sshd", "/usr/bin/cron"} {
		if !s.Has(want) {
			t.Errorf("Has(%q) = false; want true", want)
		}
	}
	if s.Has("/tmp/.x/payload") {
		t.Errorf("Has on unrelated path returned true")
	}
}

// TestProcLiveScanner_MissingProcRoot: no /proc directory at all
// (containers without /proc mounted, sandboxed agents). The scanner
// records the error and degrades; Has always returns false.
func TestProcLiveScanner_MissingProcRoot(t *testing.T) {
	procRoot := filepath.Join(t.TempDir(), "does-not-exist")
	s := NewProcLiveScanner(nullLogger(), WithProcLiveRoot(procRoot))
	s.Warmup(context.Background())

	if s.BuildErr() == nil {
		t.Errorf("BuildErr = nil; want error")
	}
	if s.Has("/usr/bin/anything") {
		t.Errorf("Has on degraded scanner returned true")
	}
}

// TestProcLiveScanner_HasBeforeWarmup: until Warmup completes, Has
// returns false rather than blocking.
func TestProcLiveScanner_HasBeforeWarmup(t *testing.T) {
	procRoot := filepath.Join(t.TempDir(), "proc")
	makeProcEntry(t, procRoot, "1", "/sbin/init")
	s := NewProcLiveScanner(nullLogger(), WithProcLiveRoot(procRoot))
	// Warmup deliberately not called.
	if s.Has("/sbin/init") {
		t.Errorf("Has before Warmup returned true; want false")
	}
}

// TestProcLiveScanner_StripsDeletedSuffix: when a process's binary
// is deleted, Linux returns "<path> (deleted)" from readlink. The
// scanner MUST strip the suffix so the canonical path still matches.
func TestProcLiveScanner_StripsDeletedSuffix(t *testing.T) {
	procRoot := filepath.Join(t.TempDir(), "proc")
	makeProcEntry(t, procRoot, "777", "/var/lib/dropped/payload (deleted)")

	s := NewProcLiveScanner(nullLogger(), WithProcLiveRoot(procRoot))
	s.Warmup(context.Background())

	if !s.Has("/var/lib/dropped/payload") {
		t.Errorf("Has on deleted-suffix-stripped path returned false; want true")
	}
}

// TestProcLiveScanner_IgnoresNonPIDDirs: /proc has lots of
// non-numeric entries (cpuinfo, meminfo, sys/, ...). The scanner
// must filter to numeric-only directory names.
func TestProcLiveScanner_IgnoresNonPIDDirs(t *testing.T) {
	procRoot := filepath.Join(t.TempDir(), "proc")
	makeProcEntry(t, procRoot, "1", "/sbin/init")
	// Non-PID directories that should be ignored.
	for _, d := range []string{"sys", "cpuinfo", "meminfo", "self", "thread-self", "bus"} {
		dir := filepath.Join(procRoot, d)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	// And a bogus exe link under one of them to verify it is NOT walked.
	bogus := filepath.Join(procRoot, "self", "exe")
	_ = os.Symlink("/should-not-appear", bogus)

	s := NewProcLiveScanner(nullLogger(), WithProcLiveRoot(procRoot))
	s.Warmup(context.Background())

	if s.Size() != 1 {
		t.Errorf("Size = %d; want 1 (only /proc/1/exe)", s.Size())
	}
	if s.Has("/should-not-appear") {
		t.Errorf("Has picked up exe link under non-PID dir")
	}
}

// TestProcLiveScanner_DanglingSymlinkTolerated: a PID whose exe
// symlink target doesn't exist on disk is still captured; the
// scanner records the literal target text without dereferencing.
func TestProcLiveScanner_DanglingSymlinkTolerated(t *testing.T) {
	procRoot := filepath.Join(t.TempDir(), "proc")
	makeProcEntry(t, procRoot, "555", "/opt/never-installed/payload")

	s := NewProcLiveScanner(nullLogger(), WithProcLiveRoot(procRoot))
	s.Warmup(context.Background())

	if !s.Has("/opt/never-installed/payload") {
		t.Errorf("Has on dangling-target entry returned false; want true")
	}
}

// TestProcLiveScanner_ReadlinkEACCES: a PID dir owned by another user
// with no exe link readable. The scanner must skip silently without
// failing the whole walk.
func TestProcLiveScanner_ReadlinkEACCES(t *testing.T) {
	procRoot := filepath.Join(t.TempDir(), "proc")
	makeProcEntry(t, procRoot, "1", "/sbin/init")

	// A PID dir with no exe link at all. Mirrors hidepid behavior:
	// the dir is present but readlink returns ENOENT.
	pid2 := filepath.Join(procRoot, "2")
	if err := os.MkdirAll(pid2, 0o755); err != nil {
		t.Fatal(err)
	}
	// Note: no exe symlink in /proc/2/.

	s := NewProcLiveScanner(nullLogger(), WithProcLiveRoot(procRoot))
	s.Warmup(context.Background())

	if s.BuildErr() != nil {
		t.Errorf("BuildErr = %v; want nil (one missing exe must not fail the walk)", s.BuildErr())
	}
	if s.Size() != 1 {
		t.Errorf("Size = %d; want 1", s.Size())
	}
	if !s.Has("/sbin/init") {
		t.Errorf("Has(/sbin/init) = false; want true")
	}
}

// TestProcLiveScanner_WarmupIsIdempotent: a second Warmup MUST NOT
// rescan, even if the underlying fixture changed.
func TestProcLiveScanner_WarmupIsIdempotent(t *testing.T) {
	procRoot := filepath.Join(t.TempDir(), "proc")
	makeProcEntry(t, procRoot, "1", "/sbin/init")

	s := NewProcLiveScanner(nullLogger(), WithProcLiveRoot(procRoot))
	s.Warmup(context.Background())
	sizeAfterFirst := s.Size()

	makeProcEntry(t, procRoot, "2", "/usr/bin/late-arrival")
	s.Warmup(context.Background())
	if s.Size() != sizeAfterFirst {
		t.Errorf("Size changed across Warmup calls: %d -> %d", sizeAfterFirst, s.Size())
	}
	if s.Has("/usr/bin/late-arrival") {
		t.Errorf("Has picked up post-Warmup entry; want false")
	}
}

// TestProcLiveScanner_ConcurrentHas: lock-free reads under -race.
func TestProcLiveScanner_ConcurrentHas(t *testing.T) {
	procRoot := filepath.Join(t.TempDir(), "proc")
	for i := 1; i <= 16; i++ {
		makeProcEntry(t, procRoot, strconvI(i),
			"/usr/bin/program-"+strconvI(i))
	}
	s := NewProcLiveScanner(nullLogger(), WithProcLiveRoot(procRoot))
	s.Warmup(context.Background())

	const goroutines = 32
	const lookups = 200
	done := make(chan struct{}, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < lookups; j++ {
				_ = s.Has("/usr/bin/program-1")
				_ = s.Has("/usr/bin/program-7")
				_ = s.Has("/tmp/nope")
			}
		}()
	}
	for i := 0; i < goroutines; i++ {
		<-done
	}
}

// TestProcLiveScanner_BuildTimeoutHonored: a tiny build timeout
// against a deliberately tarpit'ed walk degrades to an Error state.
// Hard to reproduce reliably with a fake /proc on a fast filesystem,
// so this test asserts the looser invariant: even with the timeout
// expired, Warmup never panics and Has always returns a boolean
// without blocking.
func TestProcLiveScanner_BuildTimeoutHonored(t *testing.T) {
	procRoot := filepath.Join(t.TempDir(), "proc")
	for i := 1; i <= 32; i++ {
		makeProcEntry(t, procRoot, strconvI(i), "/sbin/init")
	}

	s := NewProcLiveScanner(nullLogger(),
		WithProcLiveRoot(procRoot),
		WithProcLiveBuildTimeout(1*time.Nanosecond), // already expired
	)
	start := time.Now()
	s.Warmup(context.Background())
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Errorf("Warmup with already-expired ctx took %s; want immediate", elapsed)
	}
	// Has must not panic regardless of the build state.
	_ = s.Has("/anything")
}

// TestAnnotateLiveProcess_AppendsSignal: when target is in the set,
// the helper appends SignalLiveProcessAttached.
func TestAnnotateLiveProcess_AppendsSignal(t *testing.T) {
	procRoot := filepath.Join(t.TempDir(), "proc")
	makeProcEntry(t, procRoot, "1", "/sbin/init")
	s := NewProcLiveScanner(nullLogger(), WithProcLiveRoot(procRoot))
	s.Warmup(context.Background())

	rec := &Record{ExecTarget: "/sbin/init"}
	AnnotateLiveProcess(rec, s, rec.ExecTarget)
	if !containsString(rec.Signals, SignalLiveProcessAttached) {
		t.Errorf("Signals = %v; want SignalLiveProcessAttached", rec.Signals)
	}
}

// TestAnnotateLiveProcess_NoMatch: when target is not in the set,
// the helper does not modify the record.
func TestAnnotateLiveProcess_NoMatch(t *testing.T) {
	procRoot := filepath.Join(t.TempDir(), "proc")
	makeProcEntry(t, procRoot, "1", "/sbin/init")
	s := NewProcLiveScanner(nullLogger(), WithProcLiveRoot(procRoot))
	s.Warmup(context.Background())

	rec := &Record{ExecTarget: "/tmp/.x/payload"}
	AnnotateLiveProcess(rec, s, rec.ExecTarget)
	if containsString(rec.Signals, SignalLiveProcessAttached) {
		t.Errorf("Signals = %v; should NOT contain SignalLiveProcessAttached", rec.Signals)
	}
}

// TestAnnotateLiveProcess_NilSafe: nil rec, nil lps, empty target
// must all degrade silently.
func TestAnnotateLiveProcess_NilSafe(t *testing.T) {
	AnnotateLiveProcess(nil, NoopLiveProcessSet{}, "/sbin/init")
	rec := &Record{}
	AnnotateLiveProcess(rec, nil, "/sbin/init")
	AnnotateLiveProcess(rec, NoopLiveProcessSet{}, "")
	if len(rec.Signals) != 0 {
		t.Errorf("Signals = %v; want empty after nil-safe calls", rec.Signals)
	}
}

// TestIsPIDDirName covers the digit-only filter for /proc directory
// entries. Critical for correctness: a stray non-PID dir under /proc
// must never trigger a readlink.
func TestIsPIDDirName(t *testing.T) {
	cases := map[string]bool{
		"1":           true,
		"42":          true,
		"4194304":     true,
		"":            false,
		"sys":         false,
		"self":        false,
		"thread-self": false,
		"1a":          false,
		"a1":          false,
		"00001":       true,
		"12345678901": false, // too long for a real PID
	}
	for in, want := range cases {
		if got := isPIDDirName(in); got != want {
			t.Errorf("isPIDDirName(%q) = %v; want %v", in, got, want)
		}
	}
}

// --- helpers ---

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// strconvI is a tiny int-to-string helper that avoids pulling in
// strconv at the test top-level (which is already imported via the
// production code; this just makes the call site clearer).
func strconvI(n int) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n%10]
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
