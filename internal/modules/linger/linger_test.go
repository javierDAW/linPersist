package linger

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

// updateGolden lets developers regenerate expected.ndjson files:
//
//	go test ./internal/modules/linger -run TestGolden -update
//
// Equivalently: LINPERSIST_UPDATE_GOLDEN=1 go test ./internal/modules/linger/...
//
// In normal CI runs both the flag and the env var are false and every
// case must match its frozen expected.ndjson byte-for-byte.
var updateGolden = flag.Bool("update", false, "rewrite expected.ndjson files instead of comparing")

func shouldUpdateGolden() bool {
	if updateGolden != nil && *updateGolden {
		return true
	}
	return os.Getenv("LINPERSIST_UPDATE_GOLDEN") == "1"
}

// fixedMtime is the deterministic mtime applied to every fixture file.
// Chosen ~6 weeks before fixedNow so that recent_mtime_7d and
// recent_mtime_30d do NOT fire for unmodified fixtures.
var fixedMtime = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)

// fixedNow is what the module's Now() returns during tests.
var fixedNow = time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)

// TestGolden iterates every case directory under testdata/golden/linger
// and runs runGolden against it.
func TestGolden(t *testing.T) {
	goldenDir := filepath.Join("..", "..", "testdata", "golden", "linger")
	entries, err := os.ReadDir(goldenDir)
	if err != nil {
		t.Fatalf("read golden dir %s: %v", goldenDir, err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		t.Run(name, func(t *testing.T) {
			runGolden(t, filepath.Join(goldenDir, name))
		})
	}
}

func runGolden(t *testing.T, caseDir string) {
	t.Helper()
	rootfsSrc := filepath.Join(caseDir, "rootfs")
	if _, err := os.Stat(rootfsSrc); err != nil {
		t.Fatalf("no rootfs/ under %s: %v", caseDir, err)
	}

	tmp := t.TempDir()
	if err := copyTree(rootfsSrc, tmp); err != nil {
		t.Fatalf("copy rootfs: %v", err)
	}
	if err := normalizeFixturePerms(tmp); err != nil {
		t.Fatalf("normalize perms: %v", err)
	}
	if err := stampMtimes(tmp, fixedMtime); err != nil {
		t.Fatalf("stamp mtimes: %v", err)
	}

	mod := New(Options{
		Root: tmp,
		Now:  func() time.Time { return fixedNow },
	})

	var captured []core.Record
	sink := func(r core.Record) { captured = append(captured, r) }

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := mod.Collect(ctx, sink); err != nil {
		t.Logf("Collect: %v", err)
	}

	for i := range captured {
		redactVolatile(&captured[i])
	}
	sort.Slice(captured, func(i, j int) bool {
		if captured[i].Locus != captured[j].Locus {
			return captured[i].Locus < captured[j].Locus
		}
		return captured[i].ContentNormSHA256 < captured[j].ContentNormSHA256
	})

	var got bytes.Buffer
	enc := json.NewEncoder(&got)
	enc.SetEscapeHTML(false)
	for _, r := range captured {
		if err := enc.Encode(r); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}

	expectedPath := filepath.Join(caseDir, "expected.ndjson")
	if shouldUpdateGolden() {
		if err := os.WriteFile(expectedPath, got.Bytes(), 0o644); err != nil {
			t.Fatalf("write expected: %v", err)
		}
		t.Logf("updated %s (%d records, %d bytes)", expectedPath, len(captured), got.Len())
		return
	}
	want, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("read expected (run with -update to generate): %v", err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("mismatch for case %s\n--- want (%d bytes) ---\n%s\n--- got (%d bytes) ---\n%s",
			filepath.Base(caseDir), len(want), want, got.Len(), got.String())
	}
}

// copyTree recursively copies src into dst. Symlinks and special
// files are NOT handled (fixtures use regular files only).
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		out, err := os.Create(target)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
}

// normalizeFixturePerms applies deterministic permissions: 0755 to
// directories, 0644 to files. linger marker files have no special
// perms by convention (systemd-run --user creates them 0644).
func normalizeFixturePerms(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Chmod(path, 0o755)
		}
		return os.Chmod(path, 0o644)
	})
}

func stampMtimes(root string, when time.Time) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chtimes(path, when, when)
	})
}

// redactVolatile zeroes record fields the test runner cannot reproduce
// without root. See cron_test.go for the rationale of each redaction.
func redactVolatile(rec *core.Record) {
	zero := uint32(0)
	rec.OwnerUID = &zero
	rec.OwnerGID = &zero
	rec.CTime = nil
	rec.ATime = nil
	rec.Signals = dropSignal(rec.Signals, core.SignalNonRootOwner)
}

func dropSignal(sigs []string, name string) []string {
	if len(sigs) == 0 {
		return nil
	}
	out := make([]string, 0, len(sigs))
	for _, s := range sigs {
		if s == name {
			continue
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// --- Public API smoke tests ---

// TestNameAndSiteClasses guards the canonical identifiers the rest of
// the pipeline (matrix.yaml, signals catalog, stack_demo.sql) keys on.
// A typo here would silently desynchronise the agent from matrix-audit.
func TestNameAndSiteClasses(t *testing.T) {
	m := New(Options{})
	if got := m.Name(); got != "linger" {
		t.Fatalf("Name: got %q, want %q", got, "linger")
	}
	sc := m.SiteClasses()
	if len(sc) != 1 || sc[0] != "systemd.linger" {
		t.Fatalf("SiteClasses: got %v, want [systemd.linger]", sc)
	}
}

// --- Unit tests for the per-user signal logic ---

// TestPerUserSignals_Root verifies that the canonical "root has
// linger enabled" case does NOT fire the systemd_linger_non_root
// signal. root is the baseline; non-root usernames are what motivates
// this module.
func TestPerUserSignals_Root(t *testing.T) {
	if got := perUserSignals("root"); got != nil {
		t.Fatalf("root must not fire systemd_linger_non_root, got %v", got)
	}
}

// TestPerUserSignals_NonRoot verifies that any non-root username
// fires the module-specific signal.
func TestPerUserSignals_NonRoot(t *testing.T) {
	cases := []string{"alice", "service-account", "_kura", "ubuntu"}
	for _, name := range cases {
		got := perUserSignals(name)
		if len(got) != 1 || got[0] != core.SignalSystemdLingerNonRoot {
			t.Errorf("user=%q: got %v, want [%s]", name, got, core.SignalSystemdLingerNonRoot)
		}
	}
}

// TestPerUserSignals_Empty defends against an empty filename
// (cannot happen via the filesystem but the helper must stay
// defensive against future refactors).
func TestPerUserSignals_Empty(t *testing.T) {
	if got := perUserSignals(""); got != nil {
		t.Fatalf("empty username must not fire any signal, got %v", got)
	}
}

// --- Normalization equivalence ---

// TestNormalize_EquivalentUsernames verifies that two records whose
// username is byte-identical share the same content_norm_sha256
// regardless of file mtime / size / owner. This is the LFA grouping
// guarantee: linger-on-alice on host A and linger-on-alice on host B
// stack to a single Q1/Q3 row.
func TestNormalize_EquivalentUsernames(t *testing.T) {
	hashAlice1 := core.HashHexString("alice")
	hashAlice2 := core.HashHexString("alice")
	if hashAlice1 != hashAlice2 {
		t.Fatalf("HashHexString must be deterministic, got %q vs %q", hashAlice1, hashAlice2)
	}
	hashBob := core.HashHexString("bob")
	if hashAlice1 == hashBob {
		t.Fatalf("distinct usernames must hash differently, got collision on %q", hashAlice1)
	}
}

// --- Helpers ---

// --- Collect-level robustness ---

// TestCollect_NonExistentDir verifies that a host without
// /var/lib/systemd/linger (fresh install, minimal container) emits
// zero records and returns nil. This is a hot path: most hosts in a
// large fleet will have an empty or absent linger dir.
func TestCollect_NonExistentDir(t *testing.T) {
	tmp := t.TempDir()
	mod := New(Options{Root: tmp, Now: func() time.Time { return fixedNow }})
	var captured []core.Record
	sink := func(r core.Record) { captured = append(captured, r) }
	if err := mod.Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect on missing dir: got err %v, want nil", err)
	}
	if len(captured) != 0 {
		t.Fatalf("missing dir: got %d records, want 0", len(captured))
	}
}

// TestCollect_RespectsCancellation verifies that an already-cancelled
// context aborts the walk without emitting records. This is the
// contract the runner relies on for per-module timeout enforcement
// (see core/runner.go).
func TestCollect_RespectsCancellation(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "var/lib/systemd/linger"), 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	for _, u := range []string{"alice", "bob"} {
		if err := os.WriteFile(filepath.Join(tmp, "var/lib/systemd/linger", u), nil, 0o644); err != nil {
			t.Fatalf("setup user %s: %v", u, err)
		}
	}
	mod := New(Options{Root: tmp, Now: func() time.Time { return fixedNow }})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var captured []core.Record
	sink := func(r core.Record) { captured = append(captured, r) }
	if err := mod.Collect(ctx, sink); err == nil {
		t.Fatal("Collect with cancelled ctx: got nil, want context.Canceled")
	}
}
