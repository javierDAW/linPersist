package cron

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
	"strings"
	"testing"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

// updateGolden lets developers regenerate expected.ndjson files:
//
//	go test ./internal/modules/cron -run TestGolden -update
//
// Equivalently: LINPERSIST_UPDATE_GOLDEN=1 go test ./internal/modules/cron/...
//
// In normal CI runs both the flag and the env var are false and every
// case must match its frozen expected.ndjson byte-for-byte.
var updateGolden = flag.Bool("update", false, "rewrite expected.ndjson files instead of comparing")

// shouldUpdateGolden returns true when the test binary should regenerate
// expected.ndjson files. The -update flag is the primary trigger;
// LINPERSIST_UPDATE_GOLDEN=1 is a fallback for shells that pass env
// vars more naturally than test flags.
func shouldUpdateGolden() bool {
	if updateGolden != nil && *updateGolden {
		return true
	}
	return os.Getenv("LINPERSIST_UPDATE_GOLDEN") == "1"
}

// fixedMtime is the deterministic mtime applied to every fixture file
// by the test runner. Chosen ~6 weeks before fixedNow so that
// recent_mtime_7d and recent_mtime_30d do NOT fire for unmodified
// fixtures; cases that want to exercise those signals stamp their own
// mtime in a future commit.
var fixedMtime = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)

// fixedNow is what the module's Now() returns during tests. Mirrors
// the reference timestamp documented in internal/testdata/golden/cron/README.md.
var fixedNow = time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)

// TestGolden iterates every case directory under testdata/golden/cron
// and runs runGolden against it.
func TestGolden(t *testing.T) {
	goldenDir := filepath.Join("..", "..", "testdata", "golden", "cron")
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
		// Module-level errors are non-fatal for the test; per-record
		// errors live in Record.Errors. Log for visibility.
		t.Logf("Collect: %v", err)
	}

	for i := range captured {
		redactVolatile(&captured[i])
	}
	sort.Slice(captured, func(i, j int) bool {
		if captured[i].Locus != captured[j].Locus {
			return captured[i].Locus < captured[j].Locus
		}
		if captured[i].ContentNormSHA256 != captured[j].ContentNormSHA256 {
			return captured[i].ContentNormSHA256 < captured[j].ContentNormSHA256
		}
		return captured[i].ExecTarget < captured[j].ExecTarget
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

// normalizeFixturePerms applies deterministic permissions across the
// fixture: 0755 to scripts under run-parts directories, 0644 elsewhere.
func normalizeFixturePerms(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Chmod(path, 0o755)
		}
		rel, _ := filepath.Rel(root, path)
		if isPeriodicPath(rel) {
			return os.Chmod(path, 0o755)
		}
		return os.Chmod(path, 0o644)
	})
}

func isPeriodicPath(rel string) bool {
	rel = filepath.ToSlash(rel)
	for _, prefix := range []string{
		"etc/cron.hourly/", "etc/cron.daily/",
		"etc/cron.weekly/", "etc/cron.monthly/",
	} {
		if strings.HasPrefix(rel, prefix) {
			return true
		}
	}
	return false
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
// without root, and drops signals that are derived from those fields.
//
// owner_uid/owner_gid: forced to 0 (the test runner cannot chown root,
// so the live values are the developer's uid; the production reality is
// that /etc/* artifacts are uid 0).
//
// non_root_owner signal: dropped, because it is computed from the live
// uid which is volatile across machines. Redacting the field without
// redacting the derived signal would leave the record internally
// inconsistent (owner_uid=0 alongside a signal that means uid!=0).
//
// ctime: dropped (os.Chtimes does not control ctime).
// atime: dropped (volatile across filesystems and mount options).
func redactVolatile(rec *core.Record) {
	zero := uint32(0)
	rec.OwnerUID = &zero
	rec.OwnerGID = &zero
	rec.CTime = nil
	rec.ATime = nil
	rec.Signals = dropSignal(rec.Signals, core.SignalNonRootOwner)
}

// dropSignal returns a copy of sigs with every occurrence of name
// removed. Returns nil if the result is empty, matching the
// omitempty behavior of Record.Signals.
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

// --- Normalization equivalence and parser unit tests ---

func TestNormalize_EquivalentInputs_CronD(t *testing.T) {
	a := []byte("MAILTO=root\n* * * * * root /bin/true\n")
	b := []byte("# header comment\nMAILTO=root\n*   *   *   *   *   root   /bin/true   \n\n")
	na := Normalize(a, true)
	nb := Normalize(b, true)
	if string(na) != string(nb) {
		t.Fatalf("equivalent inputs differ:\n  a -> %q\n  b -> %q", na, nb)
	}
}

func TestNormalize_OrderIndependent(t *testing.T) {
	a := []byte("0 3 * * * root /a.sh\n@reboot root /b.sh\nMAILTO=root\n")
	b := []byte("MAILTO=root\n@reboot root /b.sh\n0 3 * * * root /a.sh\n")
	if string(Normalize(a, true)) != string(Normalize(b, true)) {
		t.Fatal("file-level Normalize must be order-independent")
	}
}

func TestParseCrontabLine_VarAssignment(t *testing.T) {
	pl := parseCrontabLine("MAILTO=root", true)
	if pl.kind != lineVarAssignment {
		t.Fatalf("kind: got %v, want lineVarAssignment", pl.kind)
	}
	if pl.varName != "MAILTO" || pl.varValue != "root" {
		t.Fatalf("name=%q value=%q", pl.varName, pl.varValue)
	}
}

func TestParseCrontabLine_ScheduleWithUser(t *testing.T) {
	pl := parseCrontabLine("0 3 * * * root /opt/backup.sh --target s3", true)
	if pl.kind != lineScheduleEntry {
		t.Fatalf("kind: %v", pl.kind)
	}
	if pl.schedule != "0 3 * * *" {
		t.Fatalf("schedule: %q", pl.schedule)
	}
	if pl.user != "root" {
		t.Fatalf("user: %q", pl.user)
	}
	if pl.command != "/opt/backup.sh --target s3" {
		t.Fatalf("command: %q", pl.command)
	}
}

func TestParseCrontabLine_AtReboot(t *testing.T) {
	pl := parseCrontabLine("@reboot alice /home/alice/init.sh", true)
	if pl.schedule != "@reboot" {
		t.Fatalf("schedule: %q", pl.schedule)
	}
	if pl.user != "alice" || pl.command != "/home/alice/init.sh" {
		t.Fatalf("user/command: %q / %q", pl.user, pl.command)
	}
}

func TestParseCrontabLine_NoUserFormat(t *testing.T) {
	pl := parseCrontabLine("@daily /home/alice/cleanup.sh", false)
	if pl.kind != lineScheduleEntry {
		t.Fatalf("kind: %v", pl.kind)
	}
	if pl.user != "" {
		t.Fatalf("user should be empty for cron.user format: %q", pl.user)
	}
	if pl.command != "/home/alice/cleanup.sh" {
		t.Fatalf("command: %q", pl.command)
	}
}

func TestParseCrontabLine_MalformedTooFewFields(t *testing.T) {
	pl := parseCrontabLine("* * * *", true)
	if pl.kind != lineMalformed {
		t.Fatalf("kind: got %v, want lineMalformed", pl.kind)
	}
}

func TestParseAnacrontabLine(t *testing.T) {
	pl := parseAnacrontabLine("1 5 cron.daily run-parts /etc/cron.daily")
	if pl.kind != lineScheduleEntry {
		t.Fatalf("kind: %v", pl.kind)
	}
	if pl.schedule != "1 5" {
		t.Fatalf("schedule: %q", pl.schedule)
	}
	if pl.user != "cron.daily" {
		t.Fatalf("jobid: %q", pl.user)
	}
	if pl.command != "run-parts /etc/cron.daily" {
		t.Fatalf("command: %q", pl.command)
	}
}
