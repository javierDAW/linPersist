package tmpfiles

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
//	go test ./internal/modules/tmpfiles -run TestGolden -update
//
// Equivalently: LINPERSIST_UPDATE_GOLDEN=1 go test ./internal/modules/tmpfiles/...
var updateGolden = flag.Bool("update", false, "rewrite expected.ndjson files instead of comparing")

func shouldUpdateGolden() bool {
	if updateGolden != nil && *updateGolden {
		return true
	}
	return os.Getenv("LINPERSIST_UPDATE_GOLDEN") == "1"
}

var fixedMtime = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
var fixedNow = time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)

// TestGolden iterates every case directory under testdata/golden/tmpfiles
// and runs runGolden against it.
func TestGolden(t *testing.T) {
	goldenDir := filepath.Join("..", "..", "testdata", "golden", "tmpfiles")
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
// the pipeline keys on.
func TestNameAndSiteClasses(t *testing.T) {
	m := New(Options{})
	if got := m.Name(); got != "tmpfiles" {
		t.Fatalf("Name: got %q, want %q", got, "tmpfiles")
	}
	sc := m.SiteClasses()
	if len(sc) != 1 || sc[0] != "systemd.tmpfiles" {
		t.Fatalf("SiteClasses: got %v, want [systemd.tmpfiles]", sc)
	}
}

// --- Parser unit tests ---

// TestParseFields_QuotedArgument verifies the argument field can
// carry whitespace inside double quotes -- tmpfiles.d uses this for
// inline file contents in w/w+ directives.
func TestParseFields_QuotedArgument(t *testing.T) {
	got := parseFields(`f /etc/foo 0644 root root - "hello world"`)
	if len(got) != 7 {
		t.Fatalf("len: got %d, want 7 (%v)", len(got), got)
	}
	if got[6] != "hello world" {
		t.Errorf("argument: got %q, want %q", got[6], "hello world")
	}
}

// --- Directive signal calibration tests (ADR-0014) ---

// TestDirectiveSignals_CreatesPayloadAtBoot is the central positive
// case: a file-creating type letter targeting a fixed path under a
// tmp-class directory. This is the implant fingerprint.
func TestDirectiveSignals_CreatesPayloadAtBoot(t *testing.T) {
	for _, raw := range []string{
		"f /tmp/.cache/payload 0755 root root - /opt/implant",
		"F /var/tmp/restore.bin 0755 root root - /opt/implant",
		"w /dev/shm/secret 0644 root root - data",
		"f+ /run/shm/agent 0755 root root - /opt/agent",
	} {
		got := directiveSignals(parseFields(raw))
		if len(got) != 1 || got[0] != core.SignalTmpfilesCreatesUnderTmp {
			t.Errorf("input=%q: got %v, want [%s]", raw, got, core.SignalTmpfilesCreatesUnderTmp)
		}
	}
}

// TestDirectiveSignals_X11AllowList covers the baseline-of-baseline
// case: every host with X11 libraries has these socket dirs declared
// in vendor tmpfiles.d files. They must NOT fire.
func TestDirectiveSignals_X11AllowList(t *testing.T) {
	for _, raw := range []string{
		"d /tmp/.X11-unix 1777 root root -",
		"f /tmp/.ICE-unix 0644 root root -",
		"d /tmp/.XIM-unix 1777 root root -",
		"d /tmp/.font-unix 1777 root root -",
		"d /tmp/.Test-unix 1777 root root -",
	} {
		got := directiveSignals(parseFields(raw))
		if got != nil {
			t.Errorf("X11 baseline must not fire: input=%q got %v", raw, got)
		}
	}
}

// TestDirectiveSignals_GlobTemplateRejected covers paths that contain
// tmpfiles.d glob / template metacharacters. systemd-private-%b-* and
// dnf*/locks/* are templated by design; an attacker plants a fixed
// path. The signal must not fire when the path has *, ?, %, [ or ].
func TestDirectiveSignals_GlobTemplateRejected(t *testing.T) {
	for _, raw := range []string{
		"f /tmp/run-%I.lock 0644 root root - -",
		"f /tmp/cache-*.dat 0644 root root - -",
		"f /tmp/queue-?.tmp 0644 root root - -",
		"f /var/tmp/sess[0-9].id 0644 root root - -",
	} {
		got := directiveSignals(parseFields(raw))
		if got != nil {
			t.Errorf("globbed path must not fire: input=%q got %v", raw, got)
		}
	}
}

// TestDirectiveSignals_NonCreateTypes verifies the type-letter filter:
// directives that do NOT create files (d/D directories, L symlink,
// C/c copy, b block, p fifo) must NOT fire even when targeting a
// tmp-class path. v1 of the calibration fired 108 false positives
// because it lacked this filter.
func TestDirectiveSignals_NonCreateTypes(t *testing.T) {
	for _, raw := range []string{
		"d /tmp/foo 1777 root root -",
		"D /tmp/bar 1777 root root -",
		"L /tmp/link - - - - /target",
		"C /tmp/copy 0644 root root - /source",
		"c /tmp/dev 0644 root root - -",
		"b /tmp/blk 0644 root root - -",
		"p /tmp/fifo 0644 root root - -",
	} {
		got := directiveSignals(parseFields(raw))
		if got != nil {
			t.Errorf("non-create type must not fire: input=%q got %v", raw, got)
		}
	}
}

// TestDirectiveSignals_NonTmpPath verifies the path prefix gate:
// file-creating directives targeting paths OUTSIDE /tmp, /var/tmp,
// /dev/shm or /run/shm must not fire. Most legitimate f-directives
// land under /var/lib or /var/log.
func TestDirectiveSignals_NonTmpPath(t *testing.T) {
	for _, raw := range []string{
		"f /var/lib/app/state 0644 root root - -",
		"f /var/log/app.log 0644 root root - -",
		"f /run/app/sock 0644 root root - -",
	} {
		got := directiveSignals(parseFields(raw))
		if got != nil {
			t.Errorf("non-tmp path must not fire: input=%q got %v", raw, got)
		}
	}
}

// TestDirectiveSignals_TooFewFields handles malformed lines.
func TestDirectiveSignals_TooFewFields(t *testing.T) {
	for _, raw := range []string{"f", "", "  "} {
		got := directiveSignals(parseFields(raw))
		if got != nil {
			t.Errorf("malformed=%q must not fire, got %v", raw, got)
		}
	}
}

// --- Normalization equivalence ---

// TestNormalize_WhitespaceCollapsed is the LFA grouping guarantee:
// two directives that differ only in whitespace MUST share their
// canonical form. Otherwise stacking joins miss.
func TestNormalize_WhitespaceCollapsed(t *testing.T) {
	a := "f /tmp/x 0644 root root - -"
	b := "f\t/tmp/x   0644 root root    -    -"
	if canonicalDirective(a) != canonicalDirective(b) {
		t.Fatalf("equivalent directives differ:\n  a -> %q\n  b -> %q",
			canonicalDirective(a), canonicalDirective(b))
	}
}

// TestNormalize_QuotedSegmentPreserved verifies whitespace INSIDE
// quoted segments stays verbatim; two directives that differ only
// inside the quoted argument must NOT collide.
func TestNormalize_QuotedSegmentPreserved(t *testing.T) {
	a := canonicalDirective(`w /tmp/msg 0644 root root - "hello world"`)
	b := canonicalDirective(`w /tmp/msg 0644 root root - "hello  world"`)
	if a == b {
		t.Fatalf("quoted whitespace must be preserved; both -> %q", a)
	}
}

// --- Collect-level robustness ---

// TestCollect_NonExistentDir verifies the module returns nil and zero
// records on a host without any tmpfiles.d directories. Minimal
// containers often ship neither /etc/tmpfiles.d nor /usr/lib/tmpfiles.d.
func TestCollect_NonExistentDir(t *testing.T) {
	tmp := t.TempDir()
	mod := New(Options{Root: tmp, Now: func() time.Time { return fixedNow }})
	var captured []core.Record
	sink := func(r core.Record) { captured = append(captured, r) }
	if err := mod.Collect(context.Background(), sink); err != nil {
		t.Fatalf("missing dirs: got err %v, want nil", err)
	}
	if len(captured) != 0 {
		t.Fatalf("missing dirs: got %d records, want 0", len(captured))
	}
}

// TestCollect_OversizedFile triggers the SIZE_LIMIT envelope path.
func TestCollect_OversizedFile(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "etc/tmpfiles.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	big := bytes.Repeat([]byte("f /var/lib/app/state 0644 root root - -\n"), 4096)
	if err := os.WriteFile(filepath.Join(dir, "huge.conf"), big, 0o644); err != nil {
		t.Fatalf("write big: %v", err)
	}
	mod := New(Options{
		Root:        tmp,
		Now:         func() time.Time { return fixedNow },
		MaxFileSize: 1024,
	})
	var captured []core.Record
	sink := func(r core.Record) { captured = append(captured, r) }
	if err := mod.Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(captured) != 1 {
		t.Fatalf("got %d records, want 1 envelope", len(captured))
	}
	if len(captured[0].Errors) != 1 || captured[0].Errors[0].Code != "SIZE_LIMIT" {
		t.Fatalf("expected SIZE_LIMIT envelope, got %+v", captured[0].Errors)
	}
}
