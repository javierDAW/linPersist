package udev

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

var updateGolden = flag.Bool("update", false, "rewrite expected.ndjson files")

func shouldUpdateGolden() bool {
	if updateGolden != nil && *updateGolden {
		return true
	}
	return os.Getenv("LINPERSIST_UPDATE_GOLDEN") == "1"
}

var fixedMtime = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
var fixedNow = time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC)

func TestGolden(t *testing.T) {
	goldenDir := filepath.Join("..", "..", "testdata", "golden", "udev")
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
		t.Fatalf("copy: %v", err)
	}
	if err := normalizeFixturePerms(tmp); err != nil {
		t.Fatalf("perms: %v", err)
	}
	if err := stampMtimes(tmp, fixedMtime); err != nil {
		t.Fatalf("stamp: %v", err)
	}
	mod := New(Options{Root: tmp, Now: func() time.Time { return fixedNow }})
	var captured []core.Record
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := mod.Collect(ctx, func(r core.Record) { captured = append(captured, r) }); err != nil {
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
		fmt.Fprintf(os.Stderr, "GOLDEN UPDATED: %s (%d records, %d bytes)\n",
			expectedPath, len(captured), got.Len())
		return
	}
	want, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("read expected (env LINPERSIST_UPDATE_GOLDEN=1 to generate): %v", err)
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

// --- parseRules tests ---

func TestParseRules_JoinsBackslashContinuations(t *testing.T) {
	in := []byte("KERNEL==\"sda*\", \\\n    SUBSYSTEM==\"block\", \\\n    RUN+=\"/x\"\n")
	got := parseRules(in)
	if len(got) != 1 {
		t.Fatalf("expected one rule, got %d: %v", len(got), got)
	}
}

func TestParseRules_DropsCommentsAndBlanks(t *testing.T) {
	in := []byte("# header\n\nKERNEL==\"a\", RUN+=\"/x\"\n\n# trailing\n")
	got := parseRules(in)
	if len(got) != 1 {
		t.Fatalf("expected 1 rule, got %d: %v", len(got), got)
	}
}

// --- normalizeRule tests ---

func TestNormalizeRule_CollapsesWhitespaceOutsideQuotes(t *testing.T) {
	in := "KERNEL==\"sda*\"   ,   SUBSYSTEM==\"block\""
	got := normalizeRule(in)
	want := "KERNEL==\"sda*\", SUBSYSTEM==\"block\""
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestNormalizeRule_PreservesQuotedWhitespace(t *testing.T) {
	// Internal double space in the quoted value MUST survive.
	in := `RUN+="/bin/sh -c 'a  b'"`
	got := normalizeRule(in)
	want := `RUN+="/bin/sh -c 'a  b'"`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestNormalizeRule_CommaSpacing(t *testing.T) {
	in := `KERNEL=="a" ,SUBSYSTEM=="b",RUN+="/x"`
	got := normalizeRule(in)
	want := `KERNEL=="a", SUBSYSTEM=="b", RUN+="/x"`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestNormalizeRule_Idempotent(t *testing.T) {
	in := `   KERNEL=="a"   ,   RUN+="/x"   `
	once := normalizeRule(in)
	twice := normalizeRule(once)
	if once != twice {
		t.Fatalf("not idempotent: once=%q twice=%q", once, twice)
	}
}

func TestNormalizeRule_EmptyInput(t *testing.T) {
	if got := normalizeRule(""); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

// --- extractAssignmentValue tests ---

func TestExtractAssignmentValue_Run(t *testing.T) {
	rule := `KERNEL=="a", RUN+="/usr/local/bin/foo --arg"`
	v, ok := extractAssignmentValue(rule, "RUN")
	if !ok {
		t.Fatalf("expected hit, got !ok")
	}
	want := "/usr/local/bin/foo --arg"
	if v != want {
		t.Fatalf("got %q want %q", v, want)
	}
}

func TestExtractAssignmentValue_Program(t *testing.T) {
	rule := `KERNEL=="a", PROGRAM="/lib/udev/helper", SYMLINK+="x"`
	v, ok := extractAssignmentValue(rule, "PROGRAM")
	if !ok {
		t.Fatalf("expected hit")
	}
	if v != "/lib/udev/helper" {
		t.Fatalf("got %q", v)
	}
}

func TestExtractAssignmentValue_RunWithBraceArg(t *testing.T) {
	rule := `KERNEL=="a", RUN{program}+="/x"`
	v, ok := extractAssignmentValue(rule, "RUN")
	if !ok {
		t.Fatalf("expected hit on RUN{program}+=")
	}
	if v != "/x" {
		t.Fatalf("got %q", v)
	}
}

func TestExtractAssignmentValue_KeyNotPresent(t *testing.T) {
	rule := `KERNEL=="a", SYMLINK+="x"`
	if _, ok := extractAssignmentValue(rule, "RUN"); ok {
		t.Fatalf("unexpected hit")
	}
}

func TestExtractAssignmentValue_WordBoundary(t *testing.T) {
	// A key that happens to contain "RUN" as a substring must not
	// match.
	rule := `KERNEL=="a", PRERUN_HOOK=="foo"`
	if _, ok := extractAssignmentValue(rule, "RUN"); ok {
		t.Fatalf("unexpected hit on PRERUN_HOOK")
	}
}

// --- Normalize file-level test ---

func TestNormalize_File(t *testing.T) {
	in := []byte("# header\n\nKERNEL==\"a\"  ,   RUN+=\"/x\"\nKERNEL==\"b\", RUN+=\"/y\"\n")
	got := string(Normalize(in))
	want := "KERNEL==\"a\", RUN+=\"/x\"\nKERNEL==\"b\", RUN+=\"/y\"\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
