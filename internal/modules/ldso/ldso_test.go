package ldso

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

// updateGolden regenerates expected.ndjson files when set:
//
//	go test ./internal/modules/ldso -run TestGolden -update
var updateGolden = flag.Bool("update", false, "rewrite expected.ndjson files instead of comparing")

// fixedMtime mirrors the reference timestamp used by the cron golden
// runner: six weeks before fixedNow so that recent_mtime_7d,
// recent_mtime_30d and recent_target_mtime_7d do NOT fire on stamped
// fixtures by default. Cases that want to exercise those signals
// stamp their own mtime in a future commit.
var fixedMtime = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)

// fixedNow is what the module's Now() returns during tests.
var fixedNow = time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)

// TestGolden iterates every case directory under testdata/golden/ldso
// and runs runGolden against it.
func TestGolden(t *testing.T) {
	goldenDir := filepath.Join("..", "..", "testdata", "golden", "ldso")
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
	if *updateGolden {
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
// files are NOT handled (fixtures use regular files and directories
// only).
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
// fixture: 0755 for directories, 0644 for regular files. No
// executable scripts appear under ldso loci.
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

// redactVolatile zeroes record fields the test runner cannot
// reproduce without root, and drops signals derived from those
// fields. See internal/testdata/golden/ldso/README.md for the
// rationale (same conventions as the cron runner).
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

// --- Normalization equivalence and parser unit tests ---

func TestNormalize_EquivalentInputs_Conf(t *testing.T) {
	a := []byte("/usr/local/lib\ninclude /etc/ld.so.conf.d/*.conf\n")
	b := []byte("# leading comment\n/usr/local/lib    # trailing comment\n  include   /etc/ld.so.conf.d/*.conf  \n\n")
	na := Normalize(a)
	nb := Normalize(b)
	if string(na) != string(nb) {
		t.Fatalf("equivalent inputs differ:\n  a -> %q\n  b -> %q", na, nb)
	}
}

func TestNormalize_OrderIndependent_Conf(t *testing.T) {
	a := []byte("/usr/local/lib\ninclude /etc/ld.so.conf.d/*.conf\n")
	b := []byte("include /etc/ld.so.conf.d/*.conf\n/usr/local/lib\n")
	if string(Normalize(a)) != string(Normalize(b)) {
		t.Fatal("file-level Normalize must be order-independent")
	}
}

func TestNormalizePreload_EquivalentInputs(t *testing.T) {
	a := []byte("/lib/a.so /lib/b.so\n")
	b := []byte("# comment\n  /lib/a.so   /lib/b.so   \n\n")
	na := NormalizePreload(a)
	nb := NormalizePreload(b)
	if string(na) != string(nb) {
		t.Fatalf("equivalent preload inputs differ:\n  a -> %q\n  b -> %q", na, nb)
	}
}

func TestNormalizePreload_OrderIndependent(t *testing.T) {
	a := []byte("/lib/a.so\n/lib/b.so\n")
	b := []byte("/lib/b.so\n/lib/a.so\n")
	if string(NormalizePreload(a)) != string(NormalizePreload(b)) {
		t.Fatal("file-level NormalizePreload must be order-independent")
	}
}

func TestParsePreloadLine_MultiPath(t *testing.T) {
	tokens := parsePreloadLine("/lib/a.so /lib/b.so  /lib/c.so")
	if len(tokens) != 3 {
		t.Fatalf("want 3 tokens, got %d: %v", len(tokens), tokens)
	}
	want := []string{"/lib/a.so", "/lib/b.so", "/lib/c.so"}
	for i, w := range want {
		if tokens[i] != w {
			t.Fatalf("token[%d]: got %q want %q", i, tokens[i], w)
		}
	}
}

func TestParsePreloadLine_InlineComment(t *testing.T) {
	tokens := parsePreloadLine("/lib/x.so # injected by libfoo")
	if len(tokens) != 1 || tokens[0] != "/lib/x.so" {
		t.Fatalf("want [/lib/x.so], got %v", tokens)
	}
}

func TestParsePreloadLine_BlankOrCommentOnly(t *testing.T) {
	if got := parsePreloadLine(""); len(got) != 0 {
		t.Fatalf("blank: got %v", got)
	}
	if got := parsePreloadLine("   \t"); len(got) != 0 {
		t.Fatalf("whitespace-only: got %v", got)
	}
	if got := parsePreloadLine("# just a comment"); len(got) != 0 {
		t.Fatalf("comment-only: got %v", got)
	}
}

func TestParseConfLine_Include(t *testing.T) {
	pl := parseConfLine("include /etc/ld.so.conf.d/*.conf")
	if pl.kind != confLineInclude {
		t.Fatalf("kind: got %v, want confLineInclude", pl.kind)
	}
	if pl.target != "/etc/ld.so.conf.d/*.conf" {
		t.Fatalf("target: %q", pl.target)
	}
}

func TestParseConfLine_IncludeWithCollapsedWhitespace(t *testing.T) {
	pl := parseConfLine("  include    /etc/ld.so.conf.d/*.conf   ")
	if pl.kind != confLineInclude {
		t.Fatalf("kind: %v", pl.kind)
	}
	if pl.target != "/etc/ld.so.conf.d/*.conf" {
		t.Fatalf("target: %q", pl.target)
	}
}

func TestParseConfLine_SearchPath(t *testing.T) {
	pl := parseConfLine("/usr/local/lib")
	if pl.kind != confLineSearchPath {
		t.Fatalf("kind: %v", pl.kind)
	}
	if pl.target != "/usr/local/lib" {
		t.Fatalf("target: %q", pl.target)
	}
}

func TestParseConfLine_BogusIncludePrefix(t *testing.T) {
	// "includebogus" is NOT the include directive because it is
	// not followed by whitespace.
	pl := parseConfLine("includebogus /some/path")
	if pl.kind != confLineSearchPath {
		t.Fatalf("expected search-path for 'includebogus', got %v", pl.kind)
	}
	if !strings.HasPrefix(pl.target, "includebogus") {
		t.Fatalf("target: %q", pl.target)
	}
}

func TestParseConfLine_InlineComment(t *testing.T) {
	pl := parseConfLine("/usr/local/lib  # added for libfoo")
	if pl.kind != confLineSearchPath {
		t.Fatalf("kind: %v", pl.kind)
	}
	if pl.target != "/usr/local/lib" {
		t.Fatalf("target: %q", pl.target)
	}
}

func TestParseConfLine_Empty(t *testing.T) {
	for _, in := range []string{"", "   ", "# only a comment", "\t"} {
		if got := parseConfLine(in); got.kind != confLineEmpty {
			t.Fatalf("input %q: kind %v, want confLineEmpty", in, got.kind)
		}
	}
}

func TestHasGlobMeta(t *testing.T) {
	cases := map[string]bool{
		"/etc/ld.so.conf.d/*.conf": true,
		"/etc/file?.conf":          true,
		"/etc/[a-z].conf":          true,
		"/usr/local/lib":           false,
		"":                         false,
	}
	for in, want := range cases {
		if got := hasGlobMeta(in); got != want {
			t.Fatalf("hasGlobMeta(%q): got %v, want %v", in, got, want)
		}
	}
}
