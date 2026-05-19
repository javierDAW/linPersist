package xdg

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

var updateGolden = flag.Bool("update", false, "rewrite expected.ndjson files instead of comparing")

func shouldUpdateGolden() bool {
	if updateGolden != nil && *updateGolden {
		return true
	}
	return os.Getenv("LINPERSIST_UPDATE_GOLDEN") == "1"
}

var fixedMtime = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
var fixedNow = time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC)

// TestGolden runs every subdirectory under testdata/golden/xdg/ as a
// case. Each case has a rootfs/ tree the module collects against, and
// an expected.ndjson the test compares to. Run with -update or
// LINPERSIST_UPDATE_GOLDEN=1 to regenerate expected.ndjson files.
func TestGolden(t *testing.T) {
	goldenDir := filepath.Join("..", "..", "testdata", "golden", "xdg")
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
		t.Fatalf("read expected (run with -update OR env LINPERSIST_UPDATE_GOLDEN=1 to generate): %v", err)
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

// redactVolatile zeroes fields that vary between test runs and
// environments (uid/gid from filesystem, ctime/atime). The
// non_root_owner signal is also dropped because it depends on the
// uid the test runs as.
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

// --- Parser unit tests ---

func TestParseDesktop_BasicSections(t *testing.T) {
	in := []byte(`# header comment

[Desktop Entry]
Type=Application
Name=Foo
Exec=/usr/bin/foo --arg
Icon=foo

[Desktop Action OpenDir]
Name=Open Directory
Exec=/usr/bin/foo --dir
`)
	pd := parseDesktop(in)
	if len(pd.sections) != 2 {
		t.Fatalf("sections = %d; want 2", len(pd.sections))
	}
	if pd.sections[0].name != "Desktop Entry" {
		t.Errorf("section[0].name = %q; want Desktop Entry", pd.sections[0].name)
	}
	if got := pd.sections[0].keys["Exec"]; got != "/usr/bin/foo --arg" {
		t.Errorf("Exec = %q; want /usr/bin/foo --arg", got)
	}
	if pd.sections[1].name != "Desktop Action OpenDir" {
		t.Errorf("section[1].name = %q; want Desktop Action OpenDir", pd.sections[1].name)
	}
}

func TestParseDesktop_DropsLocaleKeys(t *testing.T) {
	in := []byte(`[Desktop Entry]
Name=Default
Name[en]=English
Name[de]=Deutsch
Comment=A thing
Comment[es]=Una cosa
`)
	pd := parseDesktop(in)
	sec := pd.section("Desktop Entry")
	if sec == nil {
		t.Fatal("no [Desktop Entry] section")
	}
	for k := range sec.keys {
		if k != "Name" && k != "Comment" {
			t.Errorf("unexpected key %q (locale variants must be dropped)", k)
		}
	}
}

func TestCanonical_EquivalentInputsCollapse(t *testing.T) {
	a := []byte(`# Auto-generated
[Desktop Entry]
Type=Application
Name=Foo
Exec=/usr/bin/foo
Icon=foo
`)
	b := []byte(`[Desktop Entry]
Exec=/usr/bin/foo
Type=Application

# comment moved here
Name=Foo
Icon=foo

`)
	c := []byte(`[Desktop Entry]
Name=Foo
Exec=/usr/bin/foo
Type=Application
Icon=foo
Name[fr]=Foo en francais
`)
	canA := string(canonical(parseDesktop(a)))
	canB := string(canonical(parseDesktop(b)))
	canC := string(canonical(parseDesktop(c)))
	if canA != canB {
		t.Errorf("a vs b differ:\n%s\n---\n%s", canA, canB)
	}
	if canA != canC {
		t.Errorf("a vs c differ:\n%s\n---\n%s", canA, canC)
	}
}

func TestExtractExec_StripsFieldCodes(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/usr/bin/foo", "/usr/bin/foo"},
		{"/usr/bin/foo %U", "/usr/bin/foo"},
		{"/usr/bin/foo --arg %F", "/usr/bin/foo"},
		{`"/usr/bin/foo bar" %U`, "/usr/bin/foo bar"},
		{"foo --percent %% sign", "foo"},
		{"/usr/bin/foo%c-suffix", "/usr/bin/foo-suffix"},
	}
	for _, tc := range cases {
		pd := parseDesktop([]byte("[Desktop Entry]\nExec=" + tc.in + "\n"))
		got := extractExec(pd)
		if got != tc.want {
			t.Errorf("extractExec(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

func TestExtractExec_NoExec(t *testing.T) {
	pd := parseDesktop([]byte("[Desktop Entry]\nType=Link\nURL=https://example.org\n"))
	if got := extractExec(pd); got != "" {
		t.Errorf("extractExec on URL-type entry = %q; want empty", got)
	}
}

func TestStripFieldCodes_PercentPercent(t *testing.T) {
	if got := stripFieldCodes("100%% complete"); got != "100% complete" {
		t.Errorf("got %q; want %q", got, "100% complete")
	}
}
