package grub

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

func TestGolden(t *testing.T) {
	goldenDir := filepath.Join("..", "..", "testdata", "golden", "grub")
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
		// /etc/grub.d/* are executables, /etc/default/grub is data.
		// Set both to 0644 -- the file metadata determinism matters
		// more than the actual exec bit for golden tests.
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

// --- Parser unit tests ---

func TestParseConfig_BasicAssignments(t *testing.T) {
	in := []byte(`# Default GRUB config.

GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_CMDLINE_LINUX=""

# Trailing comment.
`)
	entries := ParseConfig(in)
	if len(entries) != 4 {
		t.Fatalf("entries = %d; want 4", len(entries))
	}
	got := map[string]string{}
	for _, e := range entries {
		got[e.Key] = e.Value
	}
	wants := map[string]string{
		"GRUB_DEFAULT":               "0",
		"GRUB_TIMEOUT":               "5",
		"GRUB_CMDLINE_LINUX_DEFAULT": `"quiet splash"`,
		"GRUB_CMDLINE_LINUX":         `""`,
	}
	for k, v := range wants {
		if got[k] != v {
			t.Errorf("got[%q] = %q; want %q", k, got[k], v)
		}
	}
}

func TestNormalizeConfigLine_StripsExportKeyword(t *testing.T) {
	in := "export GRUB_DEFAULT=0"
	got := NormalizeConfigLine(in)
	want := "GRUB_DEFAULT=0"
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestHasInitOverride(t *testing.T) {
	cases := map[string]bool{
		`"quiet splash"`:                         false,
		`""`:                                     false,
		`quiet splash init=/tmp/.x/bd`:           true,
		`"quiet init=/sbin/init.bak loglevel=4"`: true,
		`"loglevel=4 rdinit=/init.cpio"`:         false,
		`"init=/bin/bash"`:                       true,
	}
	for in, want := range cases {
		if got := HasInitOverride(in); got != want {
			t.Errorf("HasInitOverride(%q) = %v; want %v", in, got, want)
		}
	}
}

func TestExtractInit_ReturnsPath(t *testing.T) {
	cases := map[string]string{
		`"quiet splash init=/tmp/.x/bd"`:    "/tmp/.x/bd",
		`init=/sbin/init.bak`:               "/sbin/init.bak",
		`"loglevel=4 init=/bin/bash quiet"`: "/bin/bash",
		`"quiet splash"`:                    "",
	}
	for in, want := range cases {
		if got := ExtractInit(in); got != want {
			t.Errorf("ExtractInit(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestNormalizeDropin_StripsShebangAndComments(t *testing.T) {
	in := []byte(`#!/bin/sh
# /etc/grub.d/40_custom -- user-added boot entries.
set -e

cat <<EOF
menuentry 'Recovery shell' {
    linux /vmlinuz init=/bin/sh
}
EOF
`)
	got := string(NormalizeDropin(in))
	if !bytes.Contains([]byte(got), []byte("menuentry")) {
		t.Errorf("dropin body lost: %q", got)
	}
	if bytes.Contains([]byte(got), []byte("user-added")) {
		t.Errorf("comment leaked into canonical: %q", got)
	}
}
