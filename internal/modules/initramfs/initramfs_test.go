package initramfs

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

var updateGolden = flag.Bool("update", false, "rewrite expected.ndjson files instead of comparing")

func shouldUpdateGolden() bool {
	if updateGolden != nil && *updateGolden {
		return true
	}
	return os.Getenv("LINPERSIST_UPDATE_GOLDEN") == "1"
}

var fixedMtime = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
var fixedNow = time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)

func TestGolden(t *testing.T) {
	goldenDir := filepath.Join("..", "..", "testdata", "golden", "initramfs")
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

// --- Unit tests ---

// collect runs the module against a synthetic root and returns the
// emitted records keyed by locus.
func collect(t *testing.T, root string) map[string]core.Record {
	t.Helper()
	mod := New(Options{Root: root, Now: func() time.Time { return fixedNow }})
	out := map[string]core.Record{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := mod.Collect(ctx, func(r core.Record) { out[r.Locus] = r }); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return out
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestExecTargetIsSelf(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/initramfs-tools/hooks/evil", "#!/bin/sh\ncp /payload /usr/bin/\n")
	recs := collect(t, root)
	rec, ok := recs["/etc/initramfs-tools/hooks/evil"]
	if !ok {
		t.Fatalf("no record for the local hook; got %v", keys(recs))
	}
	if rec.SiteClass != siteClassHook {
		t.Errorf("site_class = %q, want %q", rec.SiteClass, siteClassHook)
	}
	if rec.ExecTarget != rec.Locus {
		t.Errorf("ExecTarget = %q, want self (%q)", rec.ExecTarget, rec.Locus)
	}
	if rec.ExecTargetSHA256 == "" || rec.ExecTargetSHA256 != rec.ContentSHA256 {
		t.Errorf("ExecTargetSHA256 = %q, want == ContentSHA256 (%q)", rec.ExecTargetSHA256, rec.ContentSHA256)
	}
	if rec.Module != "initramfs" {
		t.Errorf("module = %q", rec.Module)
	}
}

func TestRecursiveWalkAcrossGenerators(t *testing.T) {
	root := t.TempDir()
	// One file per generator, at varying nesting depths.
	write(t, root, "etc/initramfs-tools/scripts/local-top/payload", "#!/bin/sh\n:\n")             // initramfs-tools, nested stage
	write(t, root, "usr/lib/dracut/modules.d/99evil/module-setup.sh", "#!/bin/bash\ninstall()\n") // dracut, nested module
	write(t, root, "etc/initcpio/install/evil", "#!/bin/bash\nbuild()\n")                         // mkinitcpio
	recs := collect(t, root)
	for _, want := range []string{
		"/etc/initramfs-tools/scripts/local-top/payload",
		"/usr/lib/dracut/modules.d/99evil/module-setup.sh",
		"/etc/initcpio/install/evil",
	} {
		if _, ok := recs[want]; !ok {
			t.Errorf("missing record for %s; got %v", want, keys(recs))
		}
	}
}

func TestEmptyDirsEmitNothing(t *testing.T) {
	root := t.TempDir()
	// The stage subdirs exist but are empty, mirroring a stock host.
	for _, d := range []string{
		"etc/initramfs-tools/hooks",
		"etc/initramfs-tools/scripts/init-top",
		"etc/initramfs-tools/scripts/local-bottom",
	} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	recs := collect(t, root)
	if len(recs) != 0 {
		t.Errorf("clean host emitted %d records, want 0: %v", len(recs), keys(recs))
	}
}

func TestSkipsDotfilesAndBackups(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/initramfs-tools/hooks/.keep", "x")
	write(t, root, "etc/initramfs-tools/hooks/zfs.dpkg-old", "x")
	write(t, root, "etc/initramfs-tools/hooks/real", "#!/bin/sh\n:\n")
	recs := collect(t, root)
	if _, ok := recs["/etc/initramfs-tools/hooks/.keep"]; ok {
		t.Error("dotfile .keep should be skipped")
	}
	if _, ok := recs["/etc/initramfs-tools/hooks/zfs.dpkg-old"]; ok {
		t.Error(".dpkg-old backup should be skipped")
	}
	if _, ok := recs["/etc/initramfs-tools/hooks/real"]; !ok {
		t.Error("real hook should be collected")
	}
}

func keys(m map[string]core.Record) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
