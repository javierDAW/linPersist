package pam

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

var fixedMtime = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
var fixedNow = time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)

func TestGolden(t *testing.T) {
	goldenDir := filepath.Join("..", "..", "testdata", "golden", "pam")
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

// --- Parser unit tests ---

func TestTokenizePAM_RespectsBrackets(t *testing.T) {
	toks := tokenizePAM("auth [success=ok default=die] pam_unix.so")
	if len(toks) != 3 {
		t.Fatalf("got %d tokens, want 3: %v", len(toks), toks)
	}
	if toks[1] != "[success=ok default=die]" {
		t.Fatalf("bracket token mangled: %q", toks[1])
	}
}

func TestParsePamDLine_Simple(t *testing.T) {
	pr, ok := parsePamDLine("auth     required    pam_unix.so")
	if !ok {
		t.Fatal("parse failed")
	}
	if pr.canon != "auth required pam_unix.so" {
		t.Fatalf("canon: %q", pr.canon)
	}
	if pr.module != "pam_unix.so" {
		t.Fatalf("module: %q", pr.module)
	}
}

func TestParsePamDLine_LowercasesType(t *testing.T) {
	pr, ok := parsePamDLine("Auth required pam_unix.so")
	if !ok {
		t.Fatal("parse failed")
	}
	if pr.canon != "auth required pam_unix.so" {
		t.Fatalf("canon (type lowercased): %q", pr.canon)
	}
}

func TestParsePamDLine_BracketControl(t *testing.T) {
	pr, ok := parsePamDLine("auth [success=ok default=die] pam_unix.so")
	if !ok {
		t.Fatal("parse failed")
	}
	if pr.module != "pam_unix.so" {
		t.Fatalf("module: %q", pr.module)
	}
	if pr.canon != "auth [success=ok default=die] pam_unix.so" {
		t.Fatalf("canon: %q", pr.canon)
	}
}

func TestParsePamDLine_Include(t *testing.T) {
	pr, ok := parsePamDLine("@include common-auth")
	if !ok {
		t.Fatal("parse failed")
	}
	if !pr.include {
		t.Fatal("include flag should be true")
	}
	if pr.canon != "@include common-auth" {
		t.Fatalf("canon: %q", pr.canon)
	}
}

func TestParsePamDLine_SkipsComment(t *testing.T) {
	if _, ok := parsePamDLine("# this is a comment"); ok {
		t.Fatal("comment should be skipped")
	}
	if _, ok := parsePamDLine("   # leading-ws comment"); ok {
		t.Fatal("leading-ws comment should be skipped")
	}
}

func TestParsePamConfLine_FiveField(t *testing.T) {
	pr, ok := parsePamConfLine("sudo  auth  required  pam_unix.so")
	if !ok {
		t.Fatal("parse failed")
	}
	if pr.canon != "sudo auth required pam_unix.so" {
		t.Fatalf("canon: %q", pr.canon)
	}
	if pr.module != "pam_unix.so" {
		t.Fatalf("module: %q", pr.module)
	}
}
