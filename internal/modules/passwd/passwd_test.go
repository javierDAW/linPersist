package passwd

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
	goldenDir := filepath.Join("..", "..", "testdata", "golden", "passwd")
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

func TestShadowStatus(t *testing.T) {
	cases := map[string]string{
		"":            "empty",
		"$y$j9T$abc":  "set",
		"$6$xxx$yyy":  "set",
		"!":           "locked",
		"!$y$j9T$abc": "locked",
		"!!":          "locked",
		"*":           "disabled",
		"weirdthing":  "unknown",
	}
	for in, want := range cases {
		if got := shadowStatus(in); got != want {
			t.Fatalf("shadowStatus(%q): got %q want %q", in, got, want)
		}
	}
}

func TestSortCSV(t *testing.T) {
	cases := map[string]string{
		"":                "",
		"a":               "a",
		"b,a":             "a,b",
		"carol,bob,alice": "alice,bob,carol",
		"a, b , c":        "a,b,c", // whitespace trimmed
		"a,,b":            "a,b",   // empty dropped
	}
	for in, want := range cases {
		if got := sortCSV(in); got != want {
			t.Fatalf("sortCSV(%q): got %q want %q", in, got, want)
		}
	}
}

func TestShouldEmitUser(t *testing.T) {
	root, _ := parsePasswdLine("root:x:0:0:root:/root:/bin/bash")
	daemon, _ := parsePasswdLine("daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
	mail, _ := parsePasswdLine("mail:x:8:8:mail:/var/mail:/bin/sh")
	uidZero, _ := parsePasswdLine("ali:x:0:0:backdoor:/home/ali:/bin/bash")
	false_, _ := parsePasswdLine("svc:x:100:100:svc:/var/svc:/bin/false")

	if !shouldEmitUser(root) {
		t.Fatal("root must pass")
	}
	if shouldEmitUser(daemon) {
		t.Fatal("daemon with nologin must NOT pass")
	}
	if !shouldEmitUser(mail) {
		t.Fatal("mail with /bin/sh must pass")
	}
	if !shouldEmitUser(uidZero) {
		t.Fatal("uid=0 user must pass even with arbitrary shell")
	}
	if shouldEmitUser(false_) {
		t.Fatal("user with /bin/false must NOT pass")
	}
}

func TestParseGroupLine_MembersSorted(t *testing.T) {
	ge, ok := parseGroupLine("wheel:x:10:carol,bob,alice")
	if !ok {
		t.Fatal("parse failed")
	}
	if ge.canon != "wheel:x:10:alice,bob,carol" {
		t.Fatalf("canon: %q", ge.canon)
	}
	if ge.raw != "wheel:x:10:carol,bob,alice" {
		t.Fatalf("raw: %q", ge.raw)
	}
}

func TestParseShadowLine_HashNotInCanon(t *testing.T) {
	// The raw hash MUST NOT appear in canon.
	const secret = "$y$j9T$VERYSECRETHASH"
	se, ok := parseShadowLine("alice:" + secret + ":19500:0:99999:7:::")
	if !ok {
		t.Fatal("parse failed")
	}
	if bytes.Contains([]byte(se.canon), []byte(secret)) {
		t.Fatalf("canon leaks the hash: %q", se.canon)
	}
	if se.status != "set" {
		t.Fatalf("status: %q", se.status)
	}
}

func TestParseGshadowLine_HashNotInCanon(t *testing.T) {
	const secret = "$6$abcdef$SECRETGSHADOWHASH"
	ge, ok := parseGshadowLine("wheel:" + secret + ":alice:bob,carol")
	if !ok {
		t.Fatal("parse failed")
	}
	if bytes.Contains([]byte(ge.canon), []byte(secret)) {
		t.Fatalf("canon leaks gshadow hash: %q", ge.canon)
	}
	if ge.status != "set" {
		t.Fatalf("status: %q", ge.status)
	}
}
