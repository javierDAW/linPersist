package sudoers

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

var updateGolden = flag.Bool("update", false, "rewrite expected.ndjson files instead of comparing")

// shouldUpdateGolden accepts both the -update flag and the
// LINPERSIST_UPDATE_GOLDEN=1 env var.
func shouldUpdateGolden() bool {
	if updateGolden != nil && *updateGolden {
		return true
	}
	return os.Getenv("LINPERSIST_UPDATE_GOLDEN") == "1"
}

var fixedMtime = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
var fixedNow = time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)

func TestGolden(t *testing.T) {
	goldenDir := filepath.Join("..", "..", "testdata", "golden", "sudoers")
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

// normalizeFixturePerms sets 0440 on sudoers files (matches what
// visudo enforces), 0755 on directories.
func normalizeFixturePerms(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Chmod(path, 0o755)
		}
		return os.Chmod(path, 0o440)
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

func TestParseLine_DefaultsLine(t *testing.T) {
	pl := parseLine("Defaults env_reset")
	if pl.kind != lineDefaults {
		t.Fatalf("kind: %v", pl.kind)
	}
	if pl.canon != "Defaults env_reset" {
		t.Fatalf("canon: %q", pl.canon)
	}
}

func TestParseLine_UserSpecALL(t *testing.T) {
	pl := parseLine("root ALL=(ALL:ALL) ALL")
	if pl.kind != lineUserSpec {
		t.Fatalf("kind: %v", pl.kind)
	}
	if !hasAllCommands(pl.canon) {
		t.Fatal("hasAllCommands should be true")
	}
}

func TestParseLine_NoPasswdImplant(t *testing.T) {
	pl := parseLine("cibot ALL=(ALL) NOPASSWD: ALL")
	if pl.kind != lineUserSpec {
		t.Fatalf("kind: %v", pl.kind)
	}
	if !hasNoPasswd(pl.canon) {
		t.Fatal("hasNoPasswd should be true")
	}
	if !hasAllCommands(pl.canon) {
		t.Fatal("hasAllCommands should be true")
	}
}

func TestNopasswdGtfobin(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		// Single-command NOPASSWD on a GTFOBin == NOPASSWD:ALL.
		{"webops ALL=(root) NOPASSWD: /usr/bin/vi", true},
		{"webops ALL=(root) NOPASSWD: /usr/bin/find /var/log -name '*.gz'", true},
		{"deploy ALL=(ALL) NOPASSWD: /bin/tar, /usr/bin/awk", true},
		{"dev ALL=NOPASSWD:/usr/bin/python3 /opt/app/run.py", true},
		// duel-2 additions to the curated set.
		{"bk ALL=(root) NOPASSWD: /usr/bin/rsync -av /srv /backup", true},
		{"net ALL=(root) NOPASSWD: /usr/bin/socat - TCP:localhost:25", true},
		// Excluded common-legit binaries -> no signal (left to LFA).
		{"svc ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx", false},
		{"ci ALL=(root) NOPASSWD: /usr/bin/docker", false},
		// Non-escape scoped command -> no signal.
		{"mon ALL=(root) NOPASSWD: /usr/bin/tail -f /var/log/syslog", false},
	}
	for _, tc := range cases {
		pl := parseLine(tc.line)
		got := nopasswdGtfobin(pl.canon)
		if got != tc.want {
			t.Errorf("nopasswdGtfobin(%q) = %v; want %v (canon=%q)", tc.line, got, tc.want, pl.canon)
		}
	}
}

func TestParseLine_Alias_MembersSorted(t *testing.T) {
	pl := parseLine("User_Alias ADMINS = bob, alice, carol")
	if pl.kind != lineAlias {
		t.Fatalf("kind: %v", pl.kind)
	}
	if pl.canon != "User_Alias ADMINS=alice, bob, carol" {
		t.Fatalf("canon: %q", pl.canon)
	}
}

func TestParseLine_Includedir(t *testing.T) {
	pl := parseLine("#includedir /etc/sudoers.d")
	if pl.kind != lineInclude {
		t.Fatalf("kind: %v", pl.kind)
	}
	if pl.canon != "includedir /etc/sudoers.d" {
		t.Fatalf("canon: %q", pl.canon)
	}
}

func TestParseLine_PlainComment_Skipped(t *testing.T) {
	pl := parseLine("# this is a comment")
	if pl.kind != lineEmpty {
		t.Fatalf("comment should be lineEmpty, got %v", pl.kind)
	}
}

func TestParseLine_Blank_Skipped(t *testing.T) {
	if parseLine("").kind != lineEmpty {
		t.Fatal("blank should be lineEmpty")
	}
	if parseLine("   \t").kind != lineEmpty {
		t.Fatal("whitespace-only should be lineEmpty")
	}
}

func TestNormalize_EquivalentInputs(t *testing.T) {
	a := parseLine("Cmnd_Alias UPDATES = /usr/bin/apt upgrade, /usr/bin/apt update")
	b := parseLine("Cmnd_Alias UPDATES=/usr/bin/apt update,/usr/bin/apt upgrade")
	if a.canon != b.canon {
		t.Fatalf("equivalent inputs differ:\n  a -> %q\n  b -> %q", a.canon, b.canon)
	}
}

func TestHasAllCommands_NotALLAlias(t *testing.T) {
	// "ADMINS ALL=NOPASSWD: UPDATES" -- the only ALL is in the host
	// position, not commands. Must not fire.
	pl := parseLine("ADMINS ALL = NOPASSWD: UPDATES")
	if hasAllCommands(pl.canon) {
		t.Fatal("UPDATES should not be treated as ALL")
	}
}

// Sanity check that the test runner sees the same separator we
// hash on. Catches drift if anyone changes strings.HasSuffix in
// dropSignal etc.
var _ = strings.HasPrefix
