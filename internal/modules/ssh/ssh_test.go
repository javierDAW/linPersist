package ssh

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

// fixedMtime is the reference timestamp; ~42 days before fixedNow so
// recent_mtime_7d, recent_mtime_30d and recent_target_mtime_7d do
// NOT fire on stamped fixtures by default.
var fixedMtime = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)

// fixedNow is what the module's Now() returns during tests.
var fixedNow = time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)

// TestGolden iterates every case directory under testdata/golden/ssh.
func TestGolden(t *testing.T) {
	goldenDir := filepath.Join("..", "..", "testdata", "golden", "ssh")
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

// normalizeFixturePerms applies SSH-realistic permissions: 0600 on
// any authorized_keys file under /root/.ssh/ or /home/*/.ssh/, 0644
// on ones under /etc/ssh/, 0755 on directories. See the runner doc
// in internal/testdata/golden/ssh/README.md.
func normalizeFixturePerms(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Chmod(path, 0o755)
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		return os.Chmod(path, sshAuthkeysMode(rel))
	})
}

// sshAuthkeysMode returns the canonical mode for a fixture file at
// the given relative path. 0600 for user/root home keys (more
// privacy-sensitive), 0644 for /etc/ssh/* (system-wide config).
func sshAuthkeysMode(rel string) os.FileMode {
	if strings.HasPrefix(rel, "root/.ssh/") {
		return 0o600
	}
	if strings.HasPrefix(rel, "home/") && strings.Contains(rel, "/.ssh/") {
		return 0o600
	}
	if strings.HasPrefix(rel, "etc/ssh/") {
		return 0o644
	}
	return 0o644
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

func TestParseAuthKeyLine_NoOptionsEd25519(t *testing.T) {
	const line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClkfkBJ75drUf2/EoR2fYoU6e25i7c67hl7FP1G47kU ops@bastion"
	pk, ok := parseAuthKeyLine(line)
	if !ok {
		t.Fatalf("parse failed")
	}
	if pk.rawOpts != "" {
		t.Fatalf("opts: %q", pk.rawOpts)
	}
	if pk.keytype != "ssh-ed25519" {
		t.Fatalf("keytype: %q", pk.keytype)
	}
	if pk.comment != "ops@bastion" {
		t.Fatalf("comment: %q", pk.comment)
	}
	if pk.command != "" {
		t.Fatalf("unexpected command: %q", pk.command)
	}
	if len(pk.blobBytes) == 0 {
		t.Fatalf("blob bytes empty")
	}
}

func TestParseAuthKeyLine_WithOptions(t *testing.T) {
	const line = `from="10.0.0.0/8",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClkfkBJ75drUf2/EoR2fYoU6e25i7c67hl7FP1G47kU ops@bastion`
	pk, ok := parseAuthKeyLine(line)
	if !ok {
		t.Fatalf("parse failed")
	}
	if pk.rawOpts != `from="10.0.0.0/8",no-pty` {
		t.Fatalf("opts: %q", pk.rawOpts)
	}
	if pk.keytype != "ssh-ed25519" {
		t.Fatalf("keytype: %q", pk.keytype)
	}
	if pk.command != "" {
		t.Fatalf("unexpected command: %q", pk.command)
	}
}

func TestParseAuthKeyLine_ForcedCommand(t *testing.T) {
	const line = `command="/tmp/.h/payload" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBF2j4ETaaggPzHEw43oqV1jay2ZvCXeUUjfxxHaKVFL backdoor`
	pk, ok := parseAuthKeyLine(line)
	if !ok {
		t.Fatalf("parse failed")
	}
	if pk.command != "/tmp/.h/payload" {
		t.Fatalf("command: %q", pk.command)
	}
}

func TestParseAuthKeyLine_CommentLine(t *testing.T) {
	if _, ok := parseAuthKeyLine("# legacy ops key, removed 2025-01"); ok {
		t.Fatal("comment line should not parse")
	}
}

func TestParseAuthKeyLine_BlankLine(t *testing.T) {
	if _, ok := parseAuthKeyLine("   "); ok {
		t.Fatal("blank line should not parse")
	}
}

func TestParseAuthKeyLine_UnknownKeytype(t *testing.T) {
	if _, ok := parseAuthKeyLine("ssh-bogus AAAA ops"); ok {
		t.Fatal("unknown keytype should not parse")
	}
}

func TestParseAuthKeyLine_InvalidBase64(t *testing.T) {
	if _, ok := parseAuthKeyLine("ssh-ed25519 not-base64-{} ops"); ok {
		t.Fatal("invalid base64 blob should not parse")
	}
}

func TestCanonicalOptions_SortsAlphabetically(t *testing.T) {
	got := canonicalOptions(`no-pty,from="10.0.0.0/8",command="x"`)
	want := `command="x",from="10.0.0.0/8",no-pty`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCanonicalOptions_PreservesQuotedCommas(t *testing.T) {
	// command value contains a comma -- must NOT split there.
	got := canonicalOptions(`command="echo a,b",no-pty`)
	want := `command="echo a,b",no-pty`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCanonicalOptions_EmptyInput(t *testing.T) {
	if got := canonicalOptions(""); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestExtractForcedCommand(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`command="/usr/bin/git-shell",no-pty`, "/usr/bin/git-shell"},
		{`no-pty,command="/tmp/.h/x"`, "/tmp/.h/x"},
		{`no-pty,from="*"`, ""},
		{``, ""},
	}
	for _, c := range cases {
		got := extractForcedCommand(canonicalOptions(c.in))
		if got != c.want {
			t.Fatalf("extractForcedCommand(canon(%q)) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestReconstructLine_NoOptionsNoComment(t *testing.T) {
	got := reconstructLine("", "ssh-ed25519", "abcdef012345", "")
	want := "ssh-ed25519 <sha256:abcdef012345>"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestReconstructLine_FullForm(t *testing.T) {
	got := reconstructLine(`from="*"`, "ssh-rsa", "abcdef012345", "ops@bastion")
	want := `from="*" ssh-rsa <sha256:abcdef012345> ops@bastion`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

// Equivalence test: two semantically-identical lines (whitespace
// variation, option order variation) MUST hash to the same
// content_norm_sha256 input. Comment differences MUST NOT affect
// the canonical input (ADR-0003).
func TestNormalize_EquivalentInputs(t *testing.T) {
	a, _ := parseAuthKeyLine(`from="10.0.0.0/8",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClkfkBJ75drUf2/EoR2fYoU6e25i7c67hl7FP1G47kU ops@bastion-A`)
	b, _ := parseAuthKeyLine(`no-pty,from="10.0.0.0/8" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClkfkBJ75drUf2/EoR2fYoU6e25i7c67hl7FP1G47kU ops@bastion-B`)
	// Same blob -> same sha256 prefix.
	if string(a.blobBytes) != string(b.blobBytes) {
		t.Fatal("blob bytes should be equal across the two inputs")
	}
	canonA := reconstructLine(a.canonOpts, a.keytype, "abcdef012345", "")
	canonB := reconstructLine(b.canonOpts, b.keytype, "abcdef012345", "")
	if canonA != canonB {
		t.Fatalf("canonical inputs differ:\n  a -> %q\n  b -> %q", canonA, canonB)
	}
}
