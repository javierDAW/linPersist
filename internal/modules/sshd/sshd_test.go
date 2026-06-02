package sshd

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
	goldenDir := filepath.Join("..", "..", "testdata", "golden", "sshd")
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

// --- Parser unit tests ---

func TestParseLine_PlainDirective(t *testing.T) {
	pl := parseLine("PermitRootLogin no")
	if pl.kind != lineDirective {
		t.Fatalf("kind: %v", pl.kind)
	}
	if pl.keyword != "PermitRootLogin" || pl.value != "no" {
		t.Fatalf("keyword/value: %q / %q", pl.keyword, pl.value)
	}
}

func TestParseLine_MatchLine(t *testing.T) {
	pl := parseLine("Match User alice")
	if pl.kind != lineMatch {
		t.Fatalf("kind: %v", pl.kind)
	}
	if pl.matchRaw != "User alice" {
		t.Fatalf("matchRaw: %q", pl.matchRaw)
	}
}

func TestParseLine_IndentedDirective(t *testing.T) {
	pl := parseLine("    AuthorizedKeysFile /custom/path")
	if pl.kind != lineDirective {
		t.Fatalf("kind: %v", pl.kind)
	}
	if pl.keyword != "AuthorizedKeysFile" {
		t.Fatalf("keyword: %q", pl.keyword)
	}
}

func TestParseLine_CommentSkipped(t *testing.T) {
	if parseLine("# top comment").kind != lineEmpty {
		t.Fatal("top comment must be skipped")
	}
	if parseLine("    # indented comment").kind != lineEmpty {
		t.Fatal("indented comment must be skipped")
	}
}

func TestCanonicalMatchLine_LowercaseCriterionKeywords(t *testing.T) {
	got := canonicalMatchLine("User alice Group wheel")
	want := "match user alice group wheel"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCanonicalDirective_NoMatchContext(t *testing.T) {
	got := canonicalDirective("PermitRootLogin", "no", "")
	if got != "permitrootlogin no" {
		t.Fatalf("got %q", got)
	}
}

func TestCanonicalDirective_InsideMatch(t *testing.T) {
	got := canonicalDirective("PermitRootLogin", "yes", "match user alice")
	want := "match user alice : permitrootlogin yes"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestDirectiveExecTarget(t *testing.T) {
	if got := directiveExecTarget("AuthorizedKeysCommand", "/usr/bin/x --arg"); got != "/usr/bin/x" {
		t.Fatalf("AKC: got %q", got)
	}
	if got := directiveExecTarget("ForceCommand", `"/usr/bin/x with spaces"`); got != "/usr/bin/x with spaces" {
		t.Fatalf("FC quoted: got %q", got)
	}
	if got := directiveExecTarget("Port", "22"); got != "" {
		t.Fatalf("Port should not yield exec_target: got %q", got)
	}
}

func TestDirectiveSignals(t *testing.T) {
	sigs := directiveSignals("PermitRootLogin", "yes")
	if len(sigs) != 1 || sigs[0] != core.SignalSSHDPermitRootLoginYes {
		t.Fatalf("got %v", sigs)
	}
	sigs = directiveSignals("PermitRootLogin", "no")
	if len(sigs) != 0 {
		t.Fatalf("PermitRootLogin no should not fire: %v", sigs)
	}
	// prohibit-password is the OpenSSH default since 7.0; the signal
	// must NOT fire on it (would dirty LFA across the entire fleet).
	sigs = directiveSignals("PermitRootLogin", "prohibit-password")
	if len(sigs) != 0 {
		t.Fatalf("PermitRootLogin prohibit-password should not fire: %v", sigs)
	}
	sigs = directiveSignals("AuthorizedKeysCommand", "/usr/bin/x")
	if len(sigs) != 1 || sigs[0] != core.SignalSSHDAuthorizedKeysCommand {
		t.Fatalf("AKC: %v", sigs)
	}

	// Env-injection recognizers (duel-2 backlog).
	if sigs = directiveSignals("PermitUserEnvironment", "yes"); len(sigs) != 1 || sigs[0] != core.SignalSSHDPermitUserEnvironment {
		t.Fatalf("PermitUserEnvironment yes: %v", sigs)
	}
	if sigs = directiveSignals("PermitUserEnvironment", "no"); len(sigs) != 0 {
		t.Fatalf("PermitUserEnvironment no should be silent: %v", sigs)
	}
	if sigs = directiveSignals("SetEnv", "BASH_ENV=/opt/.h/hook"); len(sigs) != 1 || sigs[0] != core.SignalSSHDEnvInjection {
		t.Fatalf("SetEnv BASH_ENV: %v", sigs)
	}
	if sigs = directiveSignals("AcceptEnv", "LD_PRELOAD LANG LC_*"); len(sigs) != 1 || sigs[0] != core.SignalSSHDEnvInjection {
		t.Fatalf("AcceptEnv LD_PRELOAD: %v", sigs)
	}
	if sigs = directiveSignals("AcceptEnv", "LANG LC_* TZ"); len(sigs) != 0 {
		t.Fatalf("AcceptEnv benign should be silent: %v", sigs)
	}
}
