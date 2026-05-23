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
	"strings"
	"testing"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

var updateGolden = flag.Bool("update", false, "rewrite expected.ndjson files instead of comparing")

// shouldUpdateGolden accepts both the -update flag and the
// LINPERSIST_UPDATE_GOLDEN=1 env var. The env var form is the
// recommended trigger from make targets and CI scripts.
func shouldUpdateGolden() bool {
	if updateGolden != nil && *updateGolden {
		return true
	}
	return os.Getenv("LINPERSIST_UPDATE_GOLDEN") == "1"
}

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

// TestNonRootMembers covers the T1098.007 membership predicate. Every
// branch the recordFromGroup reclassification relies on is exercised:
// empty CSV, root-only, single non-root, multiple non-root.
func TestNonRootMembers(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"root", false},
		{"alice", true},
		{"root,alice", true},
		{"alice,bob", true},
		{",root,", false},
		{",alice,", true},
	}
	for _, c := range cases {
		if got := nonRootMembers(c.in); got != c.want {
			t.Errorf("nonRootMembers(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestRecordFromGroup_PrivilegedReclassification verifies that every
// privileged group with non-root members lands in
// passwd.group.privileged with the correct signal and MITRE pair,
// while non-privileged groups or root-only privileged groups stay
// under passwd.group. Uses a temp /etc/group file rather than a fake
// FileInfo so the baseSignals timestamp path (recent_mtime_*) is
// exercised end-to-end.
func TestRecordFromGroup_PrivilegedReclassification(t *testing.T) {
	tmp := t.TempDir()
	groupPath := filepath.Join(tmp, "group")
	if err := os.WriteFile(groupPath, []byte("placeholder:x:0:\n"), 0o644); err != nil {
		t.Fatalf("write group fixture: %v", err)
	}
	info, err := os.Lstat(groupPath)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	m := New(Options{Now: func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }})

	cases := []struct {
		raw           string
		wantSiteClass string
		wantSignal    string
		wantMITRE     int
	}{
		{"wheel:x:10:alice", "passwd.group.privileged", core.SignalGroupWheelMembership, 2},
		{"sudo:x:27:bob,alice", "passwd.group.privileged", core.SignalGroupSudoMembership, 2},
		{"docker:x:999:eve", "passwd.group.privileged", core.SignalGroupDockerMembership, 2},
		{"adm:x:4:alice,bob", "passwd.group.privileged", core.SignalGroupAdmMembership, 2},
		{"lxd:x:108:alice", "passwd.group.privileged", core.SignalGroupLxdMembership, 2},
		{"root:x:0:alice", "passwd.group.privileged", core.SignalGroupRootMembership, 2},
		{"wheel:x:10:", "passwd.group", "", 1},
		{"sudo:x:27:root", "passwd.group", "", 1},
		{"users:x:100:alice,bob", "passwd.group", "", 1},
	}
	for _, c := range cases {
		ge, ok := parseGroupLine(c.raw)
		if !ok {
			t.Fatalf("parse %q failed", c.raw)
		}
		rec := m.recordFromGroup("/etc/group", info, ge)
		if rec.SiteClass != c.wantSiteClass {
			t.Errorf("%q: SiteClass=%q want %q", c.raw, rec.SiteClass, c.wantSiteClass)
		}
		if len(rec.MITRE) != c.wantMITRE {
			t.Errorf("%q: len(MITRE)=%d want %d (got=%v)", c.raw, len(rec.MITRE), c.wantMITRE, rec.MITRE)
		}
		if c.wantSignal == "" {
			for _, s := range rec.Signals {
				if strings.HasPrefix(s, "group_") && strings.HasSuffix(s, "_membership") {
					t.Errorf("%q: unexpected privileged signal %q", c.raw, s)
				}
			}
			continue
		}
		found := false
		for _, s := range rec.Signals {
			if s == c.wantSignal {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%q: missing signal %q (got=%v)", c.raw, c.wantSignal, rec.Signals)
		}
	}
}
