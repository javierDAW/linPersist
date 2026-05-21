package sysusers

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

// updateGolden lets developers regenerate expected.ndjson files:
//
//	go test ./internal/modules/sysusers -run TestGolden -update
//
// Equivalently: LINPERSIST_UPDATE_GOLDEN=1 go test ./internal/modules/sysusers/...
var updateGolden = flag.Bool("update", false, "rewrite expected.ndjson files instead of comparing")

func shouldUpdateGolden() bool {
	if updateGolden != nil && *updateGolden {
		return true
	}
	return os.Getenv("LINPERSIST_UPDATE_GOLDEN") == "1"
}

// fixedMtime / fixedNow follow the project-wide convention: mtime
// ~6 weeks before now so that recent_mtime_{7,30}d do NOT fire on
// untouched fixtures.
var fixedMtime = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
var fixedNow = time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)

// TestGolden iterates every case directory under testdata/golden/sysusers
// and runs runGolden against it.
func TestGolden(t *testing.T) {
	goldenDir := filepath.Join("..", "..", "testdata", "golden", "sysusers")
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

// copyTree recursively copies src into dst.
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

// normalizeFixturePerms applies 0755 to directories and 0644 to files.
// sysusers.d files ship 0644 by convention (read-only system config).
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

// redactVolatile zeroes record fields the test runner cannot reproduce
// without root. Same rationale as cron_test.go.
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

// --- Public API smoke tests ---

// TestNameAndSiteClasses guards the canonical identifiers the rest of
// the pipeline keys on. A typo here desynchronises matrix-audit.
func TestNameAndSiteClasses(t *testing.T) {
	m := New(Options{})
	if got := m.Name(); got != "sysusers" {
		t.Fatalf("Name: got %q, want %q", got, "sysusers")
	}
	sc := m.SiteClasses()
	if len(sc) != 1 || sc[0] != "systemd.sysusers" {
		t.Fatalf("SiteClasses: got %v, want [systemd.sysusers]", sc)
	}
}

// --- Parser unit tests ---

// TestParseFields_Plain exercises the whitespace-separated grammar
// without quoted segments.
func TestParseFields_Plain(t *testing.T) {
	got := parseFields("u alice 1001 - /home/alice /bin/bash")
	want := []string{"u", "alice", "1001", "-", "/home/alice", "/bin/bash"}
	if len(got) != len(want) {
		t.Fatalf("len: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("idx %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

// TestParseFields_QuotedGecos verifies the gecos field is parsed as a
// single token even when it contains whitespace inside quotes.
func TestParseFields_QuotedGecos(t *testing.T) {
	got := parseFields(`u svc 999 "Service Account, Inc." /var/svc /sbin/nologin`)
	if len(got) != 6 {
		t.Fatalf("len: got %d, want 6 (%v)", len(got), got)
	}
	if got[3] != "Service Account, Inc." {
		t.Errorf("gecos field: got %q, want %q", got[3], "Service Account, Inc.")
	}
}

// TestParseFields_TabSeparators verifies that tabs are treated as
// whitespace separators outside quoted segments.
func TestParseFields_TabSeparators(t *testing.T) {
	got := parseFields("u\troot\t0\t-\t/root\t/bin/bash")
	if len(got) != 6 || got[0] != "u" || got[2] != "0" {
		t.Fatalf("tab parse: got %v", got)
	}
}

// --- Directive signal tests ---

// TestDirectiveSignals_UIDZeroNonRoot is the central positive case:
// type u with id 0 and name other than root must fire
// sysusers_uid_zero. This is the implant fingerprint the module exists
// to detect.
func TestDirectiveSignals_UIDZeroNonRoot(t *testing.T) {
	cases := []string{
		`u backdoor 0 "Implant" /root /bin/bash`,
		"u admin2 0 - /root /bin/bash",
		`u  systemd-rootlike  0  "spoofed"  /tmp  /bin/sh`,
	}
	for _, raw := range cases {
		canon := canonicalDirective(raw)
		got := directiveSignals(parseFields(canon))
		if len(got) != 1 || got[0] != core.SignalSysusersUIDZero {
			t.Errorf("input=%q: got %v, want [%s]", raw, got, core.SignalSysusersUIDZero)
		}
	}
}

// TestDirectiveSignals_RootBaseline verifies the canonical "root has
// uid 0" line is NOT flagged; otherwise every sysusers.d would
// generate a critical alert on every host.
func TestDirectiveSignals_RootBaseline(t *testing.T) {
	got := directiveSignals(parseFields(`u root 0 "Super User" /root /bin/bash`))
	if got != nil {
		t.Fatalf("root uid 0 must not fire signal, got %v", got)
	}
}

// TestDirectiveSignals_NonUserTypes verifies the signal is u-type
// specific. g (group), m (membership), r (range) directives must
// not fire it regardless of any "id 0" field they may carry.
func TestDirectiveSignals_NonUserTypes(t *testing.T) {
	for _, raw := range []string{
		"g wheel 0 -",
		"m alice wheel",
		"r - 100-200",
	} {
		got := directiveSignals(parseFields(raw))
		if got != nil {
			t.Errorf("input=%q: must not fire, got %v", raw, got)
		}
	}
}

// TestDirectiveSignals_NonZeroUID covers the negative path: type u
// with a non-zero id must not fire the signal even if the name is
// arbitrary.
func TestDirectiveSignals_NonZeroUID(t *testing.T) {
	for _, raw := range []string{
		`u alice 1001 - /home/alice /bin/bash`,
		`u svc - - /var/svc /sbin/nologin`,
		`u systemd-resolve 193 "systemd Resolver" -`,
	} {
		got := directiveSignals(parseFields(raw))
		if got != nil {
			t.Errorf("input=%q: must not fire, got %v", raw, got)
		}
	}
}

// TestDirectiveSignals_TooFewFields handles malformed lines that
// would otherwise index out of bounds. Must return nil, never panic.
func TestDirectiveSignals_TooFewFields(t *testing.T) {
	for _, raw := range []string{
		"u",
		"u alice",
		"",
	} {
		got := directiveSignals(parseFields(raw))
		if got != nil {
			t.Errorf("input=%q: must not fire, got %v", raw, got)
		}
	}
}

// --- Normalization equivalence ---

// TestNormalize_WhitespaceCollapsed is the central LFA guarantee for
// this module: two semantically-identical directives with differing
// whitespace MUST share the same content_norm_sha256, otherwise the
// stacking joins are broken.
func TestNormalize_WhitespaceCollapsed(t *testing.T) {
	a := `u alice 1001 - /home/alice /bin/bash`
	b := "u\talice    1001    -   /home/alice   /bin/bash"
	if canonicalDirective(a) != canonicalDirective(b) {
		t.Fatalf("equivalent directives differ:\n  a -> %q\n  b -> %q",
			canonicalDirective(a), canonicalDirective(b))
	}
}

// TestNormalize_QuotedSegmentPreserved verifies that whitespace
// inside quoted segments is preserved verbatim. Two directives that
// differ only inside the quoted gecos field MUST hash differently.
func TestNormalize_QuotedSegmentPreserved(t *testing.T) {
	a := canonicalDirective(`u svc 999 "Service Account, Inc." /var/svc /sbin/nologin`)
	b := canonicalDirective(`u svc 999 "Service  Account,  Inc." /var/svc /sbin/nologin`)
	if a == b {
		t.Fatalf("quoted whitespace must be preserved; both normalized to %q", a)
	}
}

// --- Collect-level robustness ---

// TestCollect_NonExistentDir verifies the module returns nil when
// neither /etc/sysusers.d nor /usr/lib/sysusers.d exists. Most
// container baselines have neither.
func TestCollect_NonExistentDir(t *testing.T) {
	tmp := t.TempDir()
	mod := New(Options{Root: tmp, Now: func() time.Time { return fixedNow }})
	var captured []core.Record
	sink := func(r core.Record) { captured = append(captured, r) }
	if err := mod.Collect(context.Background(), sink); err != nil {
		t.Fatalf("missing dirs: got err %v, want nil", err)
	}
	if len(captured) != 0 {
		t.Fatalf("missing dirs: got %d records, want 0", len(captured))
	}
}

// TestCollect_OversizedFile triggers the SIZE_LIMIT envelope path:
// a sysusers.d source larger than MaxFileSize must emit one envelope
// record with errors[].field=content_sha256 and code=SIZE_LIMIT.
func TestCollect_OversizedFile(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "etc/sysusers.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	big := bytes.Repeat([]byte("u alice 1001 - /home/alice /bin/bash\n"), 4096)
	if err := os.WriteFile(filepath.Join(dir, "huge.conf"), big, 0o644); err != nil {
		t.Fatalf("write big: %v", err)
	}
	mod := New(Options{
		Root:        tmp,
		Now:         func() time.Time { return fixedNow },
		MaxFileSize: 1024,
	})
	var captured []core.Record
	sink := func(r core.Record) { captured = append(captured, r) }
	if err := mod.Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(captured) != 1 {
		t.Fatalf("got %d records, want 1 envelope", len(captured))
	}
	if len(captured[0].Errors) != 1 || captured[0].Errors[0].Code != "SIZE_LIMIT" {
		t.Fatalf("expected SIZE_LIMIT envelope, got %+v", captured[0].Errors)
	}
}
