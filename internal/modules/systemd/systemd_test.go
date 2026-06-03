package systemd

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
	"strings"
	"testing"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

var updateGolden = flag.Bool("update", false, "rewrite expected.ndjson files instead of comparing")

// shouldUpdateGolden returns true when the test binary should regenerate
// expected.ndjson files instead of comparing them. The flag is the
// primary trigger; LINPERSIST_UPDATE_GOLDEN=1 is a fallback for shells
// where flag propagation through `go test` is unreliable (some WSL +
// /mnt/c configurations have surfaced this).
func shouldUpdateGolden() bool {
	if updateGolden != nil && *updateGolden {
		return true
	}
	return os.Getenv("LINPERSIST_UPDATE_GOLDEN") == "1"
}

var fixedMtime = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
var fixedNow = time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC)

func TestGolden(t *testing.T) {
	goldenDir := filepath.Join("..", "..", "testdata", "golden", "systemd")
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
	if err := applySymlinkManifest(filepath.Join(caseDir, "symlinks.txt"), tmp); err != nil {
		t.Fatalf("symlinks: %v", err)
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
		// Emit at error-visibility so the user sees confirmation even
		// without -v. We are NOT failing the test; this is just a
		// stdout breadcrumb that the file was written.
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

// copyTree recursively copies src into dst preserving symlinks.
// Unlike a follow-symlinks copy, a symlink in src becomes a symlink at
// the same relative path in dst, with the same link target.
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
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			return os.Symlink(link, target)
		case d.IsDir():
			return os.MkdirAll(target, 0o755)
		default:
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
		}
	})
}

// applySymlinkManifest reads a symlinks.txt file with one
// "target<TAB>linkname" line per symlink (both paths relative to root,
// linkname uses '/' separators) and creates the corresponding symlinks
// under root. Returns nil if the manifest file does not exist.
//
// This lets a fixture declare symlinks without depending on git's
// symlink handling.
func applySymlinkManifest(manifestPath, root string) error {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			return &fixtureError{Msg: "manifest line must be target<TAB>linkname: " + line}
		}
		target, linkName := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		linkPath := filepath.Join(root, filepath.FromSlash(linkName))
		if err := os.MkdirAll(filepath.Dir(linkPath), 0o755); err != nil {
			return err
		}
		if err := os.Symlink(target, linkPath); err != nil {
			return err
		}
	}
	return nil
}

type fixtureError struct{ Msg string }

func (e *fixtureError) Error() string { return e.Msg }

func normalizeFixturePerms(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, ierr := d.Info()
		if ierr == nil && info.Mode()&os.ModeSymlink != 0 {
			// Do not chmod a symlink (Linux chmod follows the link
			// by default and the target may not exist in our fixture).
			return nil
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
		info, ierr := d.Info()
		if ierr == nil && info.Mode()&os.ModeSymlink != 0 {
			// os.Chtimes follows symlinks and would mutate the
			// target's mtime instead of the link's. Stdlib does not
			// expose lchtimes; the symlink's own mtime is therefore
			// non-deterministic across test runs. redactVolatile
			// compensates by forcing every record's MTime to the
			// fixed test-time stamp before the golden comparison.
			return nil
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
	// Force MTime to the fixed test stamp. stampMtimes cannot stamp
	// symlinks (Linux stdlib has no lchtimes) so symlink records
	// otherwise carry the creation timestamp of os.Symlink(), which
	// drifts per run. mtime-derived signals were already computed
	// against the actual on-disk mtime before this redact runs.
	mt := fixedMtime
	rec.MTime = &mt
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

// --- Normalization unit tests ---

func TestNormalize_LineContinuationJoined(t *testing.T) {
	in := []byte("[Service]\nExecStart=/bin/echo \\\n hello world\n")
	got := string(Normalize(in))
	// We expect the continuation to join into a single value
	// "/bin/echo  hello world" (the leading space on the joined
	// line is preserved per systemd.syntax(5)).
	want := "[Service]\nExecStart=/bin/echo  hello world\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestNormalize_CommentsAndBlankLinesStripped(t *testing.T) {
	in := []byte("# header comment\n\n[Unit]\n; inline section comment\nDescription=Foo\n\n# trailing\n")
	got := string(Normalize(in))
	want := "[Unit]\nDescription=Foo\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestNormalize_SectionOrderCanonical(t *testing.T) {
	in := []byte("[Install]\nWantedBy=multi-user.target\n[Service]\nExecStart=/bin/true\n[Unit]\nDescription=Foo\n")
	got := string(Normalize(in))
	want := "[Unit]\nDescription=Foo\n\n[Service]\nExecStart=/bin/true\n\n[Install]\nWantedBy=multi-user.target\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestNormalize_KeyOrderAlphabeticalCaseInsensitive(t *testing.T) {
	in := []byte("[Unit]\nDocumentation=man:foo(5)\nAfter=network.target\nDescription=Foo\n")
	got := string(Normalize(in))
	want := "[Unit]\nAfter=network.target\nDescription=Foo\nDocumentation=man:foo(5)\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestNormalize_SetSemanticKeySortedDeduped(t *testing.T) {
	in := []byte("[Unit]\nAfter=zeta beta alpha\nAfter=beta gamma\n")
	got := string(Normalize(in))
	want := "[Unit]\nAfter=alpha beta gamma zeta\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestNormalize_SetSemanticEmptyReset(t *testing.T) {
	in := []byte("[Unit]\nAfter=a b c\nAfter=\nAfter=d\n")
	got := string(Normalize(in))
	want := "[Unit]\nAfter=d\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestNormalize_ExecFamilyPreservesSourceOrderAndPrefixes(t *testing.T) {
	in := []byte("[Service]\nExecStart=-@/usr/bin/foo --first\nExecStart=/usr/bin/foo --second\nExecStartPre=/bin/true\n")
	got := string(Normalize(in))
	// Within the section, ExecStart is alphabetically before
	// ExecStartPre. The two ExecStart= lines preserve source order
	// and their prefixes verbatim.
	want := "[Service]\nExecStart=-@/usr/bin/foo --first\nExecStart=/usr/bin/foo --second\nExecStartPre=/bin/true\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestNormalize_ExecFamilyEmptyReset(t *testing.T) {
	in := []byte("[Service]\nExecStart=/bin/first\nExecStart=\nExecStart=/bin/second\n")
	got := string(Normalize(in))
	want := "[Service]\nExecStart=/bin/second\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestNormalize_KeyCaseCanonicalized(t *testing.T) {
	in := []byte("[Service]\nexecstart=/bin/true\nTYPE=oneshot\n")
	got := string(Normalize(in))
	want := "[Service]\nExecStart=/bin/true\nType=oneshot\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestNormalize_EquivalentInputs(t *testing.T) {
	a := []byte("# my service\n[Unit]\nDescription=Foo\nAfter=network.target zeta.service\n\n[Service]\nExecStart=/bin/true\nType=oneshot\n[Install]\nWantedBy=multi-user.target\n")
	b := []byte("[Install]\nWantedBy=multi-user.target\n[Service]\nType=oneshot\nExecStart=/bin/true\n[Unit]\nAfter=zeta.service\nAfter=network.target\nDescription=Foo\n# header at bottom\n")
	na := string(Normalize(a))
	nb := string(Normalize(b))
	if na != nb {
		t.Fatalf("equivalent inputs differ:\n  a -> %q\n  b -> %q", na, nb)
	}
}

func TestNormalize_Idempotent(t *testing.T) {
	in := []byte("[Unit]\nDescription=Foo\nAfter=b a c\n[Service]\nExecStart=/bin/true\n")
	once := Normalize(in)
	twice := Normalize(once)
	if string(once) != string(twice) {
		t.Fatalf("not idempotent:\n  once  -> %q\n  twice -> %q", once, twice)
	}
}

func TestNormalize_MalformedTolerated(t *testing.T) {
	// Missing section header before keys, malformed [Section line,
	// key without '=', empty key. Should not panic and should still
	// yield a canonical form for whatever was parseable.
	in := []byte("KeyOutsideSection=Foo\n[BadSection\nDescription=NoSection\n[Service]\nNoEquals\n=NoKey\nExecStart=/bin/true\n")
	got := Normalize(in)
	if !strings.Contains(string(got), "ExecStart=/bin/true") {
		t.Fatalf("expected ExecStart= survives parsing, got %q", got)
	}
}

func TestNormalize_EmptyInput(t *testing.T) {
	if got := Normalize(nil); len(got) != 0 {
		t.Fatalf("expected empty, got %q", got)
	}
	if got := Normalize([]byte("# only comments\n\n")); len(got) != 0 {
		t.Fatalf("expected empty, got %q", got)
	}
}

// --- ExecStart prefix stripping ---

func TestStripExecPrefixes(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"/usr/bin/foo", "/usr/bin/foo"},
		{"@/usr/bin/foo argv0", "/usr/bin/foo argv0"},
		{"-/usr/bin/foo", "/usr/bin/foo"},
		{"+/usr/bin/foo", "/usr/bin/foo"},
		{"!!/usr/bin/foo", "/usr/bin/foo"},
		{"@-/usr/bin/foo", "/usr/bin/foo"},
		{"-@/usr/bin/foo", "/usr/bin/foo"},
		{"  @/usr/bin/foo", "/usr/bin/foo"},
		{"foo", "foo"},
	}
	for _, c := range cases {
		got := stripExecPrefixes(c.in)
		if got != c.want {
			t.Fatalf("stripExecPrefixes(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// --- Template-unit recognition ---

func TestIsTemplateUnit(t *testing.T) {
	cases := map[string]bool{
		"/etc/systemd/system/foo@.service":       true,
		"/etc/systemd/system/foo.service":        false,
		"/etc/systemd/system/getty@tty1.service": false,
		"/usr/lib/systemd/system/sshd@.service":  true,
		"/etc/systemd/system/foo@.timer":         true,
	}
	for path, want := range cases {
		if got := isTemplateUnit(path); got != want {
			t.Fatalf("isTemplateUnit(%q) = %v, want %v", path, got, want)
		}
	}
}

// --- classifyExtension ---

func TestClassifyExtension(t *testing.T) {
	cases := []struct {
		name      string
		siteClass string
		ok        bool
	}{
		{"foo.service", "systemd.unit", true},
		{"foo.socket", "systemd.unit", true},
		{"foo.path", "systemd.unit", true},
		{"foo.mount", "systemd.unit", true},
		{"foo.automount", "systemd.unit", true},
		{"foo.swap", "systemd.unit", true},
		{"foo.target", "systemd.unit", true},
		{"foo.timer", "systemd.timer", true},
		{"foo.slice", "", false},
		{"foo.scope", "", false},
		{"foo.conf", "", false},
		{"foo", "", false},
	}
	for _, c := range cases {
		sc, _, ok := classifyExtension(c.name)
		if ok != c.ok || sc != c.siteClass {
			t.Fatalf("classifyExtension(%q) = %q, %v; want %q, %v",
				c.name, sc, ok, c.siteClass, c.ok)
		}
	}
}

// --- siteClassForDropinDir ---

func TestSiteClassForDropinDir(t *testing.T) {
	cases := []struct {
		name      string
		siteClass string
		ok        bool
	}{
		{"sshd.service.d", "systemd.unit", true},
		{"backup.timer.d", "systemd.timer", true},
		{"foo.slice.d", "", false}, // .slice excluded from v0.1.0
		{"foo.d", "", false},
		{"not-a-dropin", "", false},
	}
	for _, c := range cases {
		sc, ok := siteClassForDropinDir(c.name)
		if ok != c.ok || sc != c.siteClass {
			t.Fatalf("siteClassForDropinDir(%q) = %q, %v; want %q, %v",
				c.name, sc, ok, c.siteClass, c.ok)
		}
	}
}

// --- ParseUnitFile ---

func TestParseUnitFile_BasicSections(t *testing.T) {
	in := []byte("[Unit]\nDescription=Foo\n[Service]\nExecStart=/bin/true\n")
	secs, errs := ParseUnitFile(in)
	if len(errs) != 0 {
		t.Fatalf("unexpected parse errors: %v", errs)
	}
	if len(secs) != 2 {
		t.Fatalf("got %d sections, want 2", len(secs))
	}
	if secs[0].Name != "Unit" || secs[1].Name != "Service" {
		t.Fatalf("section names: %v", secs)
	}
	if len(secs[0].Entries) != 1 || secs[0].Entries[0].Key != "Description" || secs[0].Entries[0].Value != "Foo" {
		t.Fatalf("Unit entries wrong: %v", secs[0].Entries)
	}
	if len(secs[1].Entries) != 1 || secs[1].Entries[0].Key != "ExecStart" || secs[1].Entries[0].Value != "/bin/true" {
		t.Fatalf("Service entries wrong: %v", secs[1].Entries)
	}
}

func TestParseUnitFile_LineContinuationsJoined(t *testing.T) {
	in := []byte("[Service]\nExecStart=/bin/foo \\\n  --arg1 \\\n  --arg2\n")
	secs, errs := ParseUnitFile(in)
	if len(errs) != 0 {
		t.Fatalf("unexpected parse errors: %v", errs)
	}
	if len(secs) != 1 || len(secs[0].Entries) != 1 {
		t.Fatalf("expected one section one entry, got %v", secs)
	}
	got := secs[0].Entries[0].Value
	want := "/bin/foo   --arg1   --arg2"
	if got != want {
		t.Fatalf("joined value = %q, want %q", got, want)
	}
}

func TestParseUnitFile_MalformedSurfacesErrors(t *testing.T) {
	in := []byte("KeyOutside=1\n[BadSection\n[Service]\nNoEquals\n=NoKey\n")
	_, errs := ParseUnitFile(in)
	if len(errs) < 3 {
		t.Fatalf("expected at least 3 errors, got %d: %v", len(errs), errs)
	}
}

func TestParseUnitFile_CommentsAndBlankLinesIgnored(t *testing.T) {
	in := []byte("# top\n\n[Unit]\n; mid\nDescription=Foo\n\n# end\n")
	secs, errs := ParseUnitFile(in)
	if len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}
	if len(secs) != 1 || len(secs[0].Entries) != 1 {
		t.Fatalf("unexpected sections: %v", secs)
	}
}

// --- resolveExecTarget ---

func TestResolveExecTarget_AbsolutePath(t *testing.T) {
	m := New(Options{Root: t.TempDir()})
	sections := []Section{{Name: "Service", Entries: []Entry{
		{Key: "ExecStart", Value: "@/usr/bin/foo --arg"},
	}}}
	path, multi, has, resolved := m.resolveExecTarget(sections)
	if !has || !resolved || multi {
		t.Fatalf("has=%v resolved=%v multi=%v", has, resolved, multi)
	}
	if path != "/usr/bin/foo" {
		t.Fatalf("path=%q want /usr/bin/foo", path)
	}
}

func TestResolveExecTarget_RelativeUnresolved(t *testing.T) {
	// Empty Root means the resolver searches the agent's actual
	// /usr/local/sbin etc. To keep the test hermetic we point Root
	// at an empty tmpdir so the resolver finds nothing.
	m := New(Options{Root: t.TempDir()})
	sections := []Section{{Name: "Service", Entries: []Entry{
		{Key: "ExecStart", Value: "uniquely-missing-command --arg"},
	}}}
	path, _, has, resolved := m.resolveExecTarget(sections)
	if !has || resolved {
		t.Fatalf("expected has=true resolved=false, got has=%v resolved=%v", has, resolved)
	}
	if path != "" {
		t.Fatalf("expected empty path for unresolved relative cmd, got %q", path)
	}
}

func TestTargetInsideWalkedLoci_HomeOnlyMatchesUserLocus(t *testing.T) {
	m := New(Options{Root: t.TempDir()})
	cases := map[string]bool{
		"/etc/systemd/system/foo.service":              true,
		"/usr/lib/systemd/system/foo.service":          true,
		"/run/systemd/system/foo.service":              true,
		"/root/.config/systemd/user/foo.service":       true,
		"/home/alice/.config/systemd/user/foo.service": true,
		"/home/alice/.config/systemd/user":             true,
		"/home/alice/payload.service":                  false,
		"/home/alice":                                  false,
		"/tmp/.cache/foo.service":                      false,
		"/opt/payload/foo.service":                     false,
		"/var/lib/foo.service":                         false,
	}
	for path, want := range cases {
		if got := m.targetInsideWalkedLoci(path); got != want {
			t.Fatalf("targetInsideWalkedLoci(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestResolveExecTarget_MultiExecStart(t *testing.T) {
	m := New(Options{Root: t.TempDir()})
	sections := []Section{{Name: "Service", Entries: []Entry{
		{Key: "ExecStart", Value: "/bin/one"},
		{Key: "ExecStart", Value: "/bin/two"},
	}}}
	_, multi, _, _ := m.resolveExecTarget(sections)
	if !multi {
		t.Fatalf("expected multi=true")
	}
}

func TestResolveExecTarget_NoExecStart(t *testing.T) {
	m := New(Options{Root: t.TempDir()})
	sections := []Section{{Name: "Unit", Entries: []Entry{
		{Key: "Description", Value: "Foo"},
	}}}
	path, _, has, _ := m.resolveExecTarget(sections)
	if has || path != "" {
		t.Fatalf("expected no ExecStart, got path=%q has=%v", path, has)
	}
}

// hasStr reports membership in a string slice.
func hasStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func TestRelationEdges_PathExplicitUnit(t *testing.T) {
	raw := []byte("[Path]\nPathModified=/tmp/.trigger\nUnit=payload.service\n")
	secs, _ := ParseUnitFile(raw)
	m := New(Options{})
	edges, sigs := m.relationEdges(secs, "/etc/systemd/system/watch.path")
	if !hasStr(edges, "PathModified=/tmp/.trigger") {
		t.Errorf("missing watched-path edge; edges=%v", edges)
	}
	if !hasStr(edges, "Unit=payload.service") {
		t.Errorf("missing explicit Unit edge; edges=%v", edges)
	}
	if !hasStr(sigs, core.SignalSystemdPathTrigger) {
		t.Errorf("missing systemd_path_trigger; sigs=%v", sigs)
	}
	if hasStr(sigs, core.SignalSystemdHasOnFailure) {
		t.Errorf("onfailure signal should not fire here")
	}
}

func TestRelationEdges_PathImplicitUnit(t *testing.T) {
	// No explicit Unit= → systemd activates <basename>.service.
	raw := []byte("[Path]\nPathChanged=/var/spool/x\n")
	secs, _ := ParseUnitFile(raw)
	m := New(Options{})
	edges, sigs := m.relationEdges(secs, "/etc/systemd/system/monitor.path")
	if !hasStr(edges, "Unit=monitor.service") {
		t.Errorf("implicit Unit edge wrong; edges=%v", edges)
	}
	if !hasStr(sigs, core.SignalSystemdPathTrigger) {
		t.Errorf("missing systemd_path_trigger; sigs=%v", sigs)
	}
}

func TestRelationEdges_OnFailureAndDeps(t *testing.T) {
	raw := []byte("[Unit]\nOnFailure=evil.service\nWants=a.service b.service\nRequires=c.service\nAfter=network.target\n")
	secs, _ := ParseUnitFile(raw)
	m := New(Options{})
	edges, sigs := m.relationEdges(secs, "/etc/systemd/system/hc.service")
	for _, want := range []string{"OnFailure=evil.service", "Wants=a.service", "Wants=b.service", "Requires=c.service"} {
		if !hasStr(edges, want) {
			t.Errorf("missing edge %q; edges=%v", want, edges)
		}
	}
	// After= is ordering-only and must NOT be captured.
	for _, e := range edges {
		if e == "After=network.target" {
			t.Errorf("After= must not be an edge; edges=%v", edges)
		}
	}
	if !hasStr(sigs, core.SignalSystemdHasOnFailure) {
		t.Errorf("missing systemd_has_onfailure; sigs=%v", sigs)
	}
	if hasStr(sigs, core.SignalSystemdPathTrigger) {
		t.Errorf("path_trigger should not fire on a service unit")
	}
}

func TestRelationEdges_NoneOnPlainUnit(t *testing.T) {
	raw := []byte("[Unit]\nDescription=plain\nAfter=network.target\n[Service]\nExecStart=/usr/bin/true\n")
	secs, _ := ParseUnitFile(raw)
	m := New(Options{})
	edges, sigs := m.relationEdges(secs, "/etc/systemd/system/plain.service")
	if len(edges) != 0 {
		t.Errorf("plain unit should yield no edges; got %v", edges)
	}
	if len(sigs) != 0 {
		t.Errorf("plain unit should yield no signals; got %v", sigs)
	}
}

func TestRelationEdges_TimerImplicitAndExplicit(t *testing.T) {
	m := New(Options{})
	// Implicit: backup.timer -> backup.service.
	secs, _ := ParseUnitFile([]byte("[Timer]\nOnCalendar=daily\n"))
	edges, sigs := m.relationEdges(secs, "/etc/systemd/system/backup.timer")
	if !hasStr(edges, "Unit=backup.service") {
		t.Errorf("implicit timer unit wrong; edges=%v", edges)
	}
	if !hasStr(sigs, core.SignalSystemdTimerTrigger) {
		t.Errorf("missing systemd_timer_trigger; sigs=%v", sigs)
	}
	// Explicit Unit=.
	secs, _ = ParseUnitFile([]byte("[Timer]\nOnBootSec=5min\nUnit=evil.service\n"))
	edges, _ = m.relationEdges(secs, "/etc/systemd/system/zz.timer")
	if !hasStr(edges, "Unit=evil.service") {
		t.Errorf("explicit timer unit wrong; edges=%v", edges)
	}
}

func TestRelationEdges_SocketImplicitAndExplicit(t *testing.T) {
	m := New(Options{})
	secs, _ := ParseUnitFile([]byte("[Socket]\nListenStream=4444\n"))
	edges, sigs := m.relationEdges(secs, "/etc/systemd/system/beacon.socket")
	if !hasStr(edges, "Unit=beacon.service") {
		t.Errorf("implicit socket unit wrong; edges=%v", edges)
	}
	if !hasStr(sigs, core.SignalSystemdSocketTrigger) {
		t.Errorf("missing systemd_socket_trigger; sigs=%v", sigs)
	}
	secs, _ = ParseUnitFile([]byte("[Socket]\nListenStream=/run/x.sock\nService=payload.service\n"))
	edges, _ = m.relationEdges(secs, "/etc/systemd/system/x.socket")
	if !hasStr(edges, "Unit=payload.service") {
		t.Errorf("explicit socket service wrong; edges=%v", edges)
	}
}

func TestRelationEdges_EnvironmentFileEdge(t *testing.T) {
	m := New(Options{})
	secs, _ := ParseUnitFile([]byte("[Service]\nEnvironmentFile=-/etc/sysconfig/telemetry\nExecStart=/usr/bin/true\n"))
	edges, _ := m.relationEdges(secs, "/etc/systemd/system/telemetry.service")
	if !hasStr(edges, "EnvironmentFile=/etc/sysconfig/telemetry") {
		t.Errorf("EnvironmentFile edge wrong (leading - must be stripped); edges=%v", edges)
	}
}

func TestRelationEdges_PlainTimerlessServiceNoTrigger(t *testing.T) {
	m := New(Options{})
	secs, _ := ParseUnitFile([]byte("[Service]\nExecStart=/usr/bin/true\n"))
	_, sigs := m.relationEdges(secs, "/etc/systemd/system/plain.service")
	for _, s := range sigs {
		if s == core.SignalSystemdTimerTrigger || s == core.SignalSystemdSocketTrigger {
			t.Errorf("plain service must not raise timer/socket trigger; sigs=%v", sigs)
		}
	}
}
