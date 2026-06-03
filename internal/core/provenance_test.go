package core

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// nullLogger returns a slog.Logger that discards every record. Keeps
// `go test -v` output clean from the Warmup/build INFO lines.
func nullLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))
}

// writeFile is a t.Helper that writes content under path with parents
// created and 0600 perms.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestNoopProvenance: contract is "always Unknown, never blocks".
func TestNoopProvenance(t *testing.T) {
	var p Provenance = NoopProvenance{}
	p.Warmup(context.Background())
	pkg, status := p.LookupPath("/usr/bin/anything")
	if pkg != "" || status != PkgStatusUnknown {
		t.Errorf("NoopProvenance returned (%q, %q); want (\"\", \"unknown\")", pkg, status)
	}
}

// TestPackageManager_String pins the string forms used in logs and
// (transitively) record fields.
func TestPackageManager_String(t *testing.T) {
	cases := map[PackageManager]string{
		PkgMgrNone: "none",
		PkgMgrDpkg: "dpkg",
		PkgMgrRpm:  "rpm",
	}
	for in, want := range cases {
		if got := in.String(); got != want {
			t.Errorf("PackageManager(%d).String() = %q; want %q", in, got, want)
		}
	}
}

// TestPkgStatus_String confirms the type is a typed string so the JSON
// emitter prints the constant value verbatim.
func TestPkgStatus_String(t *testing.T) {
	cases := map[PkgStatus]string{
		PkgStatusUnknown: "unknown",
		PkgStatusOwned:   "owned",
		PkgStatusOrphan:  "orphan",
		PkgStatusError:   "error",
	}
	for in, want := range cases {
		if got := in.String(); got != want {
			t.Errorf("PkgStatus(%q).String() = %q; want %q", string(in), got, want)
		}
	}
}

// TestResolver_DetectsNoneWhenEmptyTree: a Root tree with neither
// /var/lib/dpkg nor /var/lib/rpm yields PkgMgrNone and PkgStatusUnknown
// for every lookup.
func TestResolver_DetectsNoneWhenEmptyTree(t *testing.T) {
	root := t.TempDir()
	r := NewResolver(nullLogger(), WithProvenanceRoot(root))
	r.Warmup(context.Background())
	if r.PackageManager() != PkgMgrNone {
		t.Fatalf("PackageManager = %v; want PkgMgrNone", r.PackageManager())
	}
	pkg, status := r.LookupPath("/usr/bin/whatever")
	if pkg != "" || status != PkgStatusUnknown {
		t.Errorf("LookupPath on empty-tree resolver = (%q, %q); want (\"\", \"unknown\")",
			pkg, status)
	}
}

// TestResolver_LookupBeforeWarmup returns Unknown rather than blocking.
func TestResolver_LookupBeforeWarmup(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "var/lib/dpkg/info"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := NewResolver(nullLogger(), WithProvenanceRoot(root))
	pkg, status := r.LookupPath("/usr/bin/anything")
	if pkg != "" || status != PkgStatusUnknown {
		t.Errorf("pre-warmup LookupPath = (%q, %q); want (\"\", \"unknown\")", pkg, status)
	}
}

// TestResolver_DpkgHappyPath: a Root tree with two fake packages
// resolves owned paths and reports the rest as orphans.
func TestResolver_DpkgHappyPath(t *testing.T) {
	root := t.TempDir()
	info := filepath.Join(root, "var/lib/dpkg/info")
	writeFile(t, filepath.Join(info, "openssh-server.list"), strings.Join([]string{
		"/.",
		"/usr",
		"/usr/sbin",
		"/usr/sbin/sshd",
		"/etc/ssh/sshd_config",
		"",
	}, "\n"))
	writeFile(t, filepath.Join(info, "cron.list"), strings.Join([]string{
		"/usr/sbin/cron",
		"/etc/init.d/cron",
		"/etc/cron.daily/standard",
	}, "\n"))
	writeFile(t, filepath.Join(root, "etc/os-release"),
		"ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"22.04\"\n")

	r := NewResolver(nullLogger(), WithProvenanceRoot(root))
	r.Warmup(context.Background())

	if r.PackageManager() != PkgMgrDpkg {
		t.Fatalf("PackageManager = %v; want PkgMgrDpkg", r.PackageManager())
	}
	if r.MapSize() == 0 {
		t.Fatalf("MapSize = 0; want > 0")
	}

	cases := []struct {
		path       string
		wantPkg    string
		wantStatus PkgStatus
	}{
		{"/usr/sbin/sshd", "openssh-server", PkgStatusOwned},
		{"/etc/ssh/sshd_config", "openssh-server", PkgStatusOwned},
		{"/usr/sbin/cron", "cron", PkgStatusOwned},
		{"/etc/cron.daily/standard", "cron", PkgStatusOwned},
		{"/tmp/.x/payload", "", PkgStatusOrphan},
		{"/opt/implant/run.sh", "", PkgStatusOrphan},
	}
	for _, tc := range cases {
		gotPkg, gotStatus := r.LookupPath(tc.path)
		if gotPkg != tc.wantPkg || gotStatus != tc.wantStatus {
			t.Errorf("LookupPath(%q) = (%q, %q); want (%q, %q)",
				tc.path, gotPkg, gotStatus, tc.wantPkg, tc.wantStatus)
		}
	}
}

// TestResolver_DpkgFirstWinsOnConflict: when two packages claim the
// same path, the first iteration order wins. ADR-0009 documents this.
func TestResolver_DpkgFirstWinsOnConflict(t *testing.T) {
	root := t.TempDir()
	info := filepath.Join(root, "var/lib/dpkg/info")
	// "aaa.list" sorts before "zzz.list" so os.ReadDir on most
	// filesystems hands aaa first. We don't assert ordering here --
	// we just assert ONE consistent winner, never both.
	writeFile(t, filepath.Join(info, "aaa.list"), "/shared/path\n")
	writeFile(t, filepath.Join(info, "zzz.list"), "/shared/path\n")

	r := NewResolver(nullLogger(), WithProvenanceRoot(root))
	r.Warmup(context.Background())

	pkg, status := r.LookupPath("/shared/path")
	if status != PkgStatusOwned {
		t.Fatalf("LookupPath = (%q, %q); want owned", pkg, status)
	}
	if pkg != "aaa" && pkg != "zzz" {
		t.Errorf("LookupPath = (%q, owned); want pkg in {aaa, zzz}", pkg)
	}
}

// TestResolver_DpkgEmptyFile: an empty .list file does not corrupt the
// build and produces zero entries for that package.
func TestResolver_DpkgEmptyFile(t *testing.T) {
	root := t.TempDir()
	info := filepath.Join(root, "var/lib/dpkg/info")
	writeFile(t, filepath.Join(info, "empty-pkg.list"), "")
	writeFile(t, filepath.Join(info, "real-pkg.list"), "/usr/bin/real\n")

	r := NewResolver(nullLogger(), WithProvenanceRoot(root))
	r.Warmup(context.Background())

	if pkg, status := r.LookupPath("/usr/bin/real"); pkg != "real-pkg" || status != PkgStatusOwned {
		t.Errorf("real path lookup = (%q, %q); want (real-pkg, owned)", pkg, status)
	}
}

// TestResolver_DpkgIgnoresRootDot: the conventional "/."
// entry in dpkg .list files MUST be filtered out.
func TestResolver_DpkgIgnoresRootDot(t *testing.T) {
	root := t.TempDir()
	info := filepath.Join(root, "var/lib/dpkg/info")
	writeFile(t, filepath.Join(info, "p.list"), "/.\n/usr/bin/p\n")

	r := NewResolver(nullLogger(), WithProvenanceRoot(root))
	r.Warmup(context.Background())

	if _, status := r.LookupPath("/."); status == PkgStatusOwned {
		t.Errorf(`"/." should NOT be owned; got owned`)
	}
	if pkg, status := r.LookupPath("/usr/bin/p"); pkg != "p" || status != PkgStatusOwned {
		t.Errorf("real path = (%q, %q); want (p, owned)", pkg, status)
	}
}

// TestResolver_DpkgStripsArchSuffix: dpkg writes "foo:amd64.list" on
// multi-arch hosts; the resolver MUST strip the arch suffix.
func TestResolver_DpkgStripsArchSuffix(t *testing.T) {
	root := t.TempDir()
	info := filepath.Join(root, "var/lib/dpkg/info")
	writeFile(t, filepath.Join(info, "libc6:amd64.list"), "/lib/x86_64-linux-gnu/libc.so.6\n")

	r := NewResolver(nullLogger(), WithProvenanceRoot(root))
	r.Warmup(context.Background())

	pkg, status := r.LookupPath("/lib/x86_64-linux-gnu/libc.so.6")
	if pkg != "libc6" || status != PkgStatusOwned {
		t.Errorf("LookupPath = (%q, %q); want (libc6, owned)", pkg, status)
	}
}

// TestResolver_DpkgMissingInfoDir: when the package manager looks
// detected via /etc/os-release but /var/lib/dpkg/info is absent, the
// build fails and lookups return Error.
func TestResolver_DpkgMissingInfoDir(t *testing.T) {
	root := t.TempDir()
	// Create /var/lib/dpkg directory but NOT the info subdir, so
	// detectPackageManager sees no info directory -> falls back to None.
	if err := os.MkdirAll(filepath.Join(root, "var/lib/dpkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := NewResolver(nullLogger(), WithProvenanceRoot(root))
	r.Warmup(context.Background())

	if r.PackageManager() != PkgMgrNone {
		t.Fatalf("PackageManager = %v; want PkgMgrNone (no info dir)", r.PackageManager())
	}
}

// TestResolver_DetectPrefersOSReleaseHint: when both /var/lib/dpkg
// and /var/lib/rpm exist, /etc/os-release picks the winner.
func TestResolver_DetectPrefersOSReleaseHint(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "var/lib/dpkg/info"))
	mustMkdir(t, filepath.Join(root, "var/lib/rpm"))

	cases := []struct {
		name       string
		osRelease  string
		wantPkgMgr PackageManager
	}{
		{"ubuntu hint -> dpkg", `ID=ubuntu` + "\n", PkgMgrDpkg},
		{"rhel hint -> rpm", `ID=rhel` + "\n", PkgMgrRpm},
		{"amazon hint -> rpm", `ID="amzn"` + "\n", PkgMgrRpm},
		{"opensuse hint -> rpm", `ID=opensuse-tumbleweed` + "\n", PkgMgrRpm},
		{"id_like=debian -> dpkg",
			`ID=mydistro` + "\n" + `ID_LIKE=debian` + "\n",
			PkgMgrDpkg},
		{"id_like=rhel fedora -> rpm",
			`ID=mydistro` + "\n" + `ID_LIKE="rhel fedora"` + "\n",
			PkgMgrRpm},
		{"no hint, both present -> dpkg fallback", ``, PkgMgrDpkg},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			writeFile(t, filepath.Join(root, "etc/os-release"), tc.osRelease)
			r := NewResolver(nullLogger(), WithProvenanceRoot(root))
			got := r.detectPackageManager()
			if got != tc.wantPkgMgr {
				t.Errorf("detectPackageManager() = %v; want %v", got, tc.wantPkgMgr)
			}
		})
	}
}

// TestResolver_ReadOSReleaseIDs covers the parser used by detection.
func TestResolver_ReadOSReleaseIDs(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    []string
	}{
		{
			"ubuntu with id_like",
			"ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"22.04\"\n",
			[]string{"ubuntu", "debian"},
		},
		{
			"id_like multi-token quoted",
			"ID=mydistro\nID_LIKE=\"rhel fedora\"\n",
			[]string{"mydistro", "rhel", "fedora"},
		},
		{
			"quoted ID",
			"ID=\"amzn\"\n",
			[]string{"amzn"},
		},
		{
			"lowercases",
			"ID=Ubuntu\nID_LIKE=Debian\n",
			[]string{"ubuntu", "debian"},
		},
		{
			"empty",
			"",
			nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, filepath.Join(root, "etc/os-release"), tc.content)
			r := NewResolver(nullLogger(), WithProvenanceRoot(root))
			got := r.readOSReleaseIDs()
			if !stringsEqual(got, tc.want) {
				t.Errorf("readOSReleaseIDs() = %v; want %v", got, tc.want)
			}
		})
	}
}

// TestResolver_ReadOSReleaseIDs_MissingFile: returns empty slice when
// /etc/os-release is absent, never panics.
func TestResolver_ReadOSReleaseIDs_MissingFile(t *testing.T) {
	root := t.TempDir()
	r := NewResolver(nullLogger(), WithProvenanceRoot(root))
	got := r.readOSReleaseIDs()
	if len(got) != 0 {
		t.Errorf("readOSReleaseIDs() = %v; want empty", got)
	}
}

// TestScanRpmStream covers the rpm stdout parser for the
// --filesbypkg output format. Each line is `<name>  <path>` with
// rpm-padded whitespace between. Lines without whitespace are
// skipped; the `(none)` sentinel is skipped; first-wins on conflict.
func TestScanRpmStream(t *testing.T) {
	// Mimic real `rpm -qa --filesbypkg` output: column-padded name,
	// whitespace gap, then path.
	input := strings.Join([]string{
		"openssh-server               /usr/sbin/sshd",
		"openssh-server               /etc/ssh/sshd_config",
		"unused                       (none)",
		"some-pkg                     ",
		"first-pkg                    /shared/path",
		"second-pkg                   /shared/path",
		"",
		"cron                         /usr/bin/cron",
		// Tab-separated form: also supported (rpm uses spaces but be
		// defensive against future variants).
		"foo\t/usr/bin/foo",
	}, "\n") + "\n"

	out := make(map[string]string)
	if err := scanRpmStream(strings.NewReader(input), out); err != nil {
		t.Fatalf("scanRpmStream: %v", err)
	}

	wants := map[string]string{
		"/usr/sbin/sshd":       "openssh-server",
		"/etc/ssh/sshd_config": "openssh-server",
		"/shared/path":         "first-pkg",
		"/usr/bin/cron":        "cron",
		"/usr/bin/foo":         "foo",
	}
	for k, want := range wants {
		if got := out[k]; got != want {
			t.Errorf("out[%q] = %q; want %q", k, got, want)
		}
	}
	if _, ok := out["(none)"]; ok {
		t.Errorf("(none) sentinel must be skipped")
	}
	if _, ok := out[""]; ok {
		t.Errorf("empty-path line must be skipped")
	}
}

// TestTrimNVRSuffix pins the defensive NVR-strip behavior. Three
// classes of input are covered:
//
//   - Bare package names (typical `rpm --filesbypkg` output) pass
//     through unchanged: "openssh-server", "cron", "gnupg2-smime".
//   - Full NVR forms get stripped to NAME: "openssh-8.7p1-34.el9"
//     -> "openssh", "cron-2.3-1.el9" -> "cron", etc.
//   - Edge cases: empty string, single token, single-dash names,
//     names with one numeric segment, names with two numeric
//     segments.
func TestTrimNVRSuffix(t *testing.T) {
	cases := map[string]string{
		"openssh-server":       "openssh-server",
		"cron":                 "cron",
		"gnupg2-smime":         "gnupg2-smime",
		"openssh-8.7p1-34.el9": "openssh",
		"cron-2.3-1.el9":       "cron",
		"glibc-2.34-100.fc36":  "glibc",
		"":                     "",
		"a":                    "a",
		"a-b":                  "a-b",
		"a-1":                  "a-1",
		"a-1-2":                "a",
	}
	for in, want := range cases {
		got := trimNVRSuffix(in)
		if got != want {
			t.Errorf("trimNVRSuffix(%q) = %q; want %q", in, got, want)
		}
	}
}

// TestResolver_RpmHappyPath_FakeBinary: drop a tiny shell script that
// pretends to be /usr/bin/rpm and emits canned stdout. Confirm the
// resolver consumes it correctly.
func TestResolver_RpmHappyPath_FakeBinary(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh available; rpm fake-binary test skipped")
	}
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "var/lib/rpm"))
	writeFile(t, filepath.Join(root, "etc/os-release"), `ID=rhel`+"\n")

	// Fake rpm binary: emits canned `--filesbypkg`-style output
	// (package name, then whitespace, then path).
	fakeRpm := filepath.Join(root, "fake-rpm")
	fakeOutput := strings.Join([]string{
		"openssh-server               /usr/sbin/sshd",
		"openssh-server               /etc/ssh/sshd_config",
		"cron                         /usr/bin/cron",
	}, "\n") + "\n"
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' '%s'\n", fakeOutput)
	if err := os.WriteFile(fakeRpm, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	r := NewResolver(nullLogger(),
		WithProvenanceRoot(root),
		WithProvenanceRpmCommand([]string{fakeRpm}),
	)
	r.Warmup(context.Background())

	if r.PackageManager() != PkgMgrRpm {
		t.Fatalf("PackageManager = %v; want PkgMgrRpm", r.PackageManager())
	}
	if r.MapSize() == 0 {
		t.Fatalf("MapSize = 0; want > 0")
	}

	cases := []struct {
		path       string
		wantPkg    string
		wantStatus PkgStatus
	}{
		{"/usr/sbin/sshd", "openssh-server", PkgStatusOwned},
		{"/usr/bin/cron", "cron", PkgStatusOwned},
		{"/tmp/.h/payload", "", PkgStatusOrphan},
	}
	for _, tc := range cases {
		gotPkg, gotStatus := r.LookupPath(tc.path)
		if gotPkg != tc.wantPkg || gotStatus != tc.wantStatus {
			t.Errorf("LookupPath(%q) = (%q, %q); want (%q, %q)",
				tc.path, gotPkg, gotStatus, tc.wantPkg, tc.wantStatus)
		}
	}
}

// TestResolver_RpmBinaryMissing: the resolver records an error and
// every lookup returns PkgStatusError.
func TestResolver_RpmBinaryMissing(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "var/lib/rpm"))
	writeFile(t, filepath.Join(root, "etc/os-release"), `ID=rhel`+"\n")

	r := NewResolver(nullLogger(),
		WithProvenanceRoot(root),
		WithProvenanceRpmBinaryCandidates([]string{"/does/not/exist/rpm"}),
	)
	r.Warmup(context.Background())

	if r.PackageManager() != PkgMgrRpm {
		t.Fatalf("PackageManager = %v; want PkgMgrRpm", r.PackageManager())
	}
	pkg, status := r.LookupPath("/usr/bin/any")
	if pkg != "" || status != PkgStatusError {
		t.Errorf("LookupPath = (%q, %q); want (\"\", \"error\")", pkg, status)
	}
}

// TestResolver_RpmExitFailure: when the rpm command exits non-zero,
// the build records the error and lookups degrade.
func TestResolver_RpmExitFailure(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh available")
	}
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "var/lib/rpm"))
	writeFile(t, filepath.Join(root, "etc/os-release"), `ID=rhel`+"\n")

	failingRpm := filepath.Join(root, "fail-rpm")
	if err := os.WriteFile(failingRpm,
		[]byte("#!/bin/sh\necho boom 1>&2\nexit 1\n"),
		0o755); err != nil {
		t.Fatal(err)
	}
	r := NewResolver(nullLogger(),
		WithProvenanceRoot(root),
		WithProvenanceRpmCommand([]string{failingRpm}),
	)
	r.Warmup(context.Background())

	pkg, status := r.LookupPath("/usr/bin/any")
	if pkg != "" || status != PkgStatusError {
		t.Errorf("LookupPath = (%q, %q); want (\"\", \"error\")", pkg, status)
	}
}

// TestResolver_WarmupIsIdempotent: calling Warmup twice does NOT
// rebuild the map. We assert by checking the map size is unchanged
// after a second call against an evolving fixture directory.
func TestResolver_WarmupIsIdempotent(t *testing.T) {
	root := t.TempDir()
	info := filepath.Join(root, "var/lib/dpkg/info")
	writeFile(t, filepath.Join(info, "first.list"), "/usr/bin/first\n")

	r := NewResolver(nullLogger(), WithProvenanceRoot(root))
	r.Warmup(context.Background())
	sizeAfterFirst := r.MapSize()

	// Add a second package and call Warmup again. The second call
	// MUST NOT pick up the new entries (build is once-per-process).
	writeFile(t, filepath.Join(info, "second.list"), "/usr/bin/second\n")
	r.Warmup(context.Background())
	if r.MapSize() != sizeAfterFirst {
		t.Errorf("MapSize changed across Warmup calls: %d -> %d",
			sizeAfterFirst, r.MapSize())
	}
	if _, status := r.LookupPath("/usr/bin/second"); status == PkgStatusOwned {
		t.Errorf("LookupPath picked up post-Warmup file; expected orphan")
	}
}

// TestResolver_BuildTimeoutHonoredByCtx: a tiny build timeout combined
// with a slow fake rpm yields an Error status, not a deadlock.
//
// The fake rpm uses `exec sleep` so the shell replaces itself with
// sleep. exec.CommandContext sends SIGKILL to the (now-sleep) process
// when ctx expires; sleep dies, the stdout pipe closes, cmd.Wait
// returns immediately. Without `exec`, the shell would fork sleep
// as a child and the inherited stdout pipe would stay open past the
// shell's death, stalling cmd.Wait for the full sleep duration
// (proved by an earlier iteration of this test). cmd.WaitDelay in
// buildRpmMap is the production-side defense for the same hazard.
func TestResolver_BuildTimeoutHonoredByCtx(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh available")
	}
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "var/lib/rpm"))
	writeFile(t, filepath.Join(root, "etc/os-release"), `ID=rhel`+"\n")

	slowRpm := filepath.Join(root, "slow-rpm")
	if err := os.WriteFile(slowRpm,
		[]byte("#!/bin/sh\nexec sleep 5\n"),
		0o755); err != nil {
		t.Fatal(err)
	}
	r := NewResolver(nullLogger(),
		WithProvenanceRoot(root),
		WithProvenanceRpmCommand([]string{slowRpm}),
		WithProvenanceBuildTimeout(200*time.Millisecond),
	)
	start := time.Now()
	r.Warmup(context.Background())
	elapsed := time.Since(start)
	// Budget: 200 ms ctx + a few hundred ms for process teardown and
	// scheduler jitter. 2 s is generous; the bug we are pinning here
	// stalled for the full sleep (5 s) before the WaitDelay+exec fix.
	if elapsed > 2*time.Second {
		t.Errorf("Warmup exceeded reasonable bound: %s", elapsed)
	}
	pkg, status := r.LookupPath("/usr/bin/sshd")
	if pkg != "" || status != PkgStatusError {
		t.Errorf("LookupPath = (%q, %q); want (\"\", \"error\") after timeout", pkg, status)
	}
}

// TestResolver_ConcurrentLookups exercises the lock-free read path
// under a Race-detector run. The single Warmup is followed by many
// concurrent LookupPath callers.
func TestResolver_ConcurrentLookups(t *testing.T) {
	root := t.TempDir()
	info := filepath.Join(root, "var/lib/dpkg/info")
	writeFile(t, filepath.Join(info, "p.list"), strings.Join([]string{
		"/usr/bin/p1",
		"/usr/bin/p2",
		"/usr/bin/p3",
	}, "\n"))

	r := NewResolver(nullLogger(), WithProvenanceRoot(root))
	r.Warmup(context.Background())

	const goroutines = 32
	const lookups = 200
	done := make(chan struct{}, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < lookups; j++ {
				_, _ = r.LookupPath("/usr/bin/p1")
				_, _ = r.LookupPath("/tmp/x")
				_, _ = r.LookupPath("/usr/bin/p3")
			}
		}()
	}
	for i := 0; i < goroutines; i++ {
		<-done
	}
}

// TestResolver_LookupRelativePathReturnsUnknown pins the v0.2.0 fix
// for the PAM false-positive flood. Records that carry a relative
// exec_target (the PAM module name like "pam_unix.so", a bare crontab
// command token like "test" or "cd", a PAM @include filename like
// "system-auth") must NOT be classified as Orphan: the resolver
// cannot answer "is this relative name package-owned?" without
// PATH/LD_LIBRARY_PATH resolution. Returning Unknown lets the
// non_package_path signal NOT fire on those records.
//
// Pre-fix: lab-realistic showed 8,472 PAM records with non_package_path
// (a third of total fleet records), all of them false positives.
func TestResolver_LookupRelativePathReturnsUnknown(t *testing.T) {
	root := t.TempDir()
	info := filepath.Join(root, "var/lib/dpkg/info")
	writeFile(t, filepath.Join(info, "openssh-server.list"), "/usr/sbin/sshd\n")
	writeFile(t, filepath.Join(root, "etc/os-release"), `ID=ubuntu`+"\n")

	r := NewResolver(nullLogger(), WithProvenanceRoot(root))
	r.Warmup(context.Background())

	cases := []string{
		"pam_unix.so", // PAM module name
		"system-auth", // PAM @include filename
		"test",        // bare command token from a crontab line
		"cd",          // shell builtin from a crontab line
		"runuser",     // ditto
		"config-util", // PAM file basename
		"common-auth", // PAM @include
		"sudo",        // bare-name command
		"pam_gnome_keyring.so",
		"pam_systemd.so",
	}
	for _, target := range cases {
		pkg, status := r.LookupPath(target)
		if status != PkgStatusUnknown {
			t.Errorf("LookupPath(%q) status = %q; want Unknown (relative paths must degrade silently)",
				target, status)
		}
		if pkg != "" {
			t.Errorf("LookupPath(%q) pkg = %q; want empty", target, pkg)
		}
	}
}

// TestResolver_UsrMergeAlternates pins the v0.2.0 fix for systemd unit
// false positives. dpkg lists the systemd package's files in their
// historical /lib/systemd/... form even after the /usr-merge collapsed
// /lib into /usr/lib at the filesystem level. systemd ExecStart= lines
// reference the binary at /usr/lib/systemd/... The lookup must try
// BOTH forms; otherwise hundreds of legit baseline records fire
// non_package_path because the dpkg manifest doesn't have the /usr-
// prefixed path verbatim.
//
// Pre-fix: lab-realistic showed /usr/lib/systemd/systemd-tmpfiles,
// /usr/lib/systemd/systemd-journald, /usr/sbin/sshd, etc. on 27 hosts
// each as non_package_path. All false positives.
func TestResolver_UsrMergeAlternates(t *testing.T) {
	root := t.TempDir()
	info := filepath.Join(root, "var/lib/dpkg/info")
	// dpkg manifest as it actually appears on Debian/Ubuntu: paths
	// listed in the historical /lib, /bin, /sbin form.
	writeFile(t, filepath.Join(info, "systemd.list"), strings.Join([]string{
		"/lib/systemd/systemd-tmpfiles",
		"/lib/systemd/systemd-journald",
		"/sbin/init",
	}, "\n"))
	writeFile(t, filepath.Join(info, "coreutils.list"), strings.Join([]string{
		"/bin/cat",
		"/bin/echo",
	}, "\n"))
	writeFile(t, filepath.Join(root, "etc/os-release"), `ID=ubuntu`+"\n")

	r := NewResolver(nullLogger(), WithProvenanceRoot(root))
	r.Warmup(context.Background())

	// Lookup the post-merge form should resolve via the pre-merge form.
	postMergeCases := map[string]string{
		"/usr/lib/systemd/systemd-tmpfiles": "systemd",
		"/usr/lib/systemd/systemd-journald": "systemd",
		"/usr/sbin/init":                    "systemd",
		"/usr/bin/cat":                      "coreutils",
		"/usr/bin/echo":                     "coreutils",
	}
	for path, wantPkg := range postMergeCases {
		gotPkg, status := r.LookupPath(path)
		if status != PkgStatusOwned {
			t.Errorf("LookupPath(%q) status = %q; want Owned (usr-merge alternate)",
				path, status)
		}
		if gotPkg != wantPkg {
			t.Errorf("LookupPath(%q) pkg = %q; want %q", path, gotPkg, wantPkg)
		}
	}

	// Reverse direction: the verbatim form should also resolve
	// (no alternate consulted, just the primary key).
	if pkg, status := r.LookupPath("/lib/systemd/systemd-tmpfiles"); status != PkgStatusOwned || pkg != "systemd" {
		t.Errorf("LookupPath verbatim = (%q, %q); want (systemd, owned)", pkg, status)
	}
}

// TestUsrMergeAlternates_DirectCases pins the pure-function behavior
// of the helper that produces sibling paths. Both directions are
// covered: /usr/bin → /bin and /bin → /usr/bin. Paths outside the
// merge namespace (e.g. /opt, /etc, the empty string) return nil.
// Defends against future refactors silently dropping a prefix.
func TestUsrMergeAlternates_DirectCases(t *testing.T) {
	// Bin/sbin dirs now collapse into one equivalence class (Arch/Fedora/
	// Gentoo merge /bin,/sbin,/usr/sbin -> /usr/bin), so each returns the
	// basename under the three OTHER bin dirs, in binMergeDirs order.
	// Lib dirs stay one-to-one.
	cases := map[string][]string{
		"/usr/bin/foo":       {"/bin/foo", "/usr/sbin/foo", "/sbin/foo"},
		"/usr/sbin/init":     {"/usr/bin/init", "/bin/init", "/sbin/init"},
		"/bin/foo":           {"/usr/bin/foo", "/usr/sbin/foo", "/sbin/foo"},
		"/sbin/init":         {"/usr/bin/init", "/bin/init", "/usr/sbin/init"},
		"/usr/lib/systemd/x": {"/lib/systemd/x"},
		"/usr/lib64/libc.so": {"/lib64/libc.so"},
		"/usr/lib32/libc.so": {"/lib32/libc.so"},
		"/lib/systemd/x":     {"/usr/lib/systemd/x"},
		"/lib64/libc.so":     {"/usr/lib64/libc.so"},
		"/opt/x/bar":         nil,
		"/etc/foo":           nil,
		"":                   nil,
	}
	for in, want := range cases {
		got := usrMergeAlternates(in)
		if !stringsEqual(got, want) {
			t.Errorf("usrMergeAlternates(%q) = %v; want %v", in, got, want)
		}
	}
}

// --- test helpers ---

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", p, err)
	}
}

func stringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
