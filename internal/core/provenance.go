// Package core: provenance.go
//
// Provenance resolves an absolute filesystem path to the package that
// owns it on dpkg- and rpm-based Linux distributions. The Resolver is
// constructed once per agent run; modules consume the small Provenance
// interface so test code can inject a stub.
//
// See docs/adr/0009-provenance-dpkg-rpm.md for the design rationale.
package core

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// PkgStatus describes the result of a provenance lookup.
type PkgStatus string

const (
	// PkgStatusUnknown is returned when provenance has not been queried,
	// the host has no recognized package manager, or Warmup has not yet
	// completed. Distinct from Error because the resolver did not try.
	PkgStatusUnknown PkgStatus = "unknown"

	// PkgStatusOwned means the path is owned by an installed package.
	PkgStatusOwned PkgStatus = "owned"

	// PkgStatusOrphan means the path was checked against a successfully
	// built package-to-path map and no package claims it.
	PkgStatusOrphan PkgStatus = "orphan"

	// PkgStatusError means the lookup attempted the build but failed
	// (e.g. /var/lib/dpkg unreadable, rpm binary missing, query
	// timed out). Subsequent lookups in the same process remain Error.
	PkgStatusError PkgStatus = "error"
)

// String returns the on-wire form of the status, identical to the
// constant value. Provided so callers can write status.String() rather
// than a manual type assertion.
func (s PkgStatus) String() string { return string(s) }

// Provenance is the small read interface every module consumes. The
// production implementation is Resolver; tests inject stubs that return
// fixed answers.
type Provenance interface {
	// Warmup performs any expensive one-shot work (package-manager
	// detection plus the bulk path-to-package map build). It is
	// idempotent and safe to call concurrently. Warmup respects ctx
	// cancellation; if ctx is canceled before the build completes the
	// resolver records the partial state and every subsequent
	// LookupPath returns PkgStatusError.
	Warmup(ctx context.Context)

	// LookupPath returns the owning package (if any) plus the lookup
	// status. The empty string is returned for pkg on every status
	// other than PkgStatusOwned. LookupPath MAY perform a single
	// EvalSymlinks call on a miss, bounded by best-effort I/O on the
	// host filesystem; a hung symlink resolves to PkgStatusOrphan
	// rather than blocking the caller.
	LookupPath(path string) (pkg string, status PkgStatus)
}

// NoopProvenance always returns PkgStatusUnknown. Used by modules in
// tests that do not exercise provenance, and as the default fallback
// when an Options struct leaves the Provenance field nil.
type NoopProvenance struct{}

// Compile-time interface conformance.
var _ Provenance = NoopProvenance{}

// Warmup is a no-op.
func (NoopProvenance) Warmup(context.Context) {}

// LookupPath always returns ("", PkgStatusUnknown).
func (NoopProvenance) LookupPath(string) (string, PkgStatus) {
	return "", PkgStatusUnknown
}

// PackageManager is the family of package manager detected on the host.
type PackageManager int

const (
	// PkgMgrNone means no recognized package manager.
	PkgMgrNone PackageManager = iota
	// PkgMgrDpkg means /var/lib/dpkg/info/ was found.
	PkgMgrDpkg
	// PkgMgrRpm means /var/lib/rpm/ was found.
	PkgMgrRpm
)

// String returns the lowercase name of the package manager.
func (p PackageManager) String() string {
	switch p {
	case PkgMgrDpkg:
		return "dpkg"
	case PkgMgrRpm:
		return "rpm"
	default:
		return "none"
	}
}

// DefaultProvenanceBuildTimeout caps the time the resolver spends
// building its path-to-package map. The map-build cost on observed
// hosts is dominated by I/O (dpkg) or by the rpm child process; both
// finish in single-digit seconds on healthy hosts. Thirty seconds is
// the conservative ceiling.
const DefaultProvenanceBuildTimeout = 30 * time.Second

// Resolver is the production Provenance implementation.
//
// The zero value is NOT usable; construct via NewResolver.
type Resolver struct {
	logger *slog.Logger

	// root prefixes every filesystem path the resolver reads. Empty
	// means absolute paths. Used by tests to point the resolver at a
	// fixture tree without touching the real /var/lib/dpkg.
	root string

	// rpmCommand is the argv to spawn for bulk rpm queries. The
	// first element MUST be an absolute path; the resolver never
	// honors $PATH lookup for the rpm binary. Tests override this to
	// inject a fixture command (e.g. an `echo` printing canned
	// stdout) that simulates rpm without requiring a real rpm DB.
	rpmCommand []string

	// rpmBinaryCandidates are the absolute paths tried in order when
	// rpmCommand is unset. The resolver picks the first existing
	// regular file.
	rpmBinaryCandidates []string

	// buildTimeout caps the map-build phase. Zero means
	// DefaultProvenanceBuildTimeout.
	buildTimeout time.Duration

	// State guarded by the warmup once.
	warmupOnce sync.Once
	warmedUp   atomic.Bool
	pkgMgr     PackageManager
	pathMap    map[string]string
	buildErr   error
}

// ResolverOption tunes a Resolver at construction time.
type ResolverOption func(*Resolver)

// WithProvenanceRoot prefixes every disk path the resolver reads with
// root. Empty means absolute paths. Intended for unit tests; production
// code should leave this alone.
func WithProvenanceRoot(root string) ResolverOption {
	return func(r *Resolver) { r.root = root }
}

// WithProvenanceBuildTimeout overrides the default 30 s ceiling.
func WithProvenanceBuildTimeout(d time.Duration) ResolverOption {
	return func(r *Resolver) { r.buildTimeout = d }
}

// WithProvenanceRpmCommand overrides the rpm bulk-query argv. The first
// element MUST be an absolute path or the spawn fails. Intended for
// unit tests that feed canned stdout.
func WithProvenanceRpmCommand(argv []string) ResolverOption {
	return func(r *Resolver) { r.rpmCommand = append([]string(nil), argv...) }
}

// WithProvenanceRpmBinaryCandidates overrides the list of rpm binary
// paths the resolver tries when no rpmCommand override is set.
func WithProvenanceRpmBinaryCandidates(paths []string) ResolverOption {
	return func(r *Resolver) {
		r.rpmBinaryCandidates = append([]string(nil), paths...)
	}
}

// NewResolver constructs a production Resolver. Defaults are:
//
//   - root: ""                      (real filesystem)
//   - buildTimeout: 30 s
//   - rpm binary candidates: /usr/bin/rpm, /bin/rpm
//   - rpm bulk argv: rpm -qa --filesbypkg --nosignature --nodigest
//
// Pass options to override any of these.
func NewResolver(logger *slog.Logger, opts ...ResolverOption) *Resolver {
	if logger == nil {
		logger = slog.Default()
	}
	r := &Resolver{
		logger:              logger,
		buildTimeout:        DefaultProvenanceBuildTimeout,
		rpmBinaryCandidates: []string{"/usr/bin/rpm", "/bin/rpm"},
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Compile-time interface conformance.
var _ Provenance = (*Resolver)(nil)

// rpmBulkQueryArgs are the flags passed to rpm to dump every file
// owned by every installed package in one invocation.
//
// `--filesbypkg` is the canonical rpm flag for this task. Documented
// in rpm(8) and stable since rpm 4.4 (2005), it emits one line per
// (package, file) pair in the form:
//
//	<package-name>  <whitespace>  <file-path>
//
// The package name is left-padded to a fixed column width by rpm; the
// path follows after one or more whitespace characters. This format
// is robust across every rpm version the agent might encounter,
// including rpm 4.16+ where the older
// `[%{FILENAMES}\t%{NAME}-%{VERSION}-%{RELEASE}\n]` queryformat
// silently produced an incomplete bracket-iteration on minimized
// container images (lab-realistic v0.2.0 surfaced this as a
// 27-host systemd false-positive flood). See ADR-0009.
//
// `--nosignature --nodigest` suppress sig/digest verification, which
// would otherwise log noise to stderr (which we already discard) and
// add unnecessary cost.
var rpmBulkQueryArgs = []string{
	"-qa",
	"--filesbypkg",
	"--nosignature",
	"--nodigest",
}

// Warmup detects the package manager and builds the path-to-package
// map. Idempotent. After Warmup returns, LookupPath becomes a
// lock-free map read.
func (r *Resolver) Warmup(ctx context.Context) {
	r.warmupOnce.Do(func() {
		defer r.warmedUp.Store(true)

		r.pkgMgr = r.detectPackageManager()
		if r.pkgMgr == PkgMgrNone {
			r.logger.Debug("provenance: no package manager detected")
			return
		}

		timeout := r.buildTimeout
		if timeout <= 0 {
			timeout = DefaultProvenanceBuildTimeout
		}
		buildCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		start := time.Now()
		var (
			m   map[string]string
			err error
		)
		switch r.pkgMgr {
		case PkgMgrDpkg:
			m, err = r.buildDpkgMap(buildCtx)
		case PkgMgrRpm:
			m, err = r.buildRpmMap(buildCtx)
		}
		elapsed := time.Since(start)

		if err != nil {
			r.buildErr = err
			r.logger.Warn("provenance build failed",
				"pkg_mgr", r.pkgMgr.String(),
				"elapsed", elapsed,
				"err", err)
			return
		}
		r.pathMap = m
		r.logger.Info("provenance built",
			"pkg_mgr", r.pkgMgr.String(),
			"entries", len(m),
			"elapsed", elapsed)
	})
}

// LookupPath returns the owning package and the status for path.
//
// Lookup is well-defined only for ABSOLUTE filesystem paths. Relative
// names (`pam_unix.so`, bare command tokens from a crontab line such
// as `cd`/`nice`/`test`, PAM @include filenames like `system-auth`)
// are returned as PkgStatusUnknown — the resolver did not try.
// Treating those as `Orphan` would produce thousands of false
// positives on every Linux host because most relative-name records
// (PAM rules, anacrontab, the cron @include catalog) are legitimate
// package-shipped configuration.
//
// On Debian/Ubuntu the dpkg manifest lists usr-merge paths in their
// historical /lib, /bin, /sbin form even after the filesystem
// hierarchy was merged into /usr/. A primary-key miss on
// /usr/lib/X is retried as /lib/X (and vice versa) so the textbook
// systemd ExecStart=/usr/lib/systemd/systemd-* resolves to its
// systemd package, not to PkgStatusOrphan.
func (r *Resolver) LookupPath(path string) (string, PkgStatus) {
	if !r.warmedUp.Load() {
		return "", PkgStatusUnknown
	}
	if r.pkgMgr == PkgMgrNone {
		return "", PkgStatusUnknown
	}
	if r.buildErr != nil {
		return "", PkgStatusError
	}
	if !filepath.IsAbs(path) {
		return "", PkgStatusUnknown
	}
	if pkg, ok := r.pathMap[path]; ok {
		return pkg, PkgStatusOwned
	}
	// Try the usr-merge sibling. Cheap O(prefix-list) check; covers
	// the most common dpkg manifest skew on Debian/Ubuntu.
	for _, alt := range usrMergeAlternates(path) {
		if pkg, ok := r.pathMap[alt]; ok {
			return pkg, PkgStatusOwned
		}
	}
	// Symlink fallback. EvalSymlinks runs against the real
	// filesystem; in test mode callers point the resolver at a Root
	// tree, so this fallback no-ops when path lives outside it.
	if resolved, err := filepath.EvalSymlinks(path); err == nil && resolved != path {
		if pkg, ok := r.pathMap[resolved]; ok {
			return pkg, PkgStatusOwned
		}
	}
	return "", PkgStatusOrphan
}

// usrMergeAlternates returns the usr-merge sibling form of path, or
// nil if path does not match any of the merged prefixes. The pairs
// are documented in the filesystem(7) man page on Debian/Ubuntu and
// in the rpm packaging guidelines on Fedora/RHEL.
func usrMergeAlternates(path string) []string {
	// Pairs ordered by prevalence in the dpkg manifest: most binaries
	// live under /usr/bin (post-merge) and the manifest carries the
	// /bin form. The reverse direction is rarer but still happens for
	// /usr-prefixed paths in some packages.
	pairs := [...]struct{ a, b string }{
		{"/usr/bin/", "/bin/"},
		{"/usr/sbin/", "/sbin/"},
		{"/usr/lib/", "/lib/"},
		{"/usr/lib64/", "/lib64/"},
		{"/usr/lib32/", "/lib32/"},
	}
	for _, p := range pairs {
		switch {
		case strings.HasPrefix(path, p.a):
			return []string{p.b + path[len(p.a):]}
		case strings.HasPrefix(path, p.b):
			return []string{p.a + path[len(p.b):]}
		}
	}
	return nil
}

// PackageManager returns the detected package manager. Useful for
// logging and tests. Returns PkgMgrNone before Warmup completes.
func (r *Resolver) PackageManager() PackageManager { return r.pkgMgr }

// MapSize returns the number of path entries in the built map. Useful
// for tests and metrics. Returns 0 before Warmup completes or on
// build failure.
func (r *Resolver) MapSize() int { return len(r.pathMap) }

// detectPackageManager picks dpkg or rpm based on /etc/os-release plus
// filesystem evidence. See ADR-0009 for the rules.
func (r *Resolver) detectPackageManager() PackageManager {
	dpkgDir := r.resolveRoot("/var/lib/dpkg/info")
	rpmDir := r.resolveRoot("/var/lib/rpm")

	dpkgExists := dirExists(dpkgDir)
	rpmExists := dirExists(rpmDir)

	if !dpkgExists && !rpmExists {
		return PkgMgrNone
	}

	osIDs := r.readOSReleaseIDs()
	prefersDpkg := false
	prefersRpm := false
	for _, id := range osIDs {
		switch id {
		case "debian", "ubuntu", "kali", "raspbian", "linuxmint", "mint",
			"pop", "elementary", "neon", "deepin", "devuan":
			prefersDpkg = true
		case "rhel", "centos", "fedora", "amzn", "rocky", "almalinux",
			"ol", "oracle", "scientific", "opensuse", "opensuse-leap",
			"opensuse-tumbleweed", "sles", "suse":
			prefersRpm = true
		}
	}

	switch {
	case prefersDpkg && dpkgExists:
		return PkgMgrDpkg
	case prefersRpm && rpmExists:
		return PkgMgrRpm
	case dpkgExists:
		return PkgMgrDpkg
	case rpmExists:
		return PkgMgrRpm
	default:
		return PkgMgrNone
	}
}

// readOSReleaseIDs returns ID and every token from ID_LIKE found in
// /etc/os-release. The list is lowercased and de-duplicated. Returns
// an empty slice on any read or parse error.
func (r *Resolver) readOSReleaseIDs() []string {
	f, err := os.Open(r.resolveRoot("/etc/os-release"))
	if err != nil {
		return nil
	}
	defer f.Close()

	var ids []string
	seen := map[string]struct{}{}
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.Trim(s, `"`)
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		ids = append(ids, s)
	}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "ID="):
			add(strings.TrimPrefix(line, "ID="))
		case strings.HasPrefix(line, "ID_LIKE="):
			val := strings.Trim(strings.TrimPrefix(line, "ID_LIKE="), `"`)
			for _, tok := range strings.Fields(val) {
				add(tok)
			}
		}
	}
	return ids
}

// resolveRoot prepends r.root to logical when r.root is set. Mirrors
// the per-module helper used in cron/ldso/etc.
func (r *Resolver) resolveRoot(logical string) string {
	if r.root == "" {
		return logical
	}
	return filepath.Join(r.root, logical)
}

// dirExists returns true iff path is a directory.
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// buildDpkgMap walks /var/lib/dpkg/info/*.list and reads every line as
// an absolute path owned by the package whose name is the file's
// basename minus ".list". File-conflict policy: first occurrence wins.
//
// Version enrichment from /var/lib/dpkg/status is intentionally
// skipped in v0.2.0; ADR-0009 keeps the lookup keyed on name only.
func (r *Resolver) buildDpkgMap(ctx context.Context) (map[string]string, error) {
	infoDir := r.resolveRoot("/var/lib/dpkg/info")
	entries, err := os.ReadDir(infoDir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", infoDir, err)
	}

	out := make(map[string]string, 200_000)
	for _, e := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".list") {
			continue
		}
		if e.IsDir() {
			continue
		}
		pkgName := strings.TrimSuffix(name, ".list")
		// Drop arch suffix (foo:amd64.list) for the user-visible key.
		if colon := strings.LastIndex(pkgName, ":"); colon >= 0 {
			pkgName = pkgName[:colon]
		}
		full := filepath.Join(infoDir, name)
		if err := r.scanDpkgList(full, pkgName, out); err != nil {
			r.logger.Debug("provenance: skip dpkg list",
				"file", full, "err", err)
			// Continue: one bad list does not sink the whole build.
		}
	}
	return out, nil
}

// scanDpkgList reads one .list file line by line and inserts each
// non-empty line into out under pkgName, honoring the first-wins
// conflict policy.
func (r *Resolver) scanDpkgList(path, pkgName string, out map[string]string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.TrimSpace(sc.Text())
		if p == "" || p == "/." {
			continue
		}
		if _, dup := out[p]; dup {
			continue
		}
		out[p] = pkgName
	}
	return sc.Err()
}

// buildRpmMap spawns `rpm -qa --filesbypkg` and streams its output
// into a path-to-package map. Each line emitted by --filesbypkg has
// the form
//
//	<package-name>  <whitespace>  <file-path>
//
// See rpmBulkQueryArgs for the rationale. On any failure (binary
// missing, non-zero exit, scanner error) the resolver returns the
// error and Warmup records it under buildErr.
func (r *Resolver) buildRpmMap(ctx context.Context) (map[string]string, error) {
	argv := r.rpmCommand
	if len(argv) == 0 {
		bin, ok := r.findRpmBinary()
		if !ok {
			return nil, errors.New("rpm binary not found at any candidate path")
		}
		argv = append([]string{bin}, rpmBulkQueryArgs...)
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	// WaitDelay bounds the time cmd.Wait blocks after ctx cancellation
	// waiting for the pipe to drain. A misbehaving rpm wrapper that
	// forks a child holding stdout open (e.g. a shell that does
	// `sleep 5` without `exec`) would otherwise stall the build past
	// the context deadline. With a 5 s ceiling Wait force-closes the
	// pipe and returns, so --provenance-timeout is actually honored.
	cmd.WaitDelay = 5 * time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("rpm stdout pipe: %w", err)
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("rpm start: %w", err)
	}

	out := make(map[string]string, 200_000)
	if err := scanRpmStream(stdout, out); err != nil {
		// Drain to allow Wait to complete cleanly.
		_, _ = io.Copy(io.Discard, stdout)
		_ = cmd.Wait()
		return nil, fmt.Errorf("rpm stream: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("rpm wait: %w", err)
	}
	return out, nil
}

// findRpmBinary returns the first existing regular file in
// r.rpmBinaryCandidates. Honors Root for tests so a fixture tree can
// host a fake rpm binary.
func (r *Resolver) findRpmBinary() (string, bool) {
	for _, p := range r.rpmBinaryCandidates {
		probe := p
		if r.root != "" {
			probe = filepath.Join(r.root, p)
		}
		info, err := os.Stat(probe)
		if err != nil {
			continue
		}
		if info.IsDir() {
			continue
		}
		return probe, true
	}
	return "", false
}

// AnnotateExecTargetProvenance is the helper every module calls
// immediately after populating Record.ExecTarget. It looks up target
// against the given resolver and, when the result is informative,
// populates Record.ExecTargetPkg + Record.ExecTargetPkgStatus and
// appends SignalNonPackagePath when the target is orphan.
//
// PkgStatusUnknown is treated as "resolver had nothing to say" and is
// NOT serialized into the Record. This preserves byte-for-byte
// compatibility with golden tests that run under NoopProvenance.
//
// rec is modified in place. Callers that already finalized rec.Signals
// (sorted, de-duplicated) MUST re-finalize after this call.
func AnnotateExecTargetProvenance(rec *Record, p Provenance, target string) {
	if rec == nil || p == nil || target == "" {
		return
	}
	pkg, status := p.LookupPath(target)
	if status == PkgStatusUnknown {
		return
	}
	rec.ExecTargetPkgStatus = status.String()
	if pkg != "" {
		rec.ExecTargetPkg = pkg
	}
	if status == PkgStatusOrphan {
		rec.Signals = append(rec.Signals, SignalNonPackagePath)
	}
}

// scanRpmStream parses the output of `rpm -qa --filesbypkg`. Each
// line emitted by rpm has the shape:
//
//	<package-name>  <whitespace>  <file-path>
//
// The package name is left-padded to a fixed column by rpm; the path
// follows after one or more whitespace characters. Paths that start
// with the literal `(none)` sentinel (rpm uses it for files that
// have been removed via `rpm -e --noscripts`) and empty paths are
// skipped. First-wins conflict policy as in dpkg.
func scanRpmStream(stream io.Reader, out map[string]string) error {
	sc := bufio.NewScanner(stream)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		// Split on first whitespace run: name is first token, path
		// is everything after the gap (trimmed of leading spaces).
		i := strings.IndexAny(line, " \t")
		if i <= 0 {
			continue
		}
		name := line[:i]
		path := strings.TrimLeft(line[i+1:], " \t")
		if path == "" || path == "(none)" {
			continue
		}
		// Defensive: rpm prints package names as the bare NAME
		// (without version) for --filesbypkg. Strip a trailing
		// `-<NVR>` glob if a future rpm version changes that, so the
		// downstream map key shape stays consistent across rpm
		// versions and across the dpkg / rpm backends.
		name = trimNVRSuffix(name)
		if _, dup := out[path]; dup {
			continue
		}
		out[path] = name
	}
	return sc.Err()
}

// trimNVRSuffix removes a trailing `-<version>-<release>` from a
// package name string. Defensive against rpm version drift: in
// versions where --filesbypkg starts emitting full NVR (none of the
// versions tested today do, but worth defending against), the
// downstream code keeps seeing the bare NAME consistent with the
// dpkg manifest format.
func trimNVRSuffix(s string) string {
	// An NVR ends in `-<release>` where release is alphanumeric+dots.
	// Strip the rightmost `-<token>-<token>` pair if both tokens look
	// like version components (start with a digit).
	if !strings.ContainsRune(s, '-') {
		return s
	}
	lastDash := strings.LastIndexByte(s, '-')
	if lastDash < 1 || lastDash >= len(s)-1 {
		return s
	}
	if !isVersionToken(s[lastDash+1:]) {
		return s
	}
	prev := strings.LastIndexByte(s[:lastDash], '-')
	if prev < 1 || prev >= lastDash-1 {
		return s
	}
	if !isVersionToken(s[prev+1 : lastDash]) {
		return s
	}
	return s[:prev]
}

// isVersionToken returns true if s looks like a package version
// component: starts with a digit, contains only [0-9A-Za-z._+].
func isVersionToken(s string) bool {
	if s == "" || (s[0] < '0' || s[0] > '9') {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c == '.', c == '_', c == '+', c == '~':
		default:
			return false
		}
	}
	return true
}
