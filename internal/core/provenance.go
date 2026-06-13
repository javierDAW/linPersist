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
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	// PkgMgrApk means /lib/apk/db/installed was found (Alpine).
	PkgMgrApk
	// PkgMgrPacman means /var/lib/pacman/local/ was found (Arch family).
	PkgMgrPacman
	// PkgMgrPortage means /var/db/pkg/ was found (Gentoo family).
	PkgMgrPortage
)

// String returns the lowercase name of the package manager.
func (p PackageManager) String() string {
	switch p {
	case PkgMgrDpkg:
		return "dpkg"
	case PkgMgrRpm:
		return "rpm"
	case PkgMgrApk:
		return "apk"
	case PkgMgrPacman:
		return "pacman"
	case PkgMgrPortage:
		return "portage"
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

	// rpmDigestCommand is the argv to spawn for the bulk per-file digest
	// query that feeds fileDigests on rpm hosts. Same override contract
	// as rpmCommand (tests inject a fixture command printing canned
	// "<path> <hexdigest>" lines); unset means
	// findRpmBinary + rpmDigestQueryArgs.
	rpmDigestCommand []string

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

	// fileDigests maps an absolute package-owned path to the lowercase
	// hex digest the package manager recorded for it at install time.
	// The digest ALGORITHM is encoded by the hex length and inferred at
	// compare time (32=MD5, 40=SHA-1, 64=SHA-256), so all three package
	// managers share one map and one VerifyPath:
	//   - dpkg: MD5 from /var/lib/dpkg/info/*.md5sums + the Conffiles:
	//     stanzas of /var/lib/dpkg/status (conffiles are absent from
	//     *.md5sums by design).
	//   - rpm:  the per-file FILEDIGESTS (SHA-256 on RHEL7+/Rocky/Fedora,
	//     MD5 on EL5/6) dumped by a single bulk `rpm -qa --qf` query.
	//   - apk:  the Z: (Q1<base64 SHA-1>) checksum of each file in
	//     /lib/apk/db/installed.
	// Nil on hosts where integrity data could not be read; VerifyPath
	// then degrades to PkgVerifyUnknown rather than guessing. Read-only
	// after Warmup.
	fileDigests map[string]string

	// verifyCache memoizes VerifyPath results per absolute path so the
	// per-line records the modules emit for one config file (a crontab
	// with N entries, an sshd_config with N directives) hash the file
	// at most once per run. sync.Map because the runner's sink is
	// serialized today but VerifyPath makes no such assumption.
	verifyCache sync.Map // map[string]PkgVerifyStatus
}

// PkgVerifyStatus describes the result of a package-file integrity
// check (VerifyPath).
type PkgVerifyStatus string

const (
	// PkgVerifyUnknown: integrity was not evaluated -- resolver not
	// warmed, no integrity database (non-dpkg host or unreadable
	// metadata), or the path is not absolute. Distinct from NotOwned
	// (the resolver checked and the path has no recorded hash).
	PkgVerifyUnknown PkgVerifyStatus = "unknown"

	// PkgVerifyNotOwned: the path has no hash recorded by any package
	// (it is not a packaged file, or is a packaged file the manager
	// does not hash). No tamper claim can be made.
	PkgVerifyNotOwned PkgVerifyStatus = "not_owned"

	// PkgVerifyMatched: the on-disk content matches the recorded hash.
	PkgVerifyMatched PkgVerifyStatus = "matched"

	// PkgVerifyMismatched: the on-disk content differs from the
	// recorded hash -- the file has been modified since install. This
	// is the state that drives SignalPackageFileTampered.
	PkgVerifyMismatched PkgVerifyStatus = "mismatched"

	// PkgVerifyError: a hash was recorded but the on-disk file could
	// not be read (deleted, EACCES, I/O error). No tamper claim is
	// made; surfaced separately so it never masquerades as Matched.
	PkgVerifyError PkgVerifyStatus = "error"
)

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

// WithProvenanceRpmDigestCommand overrides the rpm per-file digest-query
// argv (the source of fileDigests on rpm hosts). Same contract as
// WithProvenanceRpmCommand; intended for unit tests.
func WithProvenanceRpmDigestCommand(argv []string) ResolverOption {
	return func(r *Resolver) { r.rpmDigestCommand = append([]string(nil), argv...) }
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

// rpmDigestQueryArgs dump every file's recorded content digest plus its
// per-file verify flags, one "<path> <hexdigest> <verifyflags>" triple
// per line. FILEDIGESTS is the digest rpm stored at install (SHA-256 on
// RHEL7+/Rocky/Fedora, MD5 on EL5/6); the algorithm is recovered from the
// hex length at compare time, so we do NOT need FILEDIGESTALGO (a header
// scalar that does not broadcast reliably across the `[]` array iterator
// in older rpm).
//
// FILEVERIFYFLAGS is the crux of matching `rpm -V` semantics: the `setup`
// package ships /etc/passwd, /etc/group, /etc/shadow, /etc/gshadow etc.
// with `%verify(not md5 ...)` because they are EXPECTED to change after
// install, so rpm clears their digest-verify bit and `rpm -V` stays
// silent. Honoring the bit (RPMVERIFY_FILEDIGEST = 1) skips exactly those
// files; comparing their digest anyway produced a ~6-file / ~108-record
// false-positive flood on every Rocky host (the nspawn lab caught this).
// Files with no content digest (dirs, symlinks, %ghost) emit an empty
// digest field and are skipped too.
var rpmDigestQueryArgs = []string{
	"-qa",
	"--qf", "[%{FILENAMES} %{FILEDIGESTS} %{FILEVERIFYFLAGS}\n]",
	"--nosignature",
	"--nodigest",
}

// rpmVerifyFileDigestBit is RPMVERIFY_FILEDIGEST: when this bit is clear
// in a file's FILEVERIFYFLAGS, rpm does not digest-verify the file and
// neither do we.
const rpmVerifyFileDigestBit = 1

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
		case PkgMgrApk:
			m, err = r.buildApkMap(buildCtx)
		case PkgMgrPacman:
			m, err = r.buildPacmanMap(buildCtx)
		case PkgMgrPortage:
			m, err = r.buildPortageMap(buildCtx)
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

		// Integrity (package-file tamper) database, per package manager.
		// Best-effort -- a read/query failure leaves fileDigests nil and
		// VerifyPath degrades to PkgVerifyUnknown rather than failing the
		// whole provenance build (ownership lookups still work).
		var (
			dig  map[string]string
			derr error
		)
		switch r.pkgMgr {
		case PkgMgrDpkg:
			dig, derr = r.buildDpkgHashes(buildCtx)
		case PkgMgrRpm:
			dig, derr = r.buildRpmDigests(buildCtx)
		case PkgMgrApk:
			dig, derr = r.buildApkDigests(buildCtx)
		case PkgMgrPortage:
			dig, derr = r.buildPortageDigests(buildCtx)
		case PkgMgrPacman:
			// pacman keeps per-file sha256 ONLY in the gzipped mtree (not the
			// plaintext `files` index) -- parsed here so package_file_tampered
			// works on Arch family too.
			dig, derr = r.buildPacmanDigests(buildCtx)
		}
		if derr != nil {
			r.logger.Warn("provenance integrity unavailable",
				"pkg_mgr", r.pkgMgr.String(), "err", derr)
		} else {
			r.fileDigests = dig
		}

		r.logger.Info("provenance built",
			"pkg_mgr", r.pkgMgr.String(),
			"entries", len(m),
			"integrity_entries", len(r.fileDigests),
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

// binMergeDirs are the executable directories that collapse into a single
// equivalence class on a usr-merged system. Debian/Ubuntu keep /usr/bin and
// /usr/sbin distinct (only /bin->/usr/bin, /sbin->/usr/sbin); Arch, Fedora
// and Gentoo merge ALL FOUR into /usr/bin. A package DB may record any of
// these forms (Gentoo portage records /sbin/unix_chkpwd while the file is
// reached at /usr/bin/unix_chkpwd), so a lookup under any one must try the
// same basename under all of them.
var binMergeDirs = []string{"/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/"}

// libMergePairs are the /usr-merge library-dir pairs (one-to-one).
var libMergePairs = [...]struct{ a, b string }{
	{"/usr/lib/", "/lib/"},
	{"/usr/lib64/", "/lib64/"},
	{"/usr/lib32/", "/lib32/"},
}

// usrMergeAlternates returns the usr-merge sibling forms of path, or nil
// if path matches no merged prefix. For an executable path it returns the
// basename under every OTHER bin/sbin merge dir (covering the full
// /bin,/sbin,/usr/sbin -> /usr/bin collapse on Arch/Fedora/Gentoo); for a
// library path it returns the one /usr<->non-/usr sibling. Extra
// non-matching candidates on a non-merged host simply miss the map and are
// harmless (a wrong "owned" would be a false negative, never the false
// positive we are eliminating). See filesystem(7) / the rpm + portage
// packaging guidelines.
func usrMergeAlternates(path string) []string {
	for _, d := range binMergeDirs {
		if strings.HasPrefix(path, d) {
			base := path[len(d):]
			out := make([]string, 0, len(binMergeDirs)-1)
			for _, alt := range binMergeDirs {
				if alt != d {
					out = append(out, alt+base)
				}
			}
			return out
		}
	}
	for _, p := range libMergePairs {
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

// Provenance trust-regime labels (host_meta.provenance_regime). They tell
// the backend whether the ownership oracle was authoritative on a host: a
// quiet/empty Q7 OR a non_package_path flood means opposite things when the
// oracle was fully built vs. blind (no package manager) vs. degraded (build
// failed or timed out — every exec_target then resolves Unknown/Error).
const (
	RegimeOwnedDBPresent  = "owned-db-present"  // pkg DB detected and built OK
	RegimePkgMgrNone      = "pkg-mgr-none"      // distroless/scratch/appliance: oracle inert
	RegimeBuildError      = "build-error"       // pkg mgr present but the map build failed
	RegimeTimeoutDegraded = "timeout-degraded"  // the map build hit --provenance-timeout
	RegimeDisabled        = "disabled"          // --no-provenance: oracle deliberately off
)

// Regime reports the resolver's trust state after Warmup (see the Regime*
// constants). The backend MUST down-weight findings on any host whose
// regime is not owned-db-present.
func (r *Resolver) Regime() string {
	if r.pkgMgr == PkgMgrNone {
		return RegimePkgMgrNone
	}
	if r.buildErr != nil {
		if errors.Is(r.buildErr, context.DeadlineExceeded) {
			return RegimeTimeoutDegraded
		}
		return RegimeBuildError
	}
	return RegimeOwnedDBPresent
}

// MapSize returns the number of path entries in the built map. Useful
// for tests and metrics. Returns 0 before Warmup completes or on
// build failure.
func (r *Resolver) MapSize() int { return len(r.pathMap) }

// detectPackageManager picks dpkg, rpm or apk based on /etc/os-release
// plus filesystem evidence. See ADR-0009 for the rules; apk added in
// v0.5.0 to cover Alpine and Alpine-derived container images.
func (r *Resolver) detectPackageManager() PackageManager {
	dpkgDir := r.resolveRoot("/var/lib/dpkg/info")
	rpmDir := r.resolveRoot("/var/lib/rpm")
	apkDB := r.resolveRoot("/lib/apk/db/installed")
	pacmanDir := r.resolveRoot("/var/lib/pacman/local")
	portageDir := r.resolveRoot("/var/db/pkg")

	dpkgExists := dirExists(dpkgDir)
	rpmExists := dirExists(rpmDir)
	apkExists := fileExists(apkDB)
	pacmanExists := dirExists(pacmanDir)
	portageExists := dirExists(portageDir)

	if !dpkgExists && !rpmExists && !apkExists && !pacmanExists && !portageExists {
		return PkgMgrNone
	}

	osIDs := r.readOSReleaseIDs()
	prefersDpkg := false
	prefersRpm := false
	prefersApk := false
	prefersPacman := false
	prefersPortage := false
	for _, id := range osIDs {
		switch id {
		case "debian", "ubuntu", "kali", "raspbian", "linuxmint", "mint",
			"pop", "elementary", "neon", "deepin", "devuan":
			prefersDpkg = true
		case "rhel", "centos", "fedora", "amzn", "rocky", "almalinux",
			"ol", "oracle", "scientific", "opensuse", "opensuse-leap",
			"opensuse-tumbleweed", "sles", "suse":
			prefersRpm = true
		case "alpine", "postmarketos", "wolfi", "chainguard":
			prefersApk = true
		case "arch", "archarm", "manjaro", "manjaro-arm", "endeavouros",
			"artix", "garuda", "cachyos", "arcolinux":
			prefersPacman = true
		case "gentoo", "funtoo", "calculate":
			prefersPortage = true
		}
	}

	switch {
	case prefersApk && apkExists:
		return PkgMgrApk
	case prefersDpkg && dpkgExists:
		return PkgMgrDpkg
	case prefersRpm && rpmExists:
		return PkgMgrRpm
	case prefersPacman && pacmanExists:
		return PkgMgrPacman
	case prefersPortage && portageExists:
		return PkgMgrPortage
	case apkExists:
		return PkgMgrApk
	case dpkgExists:
		return PkgMgrDpkg
	case rpmExists:
		return PkgMgrRpm
	case pacmanExists:
		return PkgMgrPacman
	case portageExists:
		return PkgMgrPortage
	default:
		return PkgMgrNone
	}
}

// fileExists returns true iff path is a regular file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
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

// buildDpkgHashes builds the absolute-path → recorded-MD5 map used by
// VerifyPath. It reads TWO sources, because dpkg records integrity in
// two places:
//
//   - /var/lib/dpkg/info/<pkg>.md5sums — one line per regular packaged
//     file, "<md5>␣␣<relative-path>" (path has no leading slash).
//   - /var/lib/dpkg/status Conffiles: stanzas — registered conffiles
//     (e.g. /etc/crontab), which are DELIBERATELY absent from md5sums
//     so an admin edit does not make dpkg report the file as modified
//     during a verify of the regular file list. Parsing only md5sums
//     would therefore miss exactly the "append to /etc/crontab" shape
//     this signal exists to catch.
//
// File-conflict policy: first occurrence wins (md5sums scanned first).
// A failure to enumerate the info directory is fatal to the integrity
// build (it is the bulk source); a failure to read status is logged and
// tolerated (conffiles are a supplement).
func (r *Resolver) buildDpkgHashes(ctx context.Context) (map[string]string, error) {
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
		if e.IsDir() || !strings.HasSuffix(name, ".md5sums") {
			continue
		}
		if err := scanMd5sums(filepath.Join(infoDir, name), out); err != nil {
			r.logger.Debug("provenance: skip md5sums",
				"file", name, "err", err)
		}
	}
	if err := r.scanDpkgConffiles(out); err != nil {
		r.logger.Debug("provenance: conffiles parse partial", "err", err)
	}
	return out, nil
}

// scanMd5sums reads one *.md5sums file. Each line is "<md5>␣␣<path>"
// where the path is relative to / with no leading slash and MAY contain
// spaces, so the md5 is taken as the fixed 32-char prefix and the
// remainder (trimmed) is the path. Malformed lines are skipped.
func scanMd5sums(path string, out map[string]string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if len(line) < 34 { // 32 hex + at least "  /x"
			continue
		}
		sum := strings.ToLower(line[:32])
		if !isHex32(sum) {
			continue
		}
		rel := strings.TrimSpace(line[32:])
		if rel == "" {
			continue
		}
		abs := "/" + rel
		if _, dup := out[abs]; !dup {
			out[abs] = sum
		}
	}
	return sc.Err()
}

// scanDpkgConffiles walks /var/lib/dpkg/status and extracts every
// registered conffile's recorded MD5. The status file is deb822: a
// "Conffiles:" field header is followed by continuation lines that
// begin with a space, each " <abs-path> <md5> [obsolete|newconffile]".
// A line that does not begin with a space ends the block. Entries whose
// hash token is not a 32-hex digest (e.g. the "newconffile" marker) are
// skipped. md5sums entries already present win (scanned first).
func (r *Resolver) scanDpkgConffiles(out map[string]string) error {
	statusPath := r.resolveRoot("/var/lib/dpkg/status")
	f, err := os.Open(statusPath)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	inConffiles := false
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] != ' ' && line[0] != '\t' {
			inConffiles = strings.HasPrefix(line, "Conffiles:")
			continue
		}
		if !inConffiles {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		sum := strings.ToLower(fields[1])
		if !isHex32(sum) {
			continue
		}
		if _, dup := out[fields[0]]; !dup {
			out[fields[0]] = sum
		}
	}
	return sc.Err()
}

// isHex32 reports whether s is exactly 32 lowercase-or-uppercase hex
// digits (the shape of an MD5 digest). Caller lowercases for storage.
func isHex32(s string) bool {
	return len(s) == 32 && isHexString(s)
}

// isHexDigest reports whether s is a hex digest of a length the verifier
// can recompute: 32 (MD5/dpkg), 40 (SHA-1/apk) or 64 (SHA-256/rpm). Any
// other length is rejected so an unknown algorithm never enters the map.
func isHexDigest(s string) bool {
	switch len(s) {
	case 32, 40, 64:
		return isHexString(s)
	default:
		return false
	}
}

// isHexString reports whether every byte of s is a hex digit.
func isHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// VerifyPath reports whether the file at an absolute package-owned path
// still matches the hash the package manager recorded at install time.
// It is the integrity counterpart to LookupPath (which answers
// ownership only) and drives SignalPackageFileTampered at the emit sink.
//
// Returns PkgVerifyUnknown when integrity cannot be evaluated (resolver
// not warmed, non-dpkg host, integrity DB unreadable, relative path) so
// callers never confuse "could not check" with "checked, clean". Results
// are memoized per path: the N per-line records a single config file
// produces hash it at most once per run.
//
// Covers dpkg, rpm and apk: the recorded digest's algorithm is inferred
// from its hex length (see hashByHexLen), so one implementation serves
// all three.
func (r *Resolver) VerifyPath(path string) PkgVerifyStatus {
	if !r.warmedUp.Load() || r.buildErr != nil {
		return PkgVerifyUnknown
	}
	if r.fileDigests == nil || !filepath.IsAbs(path) {
		return PkgVerifyUnknown
	}
	if cached, ok := r.verifyCache.Load(path); ok {
		return cached.(PkgVerifyStatus)
	}
	st := r.verifyUncached(path)
	r.verifyCache.Store(path, st)
	return st
}

// verifyUncached performs the recorded-digest lookup and on-disk
// comparison for VerifyPath, applying the same usr-merge sibling
// fallback as LookupPath so /usr/bin/X resolves to a manifest entry
// recorded as /bin/X (and vice versa). The on-disk file is hashed with
// the algorithm implied by the recorded digest's length.
func (r *Resolver) verifyUncached(path string) PkgVerifyStatus {
	recorded, ok := r.fileDigests[path]
	if !ok {
		for _, alt := range usrMergeAlternates(path) {
			if recorded, ok = r.fileDigests[alt]; ok {
				break
			}
		}
	}
	if !ok {
		return PkgVerifyNotOwned
	}
	got, err := hashByHexLen(r.resolveRoot(path), len(recorded))
	if err != nil {
		return PkgVerifyError
	}
	if got == recorded {
		return PkgVerifyMatched
	}
	return PkgVerifyMismatched
}

// hashByHexLen streams path through the hash whose hex digest is hexLen
// characters long -- MD5 (32, dpkg), SHA-1 (40, apk), SHA-256 (64, rpm)
// -- and returns the lowercase hex digest. Streaming keeps memory
// constant regardless of file size; callers only invoke this for
// package-owned loci (overwhelmingly small config files) and memoize the
// result. An unrecognized length returns an error so an unknown digest
// algorithm can never masquerade as a match.
func hashByHexLen(path string, hexLen int) (string, error) {
	var h hash.Hash
	switch hexLen {
	case 32:
		h = md5.New()
	case 40:
		h = sha1.New()
	case 64:
		h = sha256.New()
	default:
		return "", fmt.Errorf("unsupported digest hex length %d", hexLen)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// TamperSignal maps a VerifyPath result to the signal slice the emit
// sink appends to a Record. Only a confirmed Mismatched yields
// SignalPackageFileTampered; every other status (including Error and
// NotOwned) yields nil so the signal never fires on uncertainty.
func TamperSignal(status PkgVerifyStatus) []string {
	if status == PkgVerifyMismatched {
		return []string{SignalPackageFileTampered}
	}
	return nil
}

// buildApkMap parses /lib/apk/db/installed and returns a path → pkg
// map. The apk-tools "world database" is a single text file with
// record-oriented format separated by blank lines; each record is a
// package, each non-empty line is a `K:value` tuple. The keys this
// builder cares about:
//
//	P:<name>     — package name, sets the "current package"
//	F:<dir>      — relative-to-root directory, sets the "current dir"
//	R:<file>     — file within the current dir; one (P, /F/R) entry
//
// Any non-key line, comment, or unknown key is silently skipped.
// File-conflict policy: first occurrence wins (same as dpkg/rpm
// paths in the existing builders).
//
// Performance: a stock Alpine 3.19 minirootfs has ~20-25 packages
// totalling ~2500 lines; a fat container with build-base, ssh, curl
// etc. is ~50-100 packages and a few thousand lines. Single-pass
// scanner under 50 ms.
func (r *Resolver) buildApkMap(ctx context.Context) (map[string]string, error) {
	path := r.resolveRoot("/lib/apk/db/installed")
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	out := make(map[string]string, 20_000)
	sc := bufio.NewScanner(f)
	// apk installed records can carry long Z: (content hash) lines,
	// but the project-wide line cap of 1 MiB is more than enough.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var (
		curPkg string
		curDir string
	)
	for sc.Scan() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		line := sc.Text()
		if line == "" {
			// Record terminator: clear state so a missing P: in the
			// next record does not leak ownership across packages.
			curPkg = ""
			curDir = ""
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		key := line[0]
		val := line[2:]
		switch key {
		case 'P':
			curPkg = val
		case 'F':
			curDir = val
		case 'R':
			if curPkg == "" {
				continue
			}
			// F: is relative to / and has no leading slash; combine
			// to an absolute path. R: at the root (curDir == "")
			// produces /<R>.
			var abs string
			if curDir == "" {
				abs = "/" + val
			} else {
				abs = "/" + curDir + "/" + val
			}
			if _, dup := out[abs]; dup {
				continue
			}
			out[abs] = curPkg
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	return out, nil
}

// buildApkDigests re-parses /lib/apk/db/installed for the per-file Z:
// checksum that follows each R: entry, returning a path -> hex SHA-1
// map. The Z: value is `Q1<base64(sha1)>` (the only checksum scheme apk
// has shipped); the "Q1" tag marks SHA-1, the rest is standard base64 of
// the 20-byte digest, which we decode and hex-encode so it shares the
// length-keyed compare path with dpkg/rpm. Files without a Z: line, or
// with an unrecognized checksum tag, are skipped.
func (r *Resolver) buildApkDigests(ctx context.Context) (map[string]string, error) {
	path := r.resolveRoot("/lib/apk/db/installed")
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	out := make(map[string]string, 20_000)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var curDir, lastAbs string
	for sc.Scan() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		line := sc.Text()
		if line == "" {
			curDir, lastAbs = "", ""
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		val := line[2:]
		switch line[0] {
		case 'F':
			curDir = val
		case 'R':
			if curDir == "" {
				lastAbs = "/" + val
			} else {
				lastAbs = "/" + curDir + "/" + val
			}
		case 'Z':
			if lastAbs == "" || !strings.HasPrefix(val, "Q1") {
				continue
			}
			raw, derr := base64.StdEncoding.DecodeString(val[2:])
			if derr != nil || len(raw) != sha1.Size {
				continue
			}
			if _, dup := out[lastAbs]; !dup {
				out[lastAbs] = hex.EncodeToString(raw)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	return out, nil
}

// buildPacmanMap walks /var/lib/pacman/local/<name>-<ver>-<rel>/files and
// reads the `%FILES%` section of each, mapping every listed file (not the
// directory entries, which end in "/") to the package name. pacman's
// `files` index lists paths relative to / without a leading slash, so each
// becomes "/"+line. First-occurrence-wins, as in dpkg.
func (r *Resolver) buildPacmanMap(ctx context.Context) (map[string]string, error) {
	base := r.resolveRoot("/var/lib/pacman/local")
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil, fmt.Errorf("readdir %s: %w", base, err)
	}
	out := make(map[string]string, 40_000)
	for _, e := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !e.IsDir() {
			continue
		}
		pkg := trimLastTwoHyphenFields(e.Name())
		f, ferr := os.Open(filepath.Join(base, e.Name(), "files"))
		if ferr != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		inFiles := false
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "%") && strings.HasSuffix(strings.TrimSpace(line), "%") {
				inFiles = strings.TrimSpace(line) == "%FILES%"
				continue
			}
			if !inFiles || line == "" || strings.HasSuffix(line, "/") {
				continue // section header, blank, or a directory entry
			}
			abs := "/" + strings.TrimPrefix(line, "/")
			if _, dup := out[abs]; !dup {
				out[abs] = pkg
			}
		}
		f.Close()
	}
	return out, nil
}

// buildPacmanDigests maps each package-owned absolute path to its recorded
// lowercase sha256, parsed from the gzipped mtree v2.0 file pacman keeps per
// package at /var/lib/pacman/local/<name>/mtree. Format: a `#mtree` header,
// `/set <key=val>...` default lines, then per-entry `./relpath <key=val>...`
// lines; files carry `sha256digest=<hex>`, dirs/symlinks do not (skipped).
// This is the data the plaintext `files` index lacks, which is why pacman
// tamper was previously deferred.
func (r *Resolver) buildPacmanDigests(ctx context.Context) (map[string]string, error) {
	base := r.resolveRoot("/var/lib/pacman/local")
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil, fmt.Errorf("readdir %s: %w", base, err)
	}
	out := make(map[string]string, 40_000)
	for _, e := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !e.IsDir() {
			continue
		}
		f, ferr := os.Open(filepath.Join(base, e.Name(), "mtree"))
		if ferr != nil {
			continue
		}
		gz, gerr := gzip.NewReader(f)
		if gerr != nil {
			f.Close()
			continue
		}
		sc := bufio.NewScanner(gz)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Text()
			// Per-file entries start with "./"; "#mtree", "/set ...", blanks skip.
			if len(line) < 2 || line[0] != '.' || line[1] != '/' {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			digest := ""
			for _, fld := range fields[1:] {
				if v, ok := strings.CutPrefix(fld, "sha256digest="); ok {
					digest = strings.ToLower(v)
					break
				}
			}
			if digest == "" {
				continue // directory / symlink / no digest
			}
			abs := mtreeUnescape(fields[0][1:]) // "./usr/bin/x" -> "/usr/bin/x"
			if abs == "" || abs[0] != '/' {
				continue
			}
			if _, dup := out[abs]; !dup {
				out[abs] = digest
			}
		}
		gz.Close()
		f.Close()
	}
	return out, nil
}

// mtreeUnescape decodes the backslash escapes mtree uses in path fields:
// octal \NNN byte escapes (e.g. \040 for space) and \\ for backslash. Most
// paths need no decoding; this keeps a path with a space/specials correct.
func mtreeUnescape(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s)+1 {
			if i+1 < len(s) && s[i+1] == '\\' {
				b.WriteByte('\\')
				i++
				continue
			}
			if i+3 < len(s) && isOctal(s[i+1]) && isOctal(s[i+2]) && isOctal(s[i+3]) {
				v := (int(s[i+1]-'0') << 6) | (int(s[i+2]-'0') << 3) | int(s[i+3]-'0')
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }

// buildPortageMap walks /var/db/pkg/<category>/<pkg-version>/CONTENTS and
// maps every `obj`/`sym` path to "<category>/<pkg-version>". The CONTENTS
// format is one record per line: `obj <path> <md5> <mtime>`,
// `sym <path> -> <target> <mtime>`, `dir <path>` — field[1] is the path
// for obj and sym; dir entries are skipped.
func (r *Resolver) buildPortageMap(ctx context.Context) (map[string]string, error) {
	base := r.resolveRoot("/var/db/pkg")
	cats, err := os.ReadDir(base)
	if err != nil {
		return nil, fmt.Errorf("readdir %s: %w", base, err)
	}
	out := make(map[string]string, 40_000)
	for _, cat := range cats {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !cat.IsDir() {
			continue
		}
		pkgs, perr := os.ReadDir(filepath.Join(base, cat.Name()))
		if perr != nil {
			continue
		}
		for _, p := range pkgs {
			if !p.IsDir() {
				continue
			}
			pkgLabel := cat.Name() + "/" + p.Name()
			f, ferr := os.Open(filepath.Join(base, cat.Name(), p.Name(), "CONTENTS"))
			if ferr != nil {
				continue
			}
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			for sc.Scan() {
				fields := strings.Fields(sc.Text())
				if len(fields) < 2 {
					continue
				}
				if fields[0] != "obj" && fields[0] != "sym" {
					continue
				}
				abs := fields[1]
				if !strings.HasPrefix(abs, "/") {
					continue
				}
				if _, dup := out[abs]; !dup {
					out[abs] = pkgLabel
				}
			}
			f.Close()
		}
	}
	return out, nil
}

// buildPortageDigests re-walks /var/db/pkg/*/*/CONTENTS for the per-file
// MD5 carried on every `obj` line (`obj <path> <md5> <mtime>`), returning
// a path -> hex MD5 map. The 32-hex length routes it through the same
// length-keyed compare path as dpkg md5sums. (sym/dir lines carry no
// digest and are skipped; pacman has no plaintext digest, hence no
// buildPacmanDigests.)
func (r *Resolver) buildPortageDigests(ctx context.Context) (map[string]string, error) {
	base := r.resolveRoot("/var/db/pkg")
	cats, err := os.ReadDir(base)
	if err != nil {
		return nil, fmt.Errorf("readdir %s: %w", base, err)
	}
	out := make(map[string]string, 40_000)
	for _, cat := range cats {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !cat.IsDir() {
			continue
		}
		pkgs, perr := os.ReadDir(filepath.Join(base, cat.Name()))
		if perr != nil {
			continue
		}
		for _, p := range pkgs {
			if !p.IsDir() {
				continue
			}
			f, ferr := os.Open(filepath.Join(base, cat.Name(), p.Name(), "CONTENTS"))
			if ferr != nil {
				continue
			}
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			for sc.Scan() {
				fields := strings.Fields(sc.Text())
				if len(fields) < 4 || fields[0] != "obj" {
					continue
				}
				abs, md5 := fields[1], fields[2]
				if !strings.HasPrefix(abs, "/") || len(md5) != 32 {
					continue
				}
				if _, dup := out[abs]; !dup {
					out[abs] = md5
				}
			}
			f.Close()
		}
	}
	return out, nil
}

// trimLastTwoHyphenFields strips a trailing "-<version>-<release>" from a
// pacman local-db directory name (always shaped name-ver-rel), preserving
// hyphens inside the package name (e.g. linux-firmware-20240101-1 ->
// linux-firmware). Falls back to the input when it has fewer than 3 fields.
func trimLastTwoHyphenFields(s string) string {
	i := strings.LastIndexByte(s, '-')
	if i <= 0 {
		return s
	}
	j := strings.LastIndexByte(s[:i], '-')
	if j <= 0 {
		return s
	}
	return s[:j]
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

// buildRpmDigests spawns the per-file digest query and streams its
// "<path> <hexdigest>" lines into a path -> digest map. Same subprocess
// lifetime discipline as buildRpmMap (bounded WaitDelay, discarded
// stderr, drain-on-error). Lines with an empty digest field (dirs,
// symlinks, %ghost) are skipped.
func (r *Resolver) buildRpmDigests(ctx context.Context) (map[string]string, error) {
	argv := r.rpmDigestCommand
	if len(argv) == 0 {
		bin, ok := r.findRpmBinary()
		if !ok {
			return nil, errors.New("rpm binary not found at any candidate path")
		}
		argv = append([]string{bin}, rpmDigestQueryArgs...)
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.WaitDelay = 5 * time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("rpm digest stdout pipe: %w", err)
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("rpm digest start: %w", err)
	}

	out := make(map[string]string, 200_000)
	if err := scanRpmDigestStream(stdout, out); err != nil {
		_, _ = io.Copy(io.Discard, stdout)
		_ = cmd.Wait()
		return nil, fmt.Errorf("rpm digest stream: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("rpm digest wait: %w", err)
	}
	return out, nil
}

// scanRpmDigestStream parses "<path> <hexdigest> <verifyflags>" lines.
// The two trailing tokens are the verify flags and the digest (rpm paths
// do not contain spaces), so a two-step right split is unambiguous. A
// file is recorded only when its digest is a usable hex digest AND its
// FILEVERIFYFLAGS still has the digest-verify bit set -- mirroring
// `rpm -V`, which never reports files the package marked `%verify(not
// md5)` (e.g. setup's /etc/passwd). Non-absolute paths, empty/non-hex
// digests, and unparseable flags are skipped. First occurrence wins.
func scanRpmDigestStream(stream io.Reader, out map[string]string) error {
	sc := bufio.NewScanner(stream)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		i := strings.LastIndexByte(line, ' ')
		if i <= 0 {
			continue
		}
		flagsStr := line[i+1:]
		rest := line[:i]
		j := strings.LastIndexByte(rest, ' ')
		if j <= 0 {
			continue
		}
		path := rest[:j]
		digest := strings.ToLower(rest[j+1:])
		if !strings.HasPrefix(path, "/") || !isHexDigest(digest) {
			continue
		}
		flags, err := strconv.ParseInt(flagsStr, 10, 64)
		if err != nil || flags&rpmVerifyFileDigestBit == 0 {
			// Unparseable flags, or rpm itself does not digest-verify
			// this file -> do not flag it (matches `rpm -V`).
			continue
		}
		if _, dup := out[path]; !dup {
			out[path] = digest
		}
	}
	return sc.Err()
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
