// Package suidbits implements the linpersist collector for setuid /
// setgid binary persistence on Linux.
//
// Site_classes emitted (one record per binary):
//
//   - suid.system   regular file with mode & 04000 under /usr/bin,
//     /usr/sbin, /usr/local/bin, /usr/local/sbin, or /opt
//   - sgid.system   same set of roots with mode & 02000 and no suid bit
//   - suid.user     suid bit set under /tmp, /var/tmp, or /home
//   - sgid.user     sgid bit set under the same user roots without suid
//
// A binary with BOTH bits set lands in the suid.* class (suid wins) but
// both signals fire so the analyst sees the full picture in Q5 / Q7.
//
// MITRE T1548.001 (Abuse Elevation Control Mechanism: Setuid and
// Setgid). The textbook attacker pattern is:
//
//	cp /bin/bash /tmp/.x && chown root:root /tmp/.x && chmod u+s /tmp/.x
//
// from a low-priv shell, leaving a persistent root pivot. The module
// reports every suid/sgid binary it finds; the provenance helper marks
// package-managed binaries (passwd, sudo, mount, ...) as
// pkg_status=managed and the implant under /tmp/ surfaces in Q11 with
// the non_package_path + suid_bit_set signal pair.
//
// Performance: the agent walks at most ~10 roots per host with
// Lstat-only (no file content read for stacking), so a default invocation
// touches at most a few thousand files in <100 ms on a representative
// Ubuntu host. The optional content_sha256 read is bounded by
// MaxContentReadBytes (16 MiB) so a runaway giant binary cannot dominate
// the run.
package suidbits

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

const (
	mitreSetuid = "T1548.001"

	// DefaultMaxContentReadBytes bounds the content_sha256 streaming
	// read. Real suid binaries are well under 1 MiB; 16 MiB is the
	// safety net so a 4 GiB curiosity does not dominate the agent's
	// wall-clock.
	DefaultMaxContentReadBytes int64 = 16 * 1024 * 1024
)

// DefaultRoots is the set of filesystem subtrees walked when
// Options.Roots is nil. The four /usr* roots and /opt are typical
// system-side suid loci; /tmp, /var/tmp and /home cover the
// implant-side patterns documented in MITRE T1548.001 examples
// (cp /bin/bash /tmp/.x; chmod u+s /tmp/.x).
//
// Order is load-bearing for deterministic NDJSON emission across hosts:
// when two roots overlap (rare) the earlier one wins.
var DefaultRoots = []string{
	"/usr/bin",
	"/usr/sbin",
	"/usr/local/bin",
	"/usr/local/sbin",
	"/opt",
	"/home",
	"/tmp",
	"/var/tmp",
}

// skipDirs is the set of pseudo-filesystem prefixes the walker must
// never descend into. They never contain real persistence and walking
// /proc recursively can hang on circular symlinks.
var skipDirs = map[string]struct{}{
	"/proc": {},
	"/sys":  {},
	"/dev":  {},
	"/run":  {},
}

// systemRootPrefixes determines the suid.system vs suid.user split.
// A locus that does NOT start with any of these prefixes is classified
// as a user-side suid (implant territory) regardless of which root it
// was discovered under.
var systemRootPrefixes = []string{
	"/usr/bin/", "/usr/sbin/",
	"/usr/local/bin/", "/usr/local/sbin/",
	"/opt/",
}

// Options configures a suidbits Module.
type Options struct {
	// Root is the WSL/test-harness root that prefixes every walk path.
	// Empty means "real filesystem".
	Root string
	// Roots overrides DefaultRoots when non-nil. Useful in tests to
	// scope the walk to a single tempdir.
	Roots []string
	// Now overrides time.Now for the recent_mtime_* signals.
	Now func() time.Time
	// MaxContentReadBytes caps the per-file content_sha256 streaming
	// read. Files larger than this still emit a record (with
	// SIZE_LIMIT in errors) but no content_sha256.
	MaxContentReadBytes int64
	// Provenance annotates exec_target (== locus for suid binaries).
	// Nil defaults to core.NoopProvenance. Strongly recommended to
	// supply a real resolver — without it every suid binary will
	// report pkg_status=Unknown and the module loses its primary
	// signal-to-noise lever.
	Provenance core.Provenance
	// LiveProcessSet checks whether the suid binary is currently
	// running. A suid binary that is BOTH non-package-managed AND has
	// a live process attached is the highest-confidence implant
	// shape the module surfaces.
	LiveProcessSet core.LiveProcessSet
}

// Module collects suid/sgid binary persistence sites.
type Module struct{ opts Options }

// New constructs a suidbits Module with default fallbacks.
func New(opts Options) *Module {
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	if opts.MaxContentReadBytes <= 0 {
		opts.MaxContentReadBytes = DefaultMaxContentReadBytes
	}
	if opts.Provenance == nil {
		opts.Provenance = core.NoopProvenance{}
	}
	if opts.LiveProcessSet == nil {
		opts.LiveProcessSet = core.NoopLiveProcessSet{}
	}
	return &Module{opts: opts}
}

// Compile-time interface conformance.
var _ core.Module = (*Module)(nil)

// Name returns the module identifier.
func (m *Module) Name() string { return "suidbits" }

// SiteClasses returns the four classes this module emits.
func (m *Module) SiteClasses() []string {
	return []string{"suid.system", "sgid.system", "suid.user", "sgid.user"}
}

// Collect walks every configured root and emits one record per
// suid/sgid binary discovered. Per-root errors are joined and
// returned; one unreadable root never aborts the others.
func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	roots := m.opts.Roots
	if roots == nil {
		roots = DefaultRoots
	}
	var errs []error
	for _, root := range roots {
		if err := m.walkRoot(ctx, root, emit); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (m *Module) resolve(logical string) string {
	if m.opts.Root == "" {
		return logical
	}
	return filepath.Join(m.opts.Root, logical)
}

// walkRoot is the per-root walker. It uses filepath.WalkDir for stable
// ordering and to keep the stat call count bounded (WalkDir hands us
// the DirEntry; we only Lstat regular files that have a non-zero mode
// after the cheap entry filter).
func (m *Module) walkRoot(ctx context.Context, logicalRoot string, emit func(core.Record)) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	realRoot := m.resolve(logicalRoot)
	if _, err := os.Lstat(realRoot); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("lstat %s: %w", logicalRoot, err)
	}
	return filepath.WalkDir(realRoot, func(realPath string, d fs.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if walkErr != nil {
			// Skip unreadable subdirs instead of aborting the walk:
			// a single EACCES on /home/<other-user> is normal and
			// should not deny the rest of the root.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		logicalPath := m.logicalize(realPath)
		if d.IsDir() {
			if _, skip := skipDirs[logicalPath]; skip {
				return fs.SkipDir
			}
			return nil
		}
		// Only regular files can carry meaningful suid/sgid semantics.
		// Symlinks have their own mode bits but the kernel honors the
		// target's bits, so flagging a symlink would be a false
		// positive. Use Lstat (not Stat) so we never follow.
		info, err := os.Lstat(realPath)
		if err != nil {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		mode := st.Mode & 0o7777
		isSuid := mode&0o4000 != 0
		isSgid := mode&0o2000 != 0
		if !isSuid && !isSgid {
			return nil
		}
		emit(m.record(logicalPath, realPath, info, isSuid, isSgid))
		return nil
	})
}

// logicalize converts a real (rooted) path back to the logical path
// callers expect to see in NDJSON. When Options.Root is empty this is
// a no-op.
func (m *Module) logicalize(realPath string) string {
	if m.opts.Root == "" {
		return realPath
	}
	if !strings.HasPrefix(realPath, m.opts.Root) {
		return realPath
	}
	rel := strings.TrimPrefix(realPath, m.opts.Root)
	if rel == "" {
		return "/"
	}
	if !strings.HasPrefix(rel, "/") {
		return "/" + rel
	}
	return rel
}

// record builds the core.Record for a single suid/sgid file. The
// content_norm_sha256 stacking key is mode_octal:basename so two hosts
// carrying the same canonical suid binary (e.g. /usr/bin/passwd mode
// 4755) collapse to one Q1/Q4 group, while an attacker dropping
// /tmp/.x mode 4755 produces a unique norm by virtue of the basename.
// content_sha256 is the real file hash via core.HashReader, capped at
// MaxContentReadBytes; this lets Q6 (exec_target_sha256 stacking) cross
// hosts surface a single dropped payload across the fleet.
func (m *Module) record(logical, realPath string, info os.FileInfo, isSuid, isSgid bool) core.Record {
	siteClass := classify(logical, isSuid)
	mode := uint32(info.Mode().Perm())
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		mode = uint32(st.Mode) & 0o7777
	}
	base := filepath.Base(logical)
	canon := fmt.Sprintf("%04o:%s", mode, base)
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         siteClass,
		MITRE:             []string{mitreSetuid},
		Locus:             logical,
		ContentNormSHA256: core.HashHexString(canon),
		ContentSnippet:    canon,
		ExecTarget:        logical,
	}
	core.FillFileMeta(&rec, info)
	if hash, ok := m.hashFile(realPath, info.Size()); ok {
		rec.ContentSHA256 = hash
		rec.ExecTargetSHA256 = hash
	} else {
		rec.Errors = append(rec.Errors, core.RecordError{
			Field: "content_sha256", Code: "SIZE_LIMIT",
		})
	}
	signals := m.baseSignals(info, logical)
	if isSuid {
		signals = append(signals, core.SignalSuidBitSet)
	}
	if isSgid {
		signals = append(signals, core.SignalSgidBitSet)
	}
	rec.Signals = core.DedupSignals(signals)
	core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
	core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
	return rec
}

// classify picks the site_class. The system/user split is by logical
// path prefix, not by which root was being walked when the file was
// found, so a /home/eve binary discovered via a recursive walk of /
// (uncommon but possible in tests) still lands in suid.user.
func classify(logical string, isSuid bool) string {
	system := false
	for _, p := range systemRootPrefixes {
		if strings.HasPrefix(logical, p) {
			system = true
			break
		}
	}
	switch {
	case isSuid && system:
		return "suid.system"
	case isSuid && !system:
		return "suid.user"
	case system:
		return "sgid.system"
	default:
		return "sgid.user"
	}
}

// hashFile streams the file's sha256 if it is under the configured
// size cap. Returns ("", false) on any error or when the file exceeds
// MaxContentReadBytes so the caller can emit a SIZE_LIMIT envelope.
func (m *Module) hashFile(realPath string, size int64) (string, bool) {
	if size > m.opts.MaxContentReadBytes {
		return "", false
	}
	f, err := os.Open(realPath)
	if err != nil {
		return "", false
	}
	defer f.Close()
	h, _, err := core.HashReader(f)
	if err != nil {
		return "", false
	}
	return h, true
}

func (m *Module) baseSignals(info os.FileInfo, logical string) []string {
	var out []string
	mt := info.ModTime().UTC()
	now := m.opts.Now()
	delta := now.Sub(mt)
	switch {
	case delta >= 0 && delta < 7*24*time.Hour:
		out = append(out, core.SignalRecentMtime7d)
	case delta >= 7*24*time.Hour && delta < 30*24*time.Hour:
		out = append(out, core.SignalRecentMtime30d)
	}
	if info.Mode().Perm()&0o002 != 0 {
		out = append(out, core.SignalWorldWritable)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		if st.Uid != 0 && isSystemPath(logical) {
			out = append(out, core.SignalNonRootOwner)
		}
	}
	return out
}

// isSystemPath returns true when a non-root owner is anomalous. Suid
// binaries under /home/<user>/ legitimately have the owner equal to
// <user>; suid binaries under /usr/bin owned by a non-root uid are
// the high-confidence implant case.
func isSystemPath(p string) bool {
	for _, prefix := range []string{"/usr/", "/opt/"} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}
