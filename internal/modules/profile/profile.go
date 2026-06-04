// Package profile implements the linpersist collector for shell-init
// persistence on Linux.
//
// Site_classes emitted:
//
//   - profile.system  system-wide shell init:
//     /etc/profile, /etc/profile.d/*,
//     /etc/bash.bashrc, /etc/zsh/zshenv,
//     /etc/zsh/zprofile, /etc/environment
//   - profile.user    per-user shell init:
//     /root/.{bashrc,bash_profile,bash_login,
//     profile,zshrc,zshenv}
//     /home/<user>/.{bashrc,bash_profile,bash_login,
//     profile,zshrc,zshenv}
//
// Per-file record granularity (pattern from cron.periodic). MITRE
// T1546.004 (Event Triggered Execution: Unix Shell Configuration
// Modification).
package profile

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
	mitreProfile = "T1546.004"
	mitreTrap    = "T1546.005"

	siteClassProfileSystem = "profile.system"
	siteClassProfileUser   = "profile.user"
	siteClassTrapSystem    = "profile.trap.system"
	siteClassTrapUser      = "profile.trap.user"
)

// systemFiles is the fixed set of system-wide profile loci. The
// /etc/profile.d/ directory is handled separately by the walker.
var systemFiles = []string{
	"/etc/profile",
	"/etc/bash.bashrc",
	"/etc/zsh/zshenv",
	"/etc/zsh/zprofile",
	"/etc/environment",
}

// userProfileNames is the set of per-user shell-init filenames the
// walker probes inside each home directory (and /root/).
var userProfileNames = []string{
	".bashrc",
	".bash_profile",
	".bash_login",
	".profile",
	".zshrc",
	".zshenv",
}

type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
	// Provenance is wired uniformly across modules. profile uses
	// per-file granularity and does not populate ExecTarget, so the
	// resolver is effectively unused here, but the field is present
	// for API symmetry.
	Provenance core.Provenance
	// LiveProcessSet, also unused for profile (no ExecTarget) but
	// present for API symmetry.
	LiveProcessSet core.LiveProcessSet
}

const DefaultMaxFileSize = 1 << 20

type Module struct {
	opts Options
}

func New(opts Options) *Module {
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = DefaultMaxFileSize
	}
	if opts.Provenance == nil {
		opts.Provenance = core.NoopProvenance{}
	}
	if opts.LiveProcessSet == nil {
		opts.LiveProcessSet = core.NoopLiveProcessSet{}
	}
	return &Module{opts: opts}
}

var _ core.Module = (*Module)(nil)

func (m *Module) Name() string { return "profile" }

func (m *Module) SiteClasses() []string {
	return []string{
		siteClassProfileSystem,
		siteClassProfileUser,
		siteClassTrapSystem,
		siteClassTrapUser,
	}
}

func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error

	// System-wide files at fixed paths.
	for _, logical := range systemFiles {
		if err := m.collectFile(ctx, logical, "profile.system", emit); err != nil {
			errs = append(errs, err)
		}
	}
	// /etc/profile.d/*.sh drop-ins.
	if err := m.collectProfileDir(ctx, "/etc/profile.d", emit); err != nil {
		errs = append(errs, err)
	}
	// /root/.<file> for each candidate filename.
	for _, name := range userProfileNames {
		logical := filepath.Join("/root", name)
		if err := m.collectFile(ctx, logical, "profile.user", emit); err != nil {
			errs = append(errs, err)
		}
	}
	// /home/<user>/.<file> for each user.
	if err := m.collectHomeUsers(ctx, "/home", emit); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func (m *Module) resolve(logical string) string {
	if m.opts.Root == "" {
		return logical
	}
	return filepath.Join(m.opts.Root, logical)
}

func (m *Module) collectFile(ctx context.Context, logical, siteClass string, emit func(core.Record)) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	real := m.resolve(logical)
	info, err := os.Lstat(real)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("lstat %s: %w", logical, err)
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	m.processFile(ctx, logical, real, info, siteClass, emit)
	return nil
}

func (m *Module) collectProfileDir(ctx context.Context, logicalDir string, emit func(core.Record)) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	realDir := m.resolve(logicalDir)
	entries, err := os.ReadDir(realDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("readdir %s: %w", logicalDir, err)
	}
	for _, e := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		name := e.Name()
		if skipDirEntry(name) {
			continue
		}
		// /etc/profile only sources *.sh files from the .d directory.
		if !strings.HasSuffix(name, ".sh") {
			continue
		}
		logical := filepath.Join(logicalDir, name)
		real := filepath.Join(realDir, name)
		info, err := os.Lstat(real)
		if err != nil {
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		m.processFile(ctx, logical, real, info, "profile.system", emit)
	}
	return nil
}

// collectHomeUsers enumerates /home/, and for each subdir probes the
// six candidate per-user profile filenames.
func (m *Module) collectHomeUsers(ctx context.Context, logicalDir string, emit func(core.Record)) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	realDir := m.resolve(logicalDir)
	entries, err := os.ReadDir(realDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("readdir %s: %w", logicalDir, err)
	}
	for _, e := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !e.IsDir() {
			continue
		}
		for _, name := range userProfileNames {
			logical := filepath.Join(logicalDir, e.Name(), name)
			if err := m.collectFile(ctx, logical, "profile.user", emit); err != nil {
				_ = err
			}
		}
	}
	return nil
}

func (m *Module) processFile(ctx context.Context, logical, real string, info os.FileInfo, siteClass string, emit func(core.Record)) {
	if info.Size() > m.opts.MaxFileSize {
		emit(m.envelopeRecord(logical, info, siteClass, []core.RecordError{
			{Field: "content_sha256", Code: "SIZE_LIMIT"},
		}))
		return
	}
	raw, err := core.ReadFileCapped(real, m.opts.MaxFileSize)
	if err != nil {
		emit(m.envelopeRecord(logical, info, siteClass, []core.RecordError{
			{Field: "content_sha256", Code: errnoCode(err), Msg: err.Error()},
		}))
		return
	}
	if len(raw) == 0 {
		return
	}
	canon := Normalize(raw)
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         siteClass,
		MITRE:             []string{mitreProfile},
		Locus:             logical,
		ContentSHA256:     core.HashHex(raw),
		ContentNormSHA256: core.HashHex(canon),
		ContentSnippet:    snippet(string(canon)),
		FullExecLine:      string(canon), // Tier-B behavioral scan over the full body
	}
	core.FillFileMeta(&rec, info)
	// Pull the first explicit exec target out of the script body so
	// Q12 (campaign basename clustering) can consolidate this record
	// with sibling cron / systemd records that target the same payload.
	// Without this, a worm whose three arms all source the same
	// /usr/local/bin/sync split into two Q12 rows because the profile
	// arm carried no ExecTarget. See v0.4.0 sprint task #14.
	var execTargetSigs []string
	// A BASH_ENV=/ENV= per-shell source hook takes precedence over a
	// plain source/exec line: it is the higher-signal persistence shape
	// (runs on EVERY non-interactive shell, not just login) and is the
	// primary reason /etc/environment is in scope. ExtractExecTarget
	// returns "" on /etc/environment (KEY=value content, no source/exec
	// lead) so on that locus only this branch can populate ExecTarget.
	if hook := core.ExtractEnvHookTarget(raw); hook != "" {
		rec.ExecTarget = hook
		execTargetSigs = append([]string{core.SignalEnvHookSet}, m.execTargetStatSignals(hook)...)
		if sum, ok := core.HashFileCapped(m.resolve(hook), m.opts.MaxFileSize); ok {
			rec.ExecTargetSHA256 = sum
		}
	} else if target := core.ExtractExecTarget(raw); target != "" {
		rec.ExecTarget = target
		execTargetSigs = m.execTargetStatSignals(target)
		// Hash the payload so Q6 can stack a worm that drops the same
		// non-package binary across hosts. Without this the profile arm
		// carried no exec_target_sha256 and Q6 was structurally blind to
		// profile-based worms. Hash the ROOT-RESOLVED path so a --root
		// (mounted-image/chroot) collection hashes the image's binary,
		// not the analyst host's.
		if sum, ok := core.HashFileCapped(m.resolve(target), m.opts.MaxFileSize); ok {
			rec.ExecTargetSHA256 = sum
		}
	}
	rec.Signals = core.DedupSignals(append(m.baseSignals(info, logical), execTargetSigs...))
	if rec.ExecTarget != "" {
		// Annotate AFTER finalizing rec.Signals. These helpers APPEND to
		// rec.Signals; the previous order called them first and then
		// rebuilt rec.Signals here, silently dropping non_package_path
		// and live_process_attached (the latter is why a profile-arm worm
		// never carried the provenance signal Q6's filter needs).
		core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
		core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
		rec.Signals = core.DedupSignals(rec.Signals)
	}
	emit(rec)

	// Walk the raw content for `trap CMD SIGNAL...` directives. Each
	// real trap (non-noop) emits its own record with site_class
	// profile.trap.{system,user} and MITRE T1546.005.
	m.emitTrapsFromContent(logical, raw, info, siteClass, emit)
}

func (m *Module) envelopeRecord(logical string, info os.FileInfo, siteClass string, errs []core.RecordError) core.Record {
	rec := core.Record{
		Module:    m.Name(),
		SiteClass: siteClass,
		MITRE:     []string{mitreProfile},
		Locus:     logical,
		Errors:    errs,
	}
	if info != nil {
		core.FillFileMeta(&rec, info)
		rec.Signals = core.DedupSignals(m.baseSignals(info, logical))
	}
	return rec
}

// emitTrapsFromContent scans the file for `trap CMD SIGNAL...` lines
// and emits one Record per real trap hit. The site_class is derived
// from the parent siteClass: profile.system -> profile.trap.system,
// profile.user -> profile.trap.user. The base file-level signals
// (recent_mtime_*, world_writable, non_root_owner) are reused so a
// trap inside a freshly-written /etc/profile.d/ dropin carries
// recent_mtime_7d the same way the per-file record does.
func (m *Module) emitTrapsFromContent(logical string, raw []byte, info os.FileInfo, parentSiteClass string, emit func(core.Record)) {
	hits := scanTraps(raw)
	if len(hits) == 0 {
		return
	}
	var trapSiteClass string
	switch parentSiteClass {
	case siteClassProfileSystem:
		trapSiteClass = siteClassTrapSystem
	case siteClassProfileUser:
		trapSiteClass = siteClassTrapUser
	default:
		// Unknown parent site_class -- skip rather than guess.
		return
	}
	base := m.baseSignals(info, logical)
	for _, h := range hits {
		rec := core.Record{
			Module:            m.Name(),
			SiteClass:         trapSiteClass,
			MITRE:             []string{mitreTrap},
			Locus:             logical,
			ContentSHA256:     core.HashHex([]byte(h.raw)),
			ContentNormSHA256: core.HashHex([]byte(h.raw)),
			ContentSnippet:    h.raw,
		}
		if et := execTargetFromTrap(h); et != "" {
			rec.ExecTarget = et
			// Hash the payload so a trap worm arm stacks in Q6 alongside
			// its cron/systemd siblings. The profile.system path was
			// fixed earlier but this trap path still left ExecTargetSHA256
			// empty, so trap arms were invisible to Q6 (stats.go skips
			// records with no exec_target hash). Root-resolved so --root
			// collections hash the image's binary, not the host's.
			if sum, ok := core.HashFileCapped(m.resolve(et), m.opts.MaxFileSize); ok {
				rec.ExecTargetSHA256 = sum
			}
		}
		core.FillFileMeta(&rec, info)
		sigs := append([]string{}, base...)
		sigs = append(sigs, signalsForTrapHit(h)...)
		rec.Signals = core.DedupSignals(sigs)
		if rec.ExecTarget != "" {
			// Annotate AFTER finalizing rec.Signals (these helpers append);
			// supplies non_package_path, which Q6's non-package filter
			// needs to include the stacked trap payload.
			core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
			core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
			rec.Signals = core.DedupSignals(rec.Signals)
		}
		emit(rec)
	}
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

// execTargetStatSignals emits stat-derived signals for a populated
// ExecTarget: exec_target_orphan when the target is missing,
// recent_target_mtime_7d when the target's mtime is fresh. Mirrors
// the per-module helper cron/systemd/kmod/etc already carry — the
// profile module needs the same emissions for Q12 worm-arm clustering
// to fire on the profile arm of a three-arm worm.
func (m *Module) execTargetStatSignals(target string) []string {
	var out []string
	// A target living under a tmp-class path is the textbook dropped-
	// payload shape; emit interpreter_in_tmp uniformly with every other
	// module so payload_under_tmp_via_persistence (and the env-hook /
	// trap rules) can consume it. Judged on the literal path, not the
	// stat result, so it fires even when the target is absent.
	for _, prefix := range core.TmpDirs {
		if strings.HasPrefix(target, prefix) {
			out = append(out, core.SignalInterpreterInTmp)
			break
		}
	}
	// Root-resolved so orphan / recent-mtime are judged against the
	// collected image under --root, not the analyst host.
	info, err := os.Stat(m.resolve(target))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		out = append(out, core.SignalExecTargetOrphan)
	case err == nil:
		delta := m.opts.Now().Sub(info.ModTime().UTC())
		if delta >= 0 && delta < 7*24*time.Hour {
			out = append(out, core.SignalRecentTargetMtime7d)
		}
	}
	return out
}

func isSystemPath(p string) bool {
	for _, prefix := range []string{"/etc/", "/usr/", "/lib/", "/bin/", "/sbin/"} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

func skipDirEntry(name string) bool {
	if strings.HasPrefix(name, ".") {
		return true
	}
	if strings.HasSuffix(name, "~") {
		return true
	}
	for _, frag := range []string{".dpkg-", ".rpmsave", ".rpmnew", ".bak"} {
		if strings.Contains(name, frag) {
			return true
		}
	}
	return false
}

func snippet(s string) string {
	const max = 256
	if len(s) <= max {
		return s
	}
	return s[:max]
}
func errnoCode(err error) string {
	if errors.Is(err, fs.ErrNotExist) {
		return "ENOENT"
	}
	if errors.Is(err, fs.ErrPermission) {
		return "EACCES"
	}
	return "IO_ERROR"
}
