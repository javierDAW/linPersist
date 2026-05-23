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
	raw, err := os.ReadFile(real)
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
	}
	fillFileMeta(&rec, info)
	rec.Signals = dedupSignals(m.baseSignals(info, logical))
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
		fillFileMeta(&rec, info)
		rec.Signals = dedupSignals(m.baseSignals(info, logical))
	}
	return rec
}

func fillFileMeta(rec *core.Record, info os.FileInfo) {
	size := info.Size()
	rec.Size = &size
	mt := info.ModTime().UTC()
	rec.MTime = &mt
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		uid := uint32(st.Uid)
		gid := uint32(st.Gid)
		rec.OwnerUID = &uid
		rec.OwnerGID = &gid
		rec.Mode = core.FormatMode(uint32(st.Mode) & 0o7777)
		atime := time.Unix(int64(st.Atim.Sec), int64(st.Atim.Nsec)).UTC()
		ctime := time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)).UTC()
		rec.ATime = &atime
		rec.CTime = &ctime
	} else {
		rec.Mode = core.FormatMode(uint32(info.Mode().Perm()))
	}
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
		}
		fillFileMeta(&rec, info)
		sigs := append([]string{}, base...)
		sigs = append(sigs, signalsForTrapHit(h)...)
		rec.Signals = dedupSignals(sigs)
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

func dedupSignals(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
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
