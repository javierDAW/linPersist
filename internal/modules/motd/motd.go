// Package motd implements the linpersist collector for motd (message
// of the day) persistence on Linux.
//
// Site_class emitted:
//
//   - motd   /etc/motd, /etc/motd.d/*, /etc/update-motd.d/*. The
//     update-motd.d directory holds executable scripts that pam_motd
//     invokes at login; modifying or adding a script there is a
//     well-documented persistence vector (DFIR Report, PANIX). The
//     plain-text files are typically just banner content but an
//     attacker who can write them has already achieved a foothold
//     and could leave breadcrumbs.
//
// MITRE T1037 is used as the closest match -- the parent technique
// "Boot or Logon Initialization Scripts". MITRE ATT&CK does not (as
// of May 2026) carry a sub-technique specific to motd-via-PAM. We
// document the gap in matrix.yaml rather than mis-classify under an
// unrelated sub-technique.
package motd

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

const mitreMotd = "T1037"

// staticMotdFiles are plain-text banner files. Canonical form: only
// strip trailing whitespace + blank lines. '#' is NOT a comment in
// motd text and stripping a leading '#' line would erase banner
// content.
var staticMotdFiles = []string{
	"/etc/motd",
}

// motdDropinDir holds drop-in plain-text files (uncommon but
// supported on recent Debian/Ubuntu).
const motdDropinDir = "/etc/motd.d"

// updateMotdDir holds executable shell scripts that generate the
// dynamic motd at login. pam_motd.so invokes them; modifying one is
// the canonical persistence vector this module is built to surface.
const updateMotdDir = "/etc/update-motd.d"

// Options configures the motd module.
type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
	// Provenance annotates exec_target (set on update-motd.d scripts)
	// with its owning package. Nil defaults to core.NoopProvenance.
	Provenance core.Provenance
	// LiveProcessSet membership check for the live_process_attached
	// signal.
	LiveProcessSet core.LiveProcessSet
}

// DefaultMaxFileSize bounds a single banner or script.
const DefaultMaxFileSize = 1 << 20

// Module collects motd persistence sites.
type Module struct {
	opts Options
}

// New constructs a motd Module. Zero-valued Options is valid.
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

// Name returns the module identifier.
func (m *Module) Name() string { return "motd" }

// SiteClasses returns the single site_class this module emits.
func (m *Module) SiteClasses() []string { return []string{"motd"} }

// Collect walks every motd locus.
func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error
	for _, p := range staticMotdFiles {
		if err := m.collectStaticFile(ctx, p, emit); err != nil {
			errs = append(errs, err)
		}
	}
	if err := m.walkDir(ctx, motdDropinDir, false, emit); err != nil {
		errs = append(errs, err)
	}
	if err := m.walkDir(ctx, updateMotdDir, true, emit); err != nil {
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

// collectStaticFile handles a single fixed-path plain-text motd file.
func (m *Module) collectStaticFile(ctx context.Context, logical string, emit func(core.Record)) error {
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
	m.processFile(ctx, logical, real, info, false, emit)
	return nil
}

// walkDir walks one of the motd drop-in directories. isShell selects
// the canonical-form rules (shell-style for update-motd.d, plain-text
// for motd.d).
func (m *Module) walkDir(ctx context.Context, logicalDir string, isShell bool, emit func(core.Record)) error {
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
		if skipName(name) {
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
		m.processFile(ctx, logical, real, info, isShell, emit)
	}
	return nil
}

// processFile reads, normalizes, hashes, and emits one record.
func (m *Module) processFile(ctx context.Context, logical, real string, info os.FileInfo, isShell bool, emit func(core.Record)) {
	if info.Size() > m.opts.MaxFileSize {
		emit(m.envelopeRecord(logical, info, []core.RecordError{
			{Field: "content_sha256", Code: "SIZE_LIMIT"},
		}))
		return
	}
	raw, err := os.ReadFile(real)
	if err != nil {
		emit(m.envelopeRecord(logical, info, []core.RecordError{
			{Field: "content_sha256", Code: errnoCode(err), Msg: err.Error()},
		}))
		return
	}
	if len(raw) == 0 {
		rec := m.baseRecord(logical, info)
		rec.Signals = appendUnique(rec.Signals, core.SignalEmptyFile)
		emit(rec)
		return
	}
	var canon []byte
	if isShell {
		canon = NormalizeShell(raw)
	} else {
		canon = NormalizeText(raw)
	}
	rec := m.baseRecord(logical, info)
	rec.ContentSHA256 = core.HashHex(raw)
	rec.ContentNormSHA256 = core.HashHex(canon)
	rec.ContentSnippet = snippet(string(canon))
	if isShell {
		// update-motd.d scripts are invoked by pam_motd at login;
		// the script IS the persistence target. Surface it the same
		// way cron.periodic does.
		rec.ExecTarget = logical
		rec.ExecTargetSHA256 = rec.ContentSHA256
	}
	core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
	core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
	emit(rec)
}

func (m *Module) baseRecord(logical string, info os.FileInfo) core.Record {
	rec := core.Record{
		Module:    m.Name(),
		SiteClass: "motd",
		MITRE:     []string{mitreMotd},
		Locus:     logical,
	}
	fillFileMeta(&rec, info)
	rec.Signals = m.baseSignals(info)
	return rec
}

func (m *Module) envelopeRecord(logical string, info os.FileInfo, errs []core.RecordError) core.Record {
	rec := m.baseRecord(logical, info)
	rec.Errors = errs
	return rec
}

func (m *Module) baseSignals(info os.FileInfo) []string {
	var out []string
	now := m.opts.Now()
	mt := info.ModTime().UTC()
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
		if st.Uid != 0 {
			out = append(out, core.SignalNonRootOwner)
		}
	}
	return out
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

func skipName(name string) bool {
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
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "ENOENT"
	case errors.Is(err, fs.ErrPermission):
		return "EACCES"
	default:
		return "IO_ERROR"
	}
}

func appendUnique(sigs []string, name string) []string {
	for _, s := range sigs {
		if s == name {
			return sigs
		}
	}
	return append(sigs, name)
}
