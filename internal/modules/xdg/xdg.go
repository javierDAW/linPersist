// Package xdg implements the linpersist collector for XDG autostart
// persistence on Linux.
//
// Site_class emitted:
//
//   - xdg.autostart   one record per .desktop file under
//     /etc/xdg/autostart/, /root/.config/autostart/, and
//     /home/<user>/.config/autostart/. The argv[0] of the Exec= line
//     is the persistence target; freedesktop.org field codes (%U,
//     %f, etc.) and surrounding double quotes are stripped.
//
// MITRE T1547.013 (Boot or Logon Autostart Execution: XDG
// Autostart Entries). The textbook pattern is dropping a .desktop
// under ~/.config/autostart/ with Exec= pointing at a payload under
// /tmp/, /opt/, or /home/<user>/.local/. Per-file granularity makes
// the implant a singleton under LFA.
package xdg

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

// MITRE ATT&CK technique applied to every record this module emits.
const mitreXDGAutostart = "T1547.013"

// systemAutostartDirs are the system-wide autostart directories. XDG
// merges entries from these into the session's startup list at login.
var systemAutostartDirs = []string{
	"/etc/xdg/autostart",
}

// homeAutostartParents is the parent under which per-user autostart
// directories appear as <username>/.config/autostart/.
const homeAutostartParents = "/home"

// rootAutostartDir is the per-user autostart directory for the root
// account. Linger / sudo sessions occasionally land here.
const rootAutostartDir = "/root/.config/autostart"

// DefaultMaxFileSize bounds a single .desktop file. Real entries are
// well under 8 KiB; 1 MiB is a generous safety net.
const DefaultMaxFileSize = 1 << 20

// Options configures the xdg module.
type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
	// Provenance annotates exec_target (argv[0] of Exec=) with its
	// owning package. Nil defaults to core.NoopProvenance.
	Provenance core.Provenance
	// LiveProcessSet membership check for the live_process_attached
	// signal. A .desktop pointing at a binary that is currently
	// running is by definition an active autostart hook.
	LiveProcessSet core.LiveProcessSet
}

// Module collects XDG autostart persistence sites.
type Module struct {
	opts Options
}

// New constructs an xdg Module. Zero-valued Options is valid.
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

// Compile-time interface conformance.
var _ core.Module = (*Module)(nil)

// Name returns the module identifier.
func (m *Module) Name() string { return "xdg" }

// SiteClasses returns the single site_class this module emits.
func (m *Module) SiteClasses() []string { return []string{"xdg.autostart"} }

// Collect walks every autostart locus and emits one record per
// .desktop file.
func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error
	for _, d := range systemAutostartDirs {
		if err := m.walkDir(ctx, d, emit); err != nil {
			errs = append(errs, err)
		}
	}
	if err := m.walkDir(ctx, rootAutostartDir, emit); err != nil {
		errs = append(errs, err)
	}
	if err := m.walkHomeUsers(ctx, homeAutostartParents, emit); err != nil {
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

// walkDir lists every *.desktop file under one autostart directory
// and emits a record per file. Non-.desktop entries and dotfiles are
// skipped per the FreeDesktop spec (only *.desktop is honored by the
// session-startup logic).
func (m *Module) walkDir(ctx context.Context, logicalDir string, emit func(core.Record)) error {
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
		if !strings.HasSuffix(name, ".desktop") {
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
		m.processFile(ctx, logical, real, info, emit)
	}
	return nil
}

// walkHomeUsers enumerates /home/<user>/.config/autostart/ for every
// user directory directly under /home. /root is handled separately so
// its discovery does not depend on /home being readable.
func (m *Module) walkHomeUsers(ctx context.Context, logicalHome string, emit func(core.Record)) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	realHome := m.resolve(logicalHome)
	entries, err := os.ReadDir(realHome)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("readdir %s: %w", logicalHome, err)
	}
	for _, e := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !e.IsDir() {
			continue
		}
		user := e.Name()
		if strings.HasPrefix(user, ".") {
			continue
		}
		logicalDir := filepath.Join(logicalHome, user, ".config", "autostart")
		if err := m.walkDir(ctx, logicalDir, emit); err != nil {
			// Per-home errors are non-fatal: one unreadable home does
			// not abort the rest of the walk.
			continue
		}
	}
	return nil
}

// processFile reads, parses, normalizes, hashes, and emits one
// record per .desktop file.
func (m *Module) processFile(ctx context.Context, logical, real string, info os.FileInfo, emit func(core.Record)) {
	if info.Size() > m.opts.MaxFileSize {
		emit(m.envelopeRecord(logical, info, []core.RecordError{
			{Field: "content_sha256", Code: "SIZE_LIMIT"},
		}))
		return
	}
	raw, err := core.ReadFileCapped(real, m.opts.MaxFileSize)
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
	pd := parseDesktop(raw)
	canon := canonical(pd)
	rec := m.baseRecord(logical, info)
	rec.ContentSHA256 = core.HashHex(raw)
	rec.ContentNormSHA256 = core.HashHex(canon)
	rec.ContentSnippet = snippet(string(canon))
	rec.FullExecLine = string(canon) // Tier-B behavioral scan over the autostart Exec= line
	if exec := extractExec(pd); exec != "" {
		rec.ExecTarget = exec
		if strings.HasPrefix(exec, "/") {
			if sum, ok := core.HashFileCapped(m.resolve(exec), m.opts.MaxFileSize); ok {
				rec.ExecTargetSHA256 = sum
			}
		}
		if !strings.HasPrefix(exec, "/") {
			rec.Signals = appendUnique(rec.Signals, core.SignalUnqualifiedExecTarget)
		}
		rec.Signals = append(rec.Signals, m.execTargetSignals(exec)...)
		if m.targetMtimeRecent(exec) {
			rec.Signals = appendUnique(rec.Signals, core.SignalRecentTargetMtime7d)
		}
	}
	rec.Signals = core.DedupSignalsSorted(rec.Signals)
	core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
	core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
	emit(rec)
}

func (m *Module) baseRecord(logical string, info os.FileInfo) core.Record {
	rec := core.Record{
		Module:    m.Name(),
		SiteClass: "xdg.autostart",
		MITRE:     []string{mitreXDGAutostart},
		Locus:     logical,
	}
	core.FillFileMeta(&rec, info)
	rec.Signals = m.baseSignals(info, logical)
	return rec
}

func (m *Module) envelopeRecord(logical string, info os.FileInfo, errs []core.RecordError) core.Record {
	rec := m.baseRecord(logical, info)
	rec.Errors = errs
	return rec
}

// baseSignals returns the per-file file-level signals: recent_mtime_*,
// world_writable, non_root_owner.
func (m *Module) baseSignals(info os.FileInfo, logical string) []string {
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
		// Non-root-owner applies to system paths only. /home/* and
		// /root/.config/* are expected to be non-root in many cases
		// (the home is the user's, not root's).
		if st.Uid != 0 && isSystemAutostartPath(logical) {
			out = append(out, core.SignalNonRootOwner)
		}
	}
	return out
}

// execTargetSignals derives signals that depend on the exec_target
// path: interpreter_in_tmp, shell_indirect, exec_target_orphan.
func (m *Module) execTargetSignals(target string) []string {
	var out []string
	if isInterpreterInTmp(target) {
		out = append(out, core.SignalInterpreterInTmp)
	}
	base := filepath.Base(target)
	if _, ok := shellInterps[base]; ok {
		out = append(out, core.SignalShellIndirect)
	}
	if !m.targetExists(target) {
		out = append(out, core.SignalExecTargetOrphan)
	}
	return out
}

// targetExists returns true iff the resolved target path is a
// regular-file-equivalent existing on disk. Bound checks (size cap,
// permission errors) are not relevant here: the question is solely
// "does this path resolve to anything?".
func (m *Module) targetExists(target string) bool {
	if target == "" {
		return false
	}
	if _, err := os.Stat(m.resolve(target)); err != nil {
		return false
	}
	return true
}

// targetMtimeRecent returns true if exec_target exists and its mtime
// is within 7 days of m.opts.Now(). Cheap because the stat is shared
// with targetExists in real call paths (this is one extra syscall
// per record, acceptable).
func (m *Module) targetMtimeRecent(target string) bool {
	if target == "" {
		return false
	}
	info, err := os.Stat(m.resolve(target))
	if err != nil {
		return false
	}
	delta := m.opts.Now().Sub(info.ModTime().UTC())
	return delta >= 0 && delta < 7*24*time.Hour
}

// shellInterps mirrors the cron / ldso / ssh convention for the
// shell_indirect signal. Kept private to this package; will move to
// core when a fifth module needs the same constant.
var shellInterps = map[string]struct{}{
	"bash":    {},
	"sh":      {},
	"dash":    {},
	"zsh":     {},
	"ash":     {},
	"python":  {},
	"python3": {},
	"perl":    {},
	"ruby":    {},
	"php":     {},
	"node":    {},
}

func isInterpreterInTmp(target string) bool {
	for _, p := range core.TmpDirs {
		if strings.HasPrefix(target, p) {
			return true
		}
	}
	return false
}

// isSystemAutostartPath reports whether logical resolves under any of
// the systemAutostartDirs. Used to gate the non_root_owner signal so
// per-user homes don't fire it for files the user legitimately owns.
func isSystemAutostartPath(logical string) bool {
	for _, d := range systemAutostartDirs {
		if strings.HasPrefix(logical, d+"/") || logical == d {
			return true
		}
	}
	return false
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
