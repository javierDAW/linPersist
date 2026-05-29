// Package grub implements the linpersist collector for GRUB
// bootloader persistence on Linux.
//
// Site_classes emitted:
//
//   - kernel.grub.config   per-line records from /etc/default/grub.
//     Each non-comment, non-blank line becomes a record. The
//     KEY=VALUE shape lets the backend stack on individual
//     assignments; the high-precision signal is
//     `grub_cmdline_init` set when a GRUB_CMDLINE_LINUX* value
//     contains `init=<path>` (the kernel honors the token as a
//     pid-1 override, the textbook "swap the system init for an
//     attacker binary at next boot" pattern).
//   - kernel.grub.dropin   per-file records from /etc/grub.d/*.
//     Each script is invoked by grub-mkconfig at grub.cfg
//     regeneration time; dropping a hostile script here yields
//     both write-time code execution AND a custom boot entry that
//     runs payload at the next boot.
//
// MITRE T1542.003 (Pre-OS Boot: Bootkit). The pattern is the
// closest match in ATT&CK; cmdline-injection without a real
// bootloader implant is technically a sub-case of T1547 (Boot or
// Logon Autostart Execution) but T1542.003 is the broader
// pre-OS-tampering family the community uses for this technique.
package grub

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

const (
	mitreGrubConfig = "T1542.003"
	mitreGrubDropin = "T1542.003"
)

// grubDefaultFile is the well-known /etc/default/grub path. The file
// is shell-source'd by grub-mkconfig.
const grubDefaultFile = "/etc/default/grub"

// grubDDir holds executable shell scripts that grub-mkconfig invokes
// to build /boot/grub*/grub.cfg.
const grubDDir = "/etc/grub.d"

// DefaultMaxFileSize bounds one grub artifact. /etc/default/grub is
// well under 4 KiB; /etc/grub.d/* scripts are typically < 16 KiB.
// 1 MiB is the project-wide safety net.
const DefaultMaxFileSize = 1 << 20

// Options configures the grub module.
type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
	// Provenance annotates exec_target paths (init= overrides on
	// kernel.grub.config records, and the script file itself on
	// kernel.grub.dropin records) with their owning package. Stock
	// /etc/grub.d/* are dpkg/rpm-owned on every supported distro;
	// a non_package_path record under this site_class is a strong
	// signal.
	Provenance core.Provenance
	// LiveProcessSet membership check for live_process_attached.
	// grub-mkconfig is short-lived so the signal rarely fires on
	// dropin records, but the wiring is uniform across modules.
	LiveProcessSet core.LiveProcessSet
}

// Module collects GRUB persistence sites.
type Module struct {
	opts Options
}

// New constructs a grub Module. Zero-valued Options is valid.
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
func (m *Module) Name() string { return "grub" }

// SiteClasses returns the two site_class values this module emits.
func (m *Module) SiteClasses() []string {
	return []string{"kernel.grub.config", "kernel.grub.dropin"}
}

// Collect walks /etc/default/grub and /etc/grub.d/* and emits
// records.
func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error
	if err := m.collectDefaultGrub(ctx, emit); err != nil {
		errs = append(errs, err)
	}
	if err := m.collectGrubD(ctx, emit); err != nil {
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

// collectDefaultGrub reads /etc/default/grub and emits one record
// per KEY=VALUE assignment (or per non-recognized non-comment line).
func (m *Module) collectDefaultGrub(ctx context.Context, emit func(core.Record)) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	logical := grubDefaultFile
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
	if info.Size() > m.opts.MaxFileSize {
		emit(m.envelopeConfigRecord(logical, info, []core.RecordError{
			{Field: "content_sha256", Code: "SIZE_LIMIT"},
		}))
		return nil
	}
	raw, err := core.ReadFileCapped(real, m.opts.MaxFileSize)
	if err != nil {
		emit(m.envelopeConfigRecord(logical, info, []core.RecordError{
			{Field: "content_sha256", Code: errnoCode(err), Msg: err.Error()},
		}))
		return nil
	}
	if len(raw) == 0 {
		rec := m.baseConfigRecord(logical, info)
		rec.Signals = appendUnique(rec.Signals, core.SignalEmptyFile)
		emit(rec)
		return nil
	}
	entries := ParseConfig(raw)
	for _, e := range entries {
		if ctx.Err() != nil {
			return nil
		}
		emit(m.recordFromConfigEntry(logical, info, e))
	}
	return nil
}

// recordFromConfigEntry builds a per-line Record from a parsed
// /etc/default/grub assignment.
func (m *Module) recordFromConfigEntry(logical string, info os.FileInfo, e ConfigEntry) core.Record {
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         "kernel.grub.config",
		MITRE:             []string{mitreGrubConfig},
		Locus:             logical,
		ContentSHA256:     core.HashHexString(e.Raw),
		ContentNormSHA256: core.HashHexString(e.Canon),
		ContentSnippet:    snippet(e.Canon),
	}
	core.FillFileMeta(&rec, info)
	rec.Signals = m.baseSignals(info)
	if strings.HasPrefix(e.Key, "GRUB_CMDLINE_LINUX") && HasInitOverride(e.Value) {
		rec.Signals = appendUnique(rec.Signals, core.SignalGrubCmdlineInit)
		rec.ExecTarget = ExtractInit(e.Value)
		if rec.ExecTarget != "" {
			if isInterpreterInTmp(rec.ExecTarget) {
				rec.Signals = appendUnique(rec.Signals, core.SignalInterpreterInTmp)
			}
			if !m.targetExists(rec.ExecTarget) {
				rec.Signals = appendUnique(rec.Signals, core.SignalExecTargetOrphan)
			}
		}
	}
	rec.Signals = core.DedupSignalsSorted(rec.Signals)
	core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
	core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
	return rec
}

// collectGrubD walks /etc/grub.d/* and emits one record per script.
func (m *Module) collectGrubD(ctx context.Context, emit func(core.Record)) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	logicalDir := grubDDir
	realDir := m.resolve(logicalDir)
	entries, err := os.ReadDir(realDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("readdir %s: %w", logicalDir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		if ctx.Err() != nil {
			return ctx.Err()
		}
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
		m.processDropin(ctx, logical, real, info, emit)
	}
	return nil
}

// processDropin reads one /etc/grub.d/* script and emits its record.
func (m *Module) processDropin(ctx context.Context, logical, real string, info os.FileInfo, emit func(core.Record)) {
	if info.Size() > m.opts.MaxFileSize {
		emit(m.envelopeDropinRecord(logical, info, []core.RecordError{
			{Field: "content_sha256", Code: "SIZE_LIMIT"},
		}))
		return
	}
	raw, err := core.ReadFileCapped(real, m.opts.MaxFileSize)
	if err != nil {
		emit(m.envelopeDropinRecord(logical, info, []core.RecordError{
			{Field: "content_sha256", Code: errnoCode(err), Msg: err.Error()},
		}))
		return
	}
	if len(raw) == 0 {
		rec := m.baseDropinRecord(logical, info)
		rec.Signals = appendUnique(rec.Signals, core.SignalEmptyFile)
		emit(rec)
		return
	}
	canon := NormalizeDropin(raw)
	rec := m.baseDropinRecord(logical, info)
	rec.ContentSHA256 = core.HashHex(raw)
	rec.ContentNormSHA256 = core.HashHex(canon)
	rec.ContentSnippet = snippet(string(canon))
	// The grub.d script itself is the persistence target. grub-mkconfig
	// runs it at grub.cfg generation time as the user invoking it
	// (typically root).
	rec.ExecTarget = logical
	rec.ExecTargetSHA256 = rec.ContentSHA256
	core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
	core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
	emit(rec)
}

func (m *Module) baseConfigRecord(logical string, info os.FileInfo) core.Record {
	rec := core.Record{
		Module:    m.Name(),
		SiteClass: "kernel.grub.config",
		MITRE:     []string{mitreGrubConfig},
		Locus:     logical,
	}
	core.FillFileMeta(&rec, info)
	rec.Signals = m.baseSignals(info)
	return rec
}

func (m *Module) envelopeConfigRecord(logical string, info os.FileInfo, errs []core.RecordError) core.Record {
	rec := m.baseConfigRecord(logical, info)
	rec.Errors = errs
	return rec
}

func (m *Module) baseDropinRecord(logical string, info os.FileInfo) core.Record {
	rec := core.Record{
		Module:    m.Name(),
		SiteClass: "kernel.grub.dropin",
		MITRE:     []string{mitreGrubDropin},
		Locus:     logical,
	}
	core.FillFileMeta(&rec, info)
	rec.Signals = m.baseSignals(info)
	return rec
}

func (m *Module) envelopeDropinRecord(logical string, info os.FileInfo, errs []core.RecordError) core.Record {
	rec := m.baseDropinRecord(logical, info)
	rec.Errors = errs
	return rec
}

// baseSignals returns per-file signals: recent_mtime_*,
// world_writable, non_root_owner.
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

// targetExists returns true iff the resolved path is a stat-able
// file. Used for SignalExecTargetOrphan on init= overrides.
func (m *Module) targetExists(target string) bool {
	if target == "" {
		return false
	}
	_, err := os.Stat(m.resolve(target))
	return err == nil
}

func isInterpreterInTmp(target string) bool {
	for _, p := range core.TmpDirs {
		if strings.HasPrefix(target, p) {
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
