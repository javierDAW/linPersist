// Package atjobs implements the linpersist collector for at(1)
// scheduled-job persistence on Linux.
//
// Site_class emitted:
//
//   - at.jobs   one record per file under /var/spool/at/ and
//     /var/spool/cron/atjobs/ (the two well-known atd spool
//     directories across distros). atd executes the spool file as a
//     shell script when the queued time arrives; an attacker who can
//     write a spool file gets one-shot or recurring code execution
//     at any future time. Per-file granularity. The atd header (HOME=
//     PATH= LOGNAME= umask=) is stripped from content_norm_sha256
//     because it is volatile per user and would defeat stacking.
//
// MITRE T1053.001 (Scheduled Task/Job: At). Legacy but present and
// often unmonitored; PANIX lists it as a textbook persistence
// vector on the offensive side.
package atjobs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

// MITRE ATT&CK technique applied to every record this module emits.
const mitreAtJobs = "T1053.001"

// spoolDirs are the two well-known atd queue directories. Order is
// load-bearing for determinism: /var/spool/at/ is walked first, then
// /var/spool/cron/atjobs/, so the emitted records are stable across
// hosts that have both.
var spoolDirs = []string{
	"/var/spool/at",
	"/var/spool/cron/atjobs",
}

// DefaultMaxFileSize bounds one spool entry. Real at jobs are
// typically < 8 KiB (the header + the user's command). 1 MiB leaves
// headroom for hand-crafted multi-step jobs without letting a
// runaway file dominate memory.
const DefaultMaxFileSize = 1 << 20

// Options configures the atjobs module.
type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
	// Provenance is wired uniformly across modules. at.jobs sets
	// exec_target to the spool file itself (same pattern as
	// cron.periodic) so provenance is rarely informative here —
	// /var/spool/at is not package-owned. Present for API symmetry.
	Provenance core.Provenance
	// LiveProcessSet is also wired uniformly. The spool file itself
	// is not an /proc/<pid>/exe target, so this is informational at
	// best.
	LiveProcessSet core.LiveProcessSet
}

// Module collects at(1) job persistence sites.
type Module struct {
	opts Options
}

// New constructs an atjobs Module. Zero-valued Options is valid.
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
func (m *Module) Name() string { return "atjobs" }

// SiteClasses returns the single site_class this module emits.
func (m *Module) SiteClasses() []string { return []string{"at.jobs"} }

// Collect walks every spool directory and emits one record per job.
func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error
	for _, d := range spoolDirs {
		if err := m.walkDir(ctx, d, emit); err != nil {
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

// walkDir lists every regular file under one spool directory and
// emits one record per file. Subdirectories (like atd's own
// `.SEQ` artifacts) and special files are skipped.
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
	// Sort entries for deterministic walk order. os.ReadDir already
	// sorts by name on Linux but the spec does not promise it for
	// every filesystem; sort defensively.
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
		m.processFile(ctx, logical, real, info, emit)
	}
	return nil
}

// processFile reads, normalizes, hashes, and emits one record per
// spool entry.
func (m *Module) processFile(ctx context.Context, logical, real string, info os.FileInfo, emit func(core.Record)) {
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
	body, structured := extractBody(raw)
	_ = structured
	canon := normalizeShell(body)
	rec := m.baseRecord(logical, info)
	rec.ContentSHA256 = core.HashHex(raw)
	rec.ContentNormSHA256 = core.HashHex(canon)
	rec.ContentSnippet = snippet(string(canon))
	// The spool file itself is the persistence target: atd executes
	// it as a shell script when the queue time arrives. Same model
	// as cron.periodic.
	rec.ExecTarget = logical
	rec.ExecTargetSHA256 = rec.ContentSHA256
	core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
	core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
	emit(rec)
}

func (m *Module) baseRecord(logical string, info os.FileInfo) core.Record {
	rec := core.Record{
		Module:    m.Name(),
		SiteClass: "at.jobs",
		MITRE:     []string{mitreAtJobs},
		Locus:     logical,
	}
	core.FillFileMeta(&rec, info)
	rec.Signals = m.baseSignals(info)
	return rec
}

func (m *Module) envelopeRecord(logical string, info os.FileInfo, errs []core.RecordError) core.Record {
	rec := m.baseRecord(logical, info)
	rec.Errors = errs
	return rec
}

// baseSignals returns the per-file signals: recent_mtime_* and
// world_writable. non_root_owner does NOT apply here: atd spool files
// are by construction owned by the user who scheduled the job, so a
// non-root uid is expected.
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
	return out
}

// skipName mirrors the convention every other module uses: hide
// dotfiles, backup files, and dpkg/rpm leftovers from the walker.
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
