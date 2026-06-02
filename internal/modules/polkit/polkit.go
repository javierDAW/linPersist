// Package polkit implements the linpersist collector for polkit
// (PolicyKit) JS rule persistence on Linux.
//
// Site_class emitted:
//
//   - polkit.rules   one record per .rules file under
//     /etc/polkit-1/rules.d/ (administrator/local rules) and
//     /usr/share/polkit-1/rules.d/ (distro-shipped rules). Polkit's
//     JS engine evaluates these to decide whether an action is
//     allowed. A malicious rule can grant any user uid-0 effectively
//     by returning polkit.Result.YES from a rule callback.
//
// MITRE T1548 (Abuse Elevation Control Mechanism, parent technique).
// ATT&CK has no Linux-polkit sub-technique as of May 2026; T1548 is
// the closest match. The textbook reference is Pwnkit (CVE-2021-4034)
// — a heap overflow in pkexec — and a long tail of post-exploit
// rule-file backdoors documented by Mandiant and The DFIR Report.
package polkit

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

// MITRE ATT&CK technique applied to every record this module emits.
const mitrePolkit = "T1548"

// rulesDirs are the two well-known polkit rules directories. Order
// matters for determinism: /etc/ rules override /usr/share/ on the
// real host, but the agent walks both and emits records for both;
// the backend correlates by basename.
var rulesDirs = []string{
	"/etc/polkit-1/rules.d",
	"/usr/share/polkit-1/rules.d",
}

// DefaultMaxFileSize bounds one rule file. Real polkit rules files
// are typically < 4 KiB; 1 MiB leaves room for an unusual rule
// without letting a runaway file dominate memory.
const DefaultMaxFileSize = 1 << 20

// Options configures the polkit module.
type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
	// Provenance is wired uniformly across modules. polkit.rules
	// records do NOT populate ExecTarget (rules evaluate policy, not
	// binaries); the field is present for API symmetry.
	Provenance core.Provenance
	// LiveProcessSet is also wired uniformly but unused here for the
	// same reason as Provenance.
	LiveProcessSet core.LiveProcessSet
}

// Module collects polkit JS rule persistence sites.
type Module struct {
	opts Options
}

// New constructs a polkit Module. Zero-valued Options is valid.
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
func (m *Module) Name() string { return "polkit" }

// SiteClasses returns the single site_class this module emits.
func (m *Module) SiteClasses() []string { return []string{"polkit.rules"} }

// Collect walks every rules directory and emits one record per file.
func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error
	for _, d := range rulesDirs {
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

// walkDir lists every *.rules file under one rules directory and
// emits a record per file. Non-.rules entries are skipped to match
// what the polkit daemon honors.
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
		if !strings.HasSuffix(name, ".rules") {
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
// rules file.
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
	canon := Normalize(raw)
	rec := m.baseRecord(logical, info)
	rec.ContentSHA256 = core.HashHex(raw)
	rec.ContentNormSHA256 = core.HashHex(canon)
	rec.ContentSnippet = snippet(string(canon))
	if containsToken(canon, "addAdminRule(") {
		rec.Signals = appendUnique(rec.Signals, core.SignalPolkitAdminRule)
	}
	if containsToken(canon, "polkit.Result.YES") || containsToken(canon, "Result.YES") {
		rec.Signals = appendUnique(rec.Signals, core.SignalPolkitYesConstant)
	}
	rec.Signals = core.DedupSignalsSorted(rec.Signals)
	emit(rec)
}

func (m *Module) baseRecord(logical string, info os.FileInfo) core.Record {
	rec := core.Record{
		Module:    m.Name(),
		SiteClass: "polkit.rules",
		MITRE:     []string{mitrePolkit},
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

// baseSignals returns the per-file signals: recent_mtime_*,
// world_writable, non_root_owner. polkit rule files are expected to
// be root-owned (the daemon refuses to honor others), so non_root_owner
// here is a notable anomaly.
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
