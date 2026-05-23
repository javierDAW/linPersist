// Package sshd implements the linpersist collector for sshd_config
// persistence on Linux.
//
// Site_class emitted: sshd.config (MITRE T1098.004 + T1556).
// Loci: /etc/ssh/sshd_config and every *.conf file under
// /etc/ssh/sshd_config.d/.
//
// Granularity is one record per non-comment, non-blank line, plus
// one record per Match line. Match block scoping is encoded into
// content_norm_sha256 per ADR-0004.
package sshd

import (
	"bufio"
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

// MITRE ATT&CK techniques applied to every record this module emits.
var mitreSSHDConfig = []string{"T1098.004", "T1556"}

// Options configures a Module instance.
type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
	// Provenance annotates exec_target paths (AuthorizedKeysCommand,
	// ForceCommand) with their owning package. Nil defaults to
	// core.NoopProvenance.
	Provenance core.Provenance
	// LiveProcessSet membership check for the live_process_attached
	// signal. Nil defaults to core.NoopLiveProcessSet.
	LiveProcessSet core.LiveProcessSet
}

const DefaultMaxFileSize = 1 << 20

// Module collects sshd_config persistence artifacts.
type Module struct {
	opts Options
}

// New constructs a Module with default fallbacks.
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

// Name returns "sshd".
func (m *Module) Name() string { return "sshd" }

// SiteClasses returns the single site_class this module emits.
func (m *Module) SiteClasses() []string {
	return []string{"sshd.config"}
}

// Collect walks /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/*.
func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error
	if err := m.collectFile(ctx, "/etc/ssh/sshd_config", emit); err != nil {
		errs = append(errs, err)
	}
	if err := m.collectDir(ctx, "/etc/ssh/sshd_config.d", emit); err != nil {
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

func (m *Module) collectFile(ctx context.Context, logical string, emit func(core.Record)) error {
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
	m.processFile(ctx, logical, real, info, emit)
	return nil
}

func (m *Module) collectDir(ctx context.Context, logicalDir string, emit func(core.Record)) error {
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
		if !strings.HasSuffix(name, ".conf") {
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
		return
	}

	// Walk the file maintaining the current Match canonical context.
	// Each file is parsed standalone; no Match context carries between
	// /etc/ssh/sshd_config and drop-in files.
	currentMatch := ""
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if ctx.Err() != nil {
			return
		}
		pl := parseLine(sc.Text())
		switch pl.kind {
		case lineEmpty:
			continue
		case lineMatch:
			currentMatch = canonicalMatchLine(pl.matchRaw)
			emit(m.recordFromMatch(logical, info, pl, currentMatch))
		case lineDirective:
			emit(m.recordFromDirective(logical, info, pl, currentMatch))
		}
	}
}

// recordFromMatch builds the per-Match-line Record. The Match line
// itself carries the sshd_match_block_directive signal so backends
// can find every line in a Match block (the Match line plus its
// directives) with one predicate.
func (m *Module) recordFromMatch(logical string, info os.FileInfo, pl parsedLine, canon string) core.Record {
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         "sshd.config",
		MITRE:             mitreSSHDConfig,
		Locus:             logical,
		ContentSHA256:     core.HashHexString(pl.raw),
		ContentNormSHA256: core.HashHexString(canon),
		ContentSnippet:    snippet(snippetMatch(pl.keyword, pl.matchRaw)),
	}
	core.FillFileMeta(&rec, info)
	signals := m.baseSignals(info, logical)
	signals = append(signals, core.SignalSSHDMatchBlockDirective)
	rec.Signals = core.DedupSignals(signals)
	return rec
}

// recordFromDirective builds the per-directive Record.
func (m *Module) recordFromDirective(logical string, info os.FileInfo, pl parsedLine, currentMatch string) core.Record {
	canon := canonicalDirective(pl.keyword, pl.value, currentMatch)
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         "sshd.config",
		MITRE:             mitreSSHDConfig,
		Locus:             logical,
		ContentSHA256:     core.HashHexString(pl.raw),
		ContentNormSHA256: core.HashHexString(canon),
		ContentSnippet:    snippet(snippetDirective(pl.keyword, pl.value)),
	}
	if et := directiveExecTarget(pl.keyword, pl.value); et != "" {
		rec.ExecTarget = et
	}
	core.FillFileMeta(&rec, info)
	signals := m.baseSignals(info, logical)
	signals = append(signals, directiveSignals(pl.keyword, pl.value)...)
	if currentMatch != "" {
		signals = append(signals, core.SignalSSHDMatchBlockDirective)
	}
	if rec.ExecTarget != "" {
		signals = append(signals, m.execTargetSignals(rec.ExecTarget)...)
	}
	rec.Signals = core.DedupSignals(signals)
	core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
	core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
	return rec
}

func (m *Module) envelopeRecord(logical string, info os.FileInfo, errs []core.RecordError) core.Record {
	rec := core.Record{
		Module:    m.Name(),
		SiteClass: "sshd.config",
		MITRE:     mitreSSHDConfig,
		Locus:     logical,
		Errors:    errs,
	}
	if info != nil {
		core.FillFileMeta(&rec, info)
		rec.Signals = core.DedupSignals(m.baseSignals(info, logical))
	}
	return rec
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

func (m *Module) execTargetSignals(target string) []string {
	var out []string
	if target == "" || !strings.HasPrefix(target, "/") {
		return out
	}
	for _, prefix := range core.TmpDirs {
		if strings.HasPrefix(target, prefix) {
			out = append(out, core.SignalInterpreterInTmp)
			break
		}
	}
	if _, err := os.Stat(m.resolve(target)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			out = append(out, core.SignalExecTargetOrphan)
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
