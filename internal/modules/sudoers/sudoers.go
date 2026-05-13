// Package sudoers implements the linpersist collector for sudo
// persistence on Linux.
//
// Site_class emitted: sudoers (MITRE T1548.003).
// Loci: /etc/sudoers and every regular file under /etc/sudoers.d/.
//
// Granularity is one record per non-comment, non-blank line. Five
// line kinds are recognized (alias, defaults, user spec, #include,
// #includedir). See normalize.go for the canonical-form rules.
package sudoers

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

// MITRE ATT&CK technique applied to every record this module emits.
const mitreSudoers = "T1548.003"

// Options configures a Module instance.
type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
}

const DefaultMaxFileSize = 1 << 20

// Module collects sudoers persistence artifacts.
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
	return &Module{opts: opts}
}

// Compile-time interface conformance.
var _ core.Module = (*Module)(nil)

// Name returns "sudoers".
func (m *Module) Name() string { return "sudoers" }

// SiteClasses returns the single site_class this module emits.
func (m *Module) SiteClasses() []string {
	return []string{"sudoers"}
}

// Collect walks /etc/sudoers and /etc/sudoers.d/*.
func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error
	if err := m.collectFile(ctx, "/etc/sudoers", emit); err != nil {
		errs = append(errs, err)
	}
	if err := m.collectDir(ctx, "/etc/sudoers.d", emit); err != nil {
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

	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if ctx.Err() != nil {
			return
		}
		rawLine := sc.Text()
		pl := parseLine(rawLine)
		if pl.kind == lineEmpty {
			continue
		}
		emit(m.recordFromLine(logical, info, pl))
	}
}

// recordFromLine builds the per-line Record.
func (m *Module) recordFromLine(logical string, info os.FileInfo, pl parsedLine) core.Record {
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         "sudoers",
		MITRE:             []string{mitreSudoers},
		Locus:             logical,
		ContentSHA256:     core.HashHexString(pl.raw),
		ContentNormSHA256: core.HashHexString(pl.canon),
		ContentSnippet:    snippet(pl.canon),
	}
	fillFileMeta(&rec, info)

	signals := m.baseSignals(info, logical)
	switch pl.kind {
	case lineInclude:
		signals = append(signals, core.SignalSudoersIncludeDirective)
	case lineAlias, lineDefaults, lineUserSpec:
		if hasNoPasswd(pl.canon) {
			signals = append(signals, core.SignalSudoersNoPasswd)
		}
		if hasAllCommands(pl.canon) {
			signals = append(signals, core.SignalSudoersAllCommands)
		}
	}
	rec.Signals = dedupSignals(signals)
	return rec
}

func (m *Module) envelopeRecord(logical string, info os.FileInfo, errs []core.RecordError) core.Record {
	rec := core.Record{
		Module:    m.Name(),
		SiteClass: "sudoers",
		MITRE:     []string{mitreSudoers},
		Locus:     logical,
		Errors:    errs,
	}
	if info != nil {
		fillFileMeta(&rec, info)
		rec.Signals = dedupSignals(m.baseSignals(info, logical))
	}
	return rec
}

// fillFileMeta mirrors the other modules' implementation.
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

// baseSignals returns per-file signals independent of line content.
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
