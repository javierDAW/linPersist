// Package ldso implements the linpersist collector for dynamic-linker
// persistence sites on Linux.
//
// Site_classes emitted by this module:
//
//   - ldso.preload   /etc/ld.so.preload   (one record per path token;
//                                          glibc honors multi-path
//                                          lines even though ld.so(8)
//                                          documents one path per line)
//   - ldso.conf      /etc/ld.so.conf      (one record per non-comment,
//                                          non-blank line; include
//                                          directives are NOT expanded)
//   - ldso.confd     /etc/ld.so.conf.d/*  (one record per non-comment,
//                                          non-blank line across every
//                                          *.conf drop-in file)
//
// All three carry MITRE ATT&CK T1574.006 (Hijack Execution Flow:
// Dynamic Linker Hijacking).
//
// Record granularity per site_class is documented in ADR-0002 for
// crontab-family files; ldso adopts the same per-entry shape so the
// downstream stacking model stays uniform across modules.
package ldso

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

// MITRE ATT&CK technique ID applied to every record this module emits.
const mitreLDSO = "T1574.006"

// tmpDirs is the set of path prefixes that trigger interpreter_in_tmp.
// Mirrors the list used by the cron module; kept private per module
// because the canonical home for this constant (a core helper) is
// scheduled for a later refactor once a third module needs it.
var tmpDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"}

// Options configures a Module instance.
//
// Root, Now and MaxFileSize follow the same convention as the cron
// module: empty Root means absolute paths read as-is, Now defaults to
// time.Now().UTC(), and MaxFileSize defaults to DefaultMaxFileSize.
type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
}

// DefaultMaxFileSize bounds the per-file read. ld.so.conf and
// ld.so.preload are < 1 KiB on every distro in the support matrix;
// 1 MiB is a generous safety net.
const DefaultMaxFileSize = 1 << 20

// Module collects dynamic-linker persistence artifacts.
type Module struct {
	opts Options
}

// New constructs a Module with default fallbacks for unset Options.
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

// Name returns "ldso".
func (m *Module) Name() string { return "ldso" }

// SiteClasses returns the three site_class values this module emits.
func (m *Module) SiteClasses() []string {
	return []string{"ldso.preload", "ldso.conf", "ldso.confd"}
}

// Collect walks the configured loci and emits Records via emit.
func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error

	if err := m.collectPreload(ctx, "/etc/ld.so.preload", emit); err != nil {
		errs = append(errs, err)
	}
	if err := m.collectConfFile(ctx, "/etc/ld.so.conf", "ldso.conf", emit); err != nil {
		errs = append(errs, err)
	}
	if err := m.collectConfdDir(ctx, "/etc/ld.so.conf.d", emit); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// resolve prepends Options.Root (if any) to a logical path so all
// disk access stays inside the test root in unit tests.
func (m *Module) resolve(logical string) string {
	if m.opts.Root == "" {
		return logical
	}
	return filepath.Join(m.opts.Root, logical)
}

// collectPreload reads /etc/ld.so.preload and emits one record per
// whitespace-separated path token. Missing or empty files emit no
// records (an absent preload file is the common case and an empty
// preload file is indistinguishable from absence for our purposes).
func (m *Module) collectPreload(ctx context.Context, logical string, emit func(core.Record)) error {
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
	const siteClass = "ldso.preload"

	if info.Size() > m.opts.MaxFileSize {
		emit(m.envelopeRecord(logical, info, siteClass, []core.RecordError{
			{Field: "content_sha256", Code: "SIZE_LIMIT"},
		}, nil))
		return nil
	}
	raw, err := os.ReadFile(real)
	if err != nil {
		emit(m.envelopeRecord(logical, info, siteClass, []core.RecordError{
			{Field: "content_sha256", Code: errnoCode(err), Msg: err.Error()},
		}, nil))
		return nil
	}
	if len(raw) == 0 {
		return nil
	}

	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if ctx.Err() != nil {
			return nil
		}
		rawLine := sc.Text()
		if isLeadingComment(rawLine) {
			continue
		}
		stripped := stripInlineComment(rawLine)
		if strings.TrimSpace(stripped) == "" {
			continue
		}
		tokens := parsePreloadLine(rawLine)
		if len(tokens) == 0 {
			continue
		}
		// content_sha256 is computed once per source line and shared
		// across every record produced from that line. The whole-line
		// raw bytes encode the original ordering of paths, which is
		// useful for backend queries that want to reconstruct the
		// authoring intent.
		lineHash := core.HashHexString(stripped)
		for _, tok := range tokens {
			emit(m.recordFromPreloadToken(logical, info, lineHash, tok))
		}
	}
	return nil
}

// recordFromPreloadToken builds the per-path Record for one
// ld.so.preload entry. lineHash is sha256 of the source line bytes
// (after inline-comment strip and right-trim) and is shared across
// every token derived from the same line; the per-record
// content_norm_sha256 is hashed over the token alone.
func (m *Module) recordFromPreloadToken(logical string, info os.FileInfo, lineHash, token string) core.Record {
	canon := canonicalPreload(token)
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         "ldso.preload",
		MITRE:             []string{mitreLDSO},
		Locus:             logical,
		ContentSHA256:     lineHash,
		ContentNormSHA256: core.HashHexString(canon),
		ContentSnippet:    snippet(canon),
		ExecTarget:        token,
	}
	fillFileMeta(&rec, info)

	signals := m.baseSignals(info, logical)
	signals = append(signals, core.SignalLDPreloadSet)
	signals = append(signals, m.execTargetSignals(token)...)
	if h, ok := m.hashExecTarget(token); ok {
		rec.ExecTargetSHA256 = h
	}
	if m.targetMtimeRecent(token) {
		signals = append(signals, core.SignalRecentTargetMtime7d)
	}
	rec.Signals = dedupSignals(signals)
	return rec
}

// collectConfFile reads a single ld.so.conf-style file and emits one
// record per non-comment, non-blank line.
func (m *Module) collectConfFile(ctx context.Context, logical, siteClass string, emit func(core.Record)) error {
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
	m.processConfFile(ctx, logical, real, info, siteClass, emit)
	return nil
}

// collectConfdDir walks /etc/ld.so.conf.d/ and processes every *.conf
// drop-in file as site_class=ldso.confd.
func (m *Module) collectConfdDir(ctx context.Context, logicalDir string, emit func(core.Record)) error {
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
			// Glibc only honors *.conf drop-ins; mirror that filter
			// so files like .keep or README in the directory don't
			// produce phantom records.
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
		m.processConfFile(ctx, logical, real, info, "ldso.confd", emit)
	}
	return nil
}

// processConfFile reads, parses and emits records for one
// ld.so.conf-style file.
func (m *Module) processConfFile(ctx context.Context, logical, real string, info os.FileInfo, siteClass string, emit func(core.Record)) {
	if info.Size() > m.opts.MaxFileSize {
		emit(m.envelopeRecord(logical, info, siteClass, []core.RecordError{
			{Field: "content_sha256", Code: "SIZE_LIMIT"},
		}, nil))
		return
	}
	raw, err := os.ReadFile(real)
	if err != nil {
		emit(m.envelopeRecord(logical, info, siteClass, []core.RecordError{
			{Field: "content_sha256", Code: errnoCode(err), Msg: err.Error()},
		}, nil))
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
		if isLeadingComment(rawLine) {
			continue
		}
		stripped := stripInlineComment(rawLine)
		if strings.TrimSpace(stripped) == "" {
			continue
		}
		pl := parseConfLine(rawLine)
		if pl.kind == confLineEmpty {
			continue
		}
		lineHash := core.HashHexString(stripped)
		emit(m.recordFromConfLine(logical, info, siteClass, pl, lineHash))
	}
}

// recordFromConfLine builds the per-line Record for one ld.so.conf
// (or *.conf drop-in) entry.
func (m *Module) recordFromConfLine(logical string, info os.FileInfo, siteClass string, pl parsedConfLine, lineHash string) core.Record {
	canon := canonicalConf(pl)
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         siteClass,
		MITRE:             []string{mitreLDSO},
		Locus:             logical,
		ContentSHA256:     lineHash,
		ContentNormSHA256: core.HashHexString(canon),
		ContentSnippet:    snippet(canon),
		ExecTarget:        pl.target,
	}
	fillFileMeta(&rec, info)

	signals := m.baseSignals(info, logical)
	signals = append(signals, m.execTargetSignals(pl.target)...)
	if h, ok := m.hashExecTarget(pl.target); ok {
		rec.ExecTargetSHA256 = h
	}
	if m.targetMtimeRecent(pl.target) {
		signals = append(signals, core.SignalRecentTargetMtime7d)
	}
	rec.Signals = dedupSignals(signals)
	return rec
}

// envelopeRecord builds a record that represents the file itself
// rather than a parsed line. Used for SIZE_LIMIT and EACCES.
func (m *Module) envelopeRecord(logical string, info os.FileInfo, siteClass string, errs []core.RecordError, extraSignals []string) core.Record {
	rec := core.Record{
		Module:    m.Name(),
		SiteClass: siteClass,
		MITRE:     []string{mitreLDSO},
		Locus:     logical,
		Errors:    errs,
	}
	fillFileMeta(&rec, info)
	base := m.baseSignals(info, logical)
	if siteClass == "ldso.preload" {
		base = append(base, core.SignalLDPreloadSet)
	}
	rec.Signals = dedupSignals(append(base, extraSignals...))
	return rec
}

// fillFileMeta populates ownership, mode and timestamp fields from a
// FileInfo. Mirrors the cron module's implementation; kept private
// because cross-module helpers are not part of the v0.1.0 core API
// surface (a refactor into core/ will land when a third module needs
// the same code).
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

// baseSignals returns the per-file signals that are independent of
// the line content: recent_mtime_*, world_writable, non_root_owner.
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

// execTargetSignals derives signals from a single exec_target string.
// Globs in exec_target skip orphan detection (a glob with zero
// matches is normal, not an orphan). The /tmp prefix check applies
// to every target so an include directive pointing under /tmp still
// surfaces.
func (m *Module) execTargetSignals(target string) []string {
	var out []string
	if target == "" {
		return out
	}
	for _, prefix := range tmpDirs {
		if strings.HasPrefix(target, prefix) {
			out = append(out, core.SignalInterpreterInTmp)
			break
		}
	}
	if strings.HasPrefix(target, "/") && !hasGlobMeta(target) {
		if _, err := os.Stat(m.resolve(target)); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				out = append(out, core.SignalExecTargetOrphan)
			}
		}
	}
	return out
}

// hashExecTarget returns the SHA-256 of the file at target, or
// (_, false) when the target is a glob, does not exist, or is not a
// regular file. Directories are explicitly excluded so search-path
// entries like /usr/local/lib do not yield a hash.
func (m *Module) hashExecTarget(target string) (string, bool) {
	if target == "" {
		return "", false
	}
	if !strings.HasPrefix(target, "/") {
		return "", false
	}
	if hasGlobMeta(target) {
		return "", false
	}
	real := m.resolve(target)
	info, err := os.Lstat(real)
	if err != nil {
		return "", false
	}
	if !info.Mode().IsRegular() {
		return "", false
	}
	f, err := os.Open(real)
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

// targetMtimeRecent reports whether the resolved exec_target's mtime
// falls within the last 7 days relative to Options.Now. Returns
// false when the target is a glob, missing or unreadable.
func (m *Module) targetMtimeRecent(target string) bool {
	if target == "" || hasGlobMeta(target) || !strings.HasPrefix(target, "/") {
		return false
	}
	info, err := os.Stat(m.resolve(target))
	if err != nil {
		return false
	}
	delta := m.opts.Now().Sub(info.ModTime().UTC())
	return delta >= 0 && delta < 7*24*time.Hour
}

// isSystemPath returns true for paths under /etc, /usr, /lib, /bin,
// /sbin where uid != 0 ownership is anomalous.
func isSystemPath(p string) bool {
	for _, prefix := range []string{"/etc/", "/usr/", "/lib/", "/bin/", "/sbin/"} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// skipDirEntry returns true for dpkg backup files, dotfiles, and
// editor-style backups.
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

// snippet returns the first 256 bytes of s, byte-truncated.
func snippet(s string) string {
	const max = 256
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// dedupSignals stable-deduplicates a signal slice, preserving order
// of first occurrence.
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

// errnoCode returns the POSIX errno mnemonic for an os error when
// detectable, otherwise "IO_ERROR".
func errnoCode(err error) string {
	if errors.Is(err, fs.ErrNotExist) {
		return "ENOENT"
	}
	if errors.Is(err, fs.ErrPermission) {
		return "EACCES"
	}
	return "IO_ERROR"
}
