// Package cron implements the linpersist collector for cron-family
// persistence sites on Linux.
//
// Site_classes emitted by this module:
//
//   - cron.d         system crontabs with USER column
//     (/etc/crontab, /etc/cron.d/*)
//   - cron.user      per-user crontabs without USER column
//     (/var/spool/cron/crontabs/*, /var/spool/cron/*)
//   - cron.periodic  run-parts executables
//     (/etc/cron.{hourly,daily,weekly,monthly}/*)
//   - cron.anacron   /etc/anacrontab (period/delay/jobid/command)
//
// Record granularity is per non-comment, non-blank line for the three
// crontab-format site_classes; per file for cron.periodic. See
// docs/adr/0002-record-granularity.md for the rationale.
package cron

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
const mitreCron = "T1053.003"

// shellInterps is the set of executable basenames that trigger the
// shell_indirect signal: when these are the first token of a cron
// command, the real workload lives inside a -c argument the agent
// does not parse.
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

// Options configures a Module instance.
//
// Root is the synthetic filesystem prefix prepended to every locus
// before disk access. In production it is "" (absolute paths are
// read as-is). In tests it is set to a t.TempDir() so the module
// reads a copy of the fixture instead of the host's real /etc.
//
// Now is the clock used for time-relative signals (recent_mtime_7d
// and recent_mtime_30d). In tests it is fixed to make goldens
// reproducible.
//
// MaxFileSize bounds the bytes the module will read for any single
// artifact. Files larger than this emit one envelope record with an
// errors[] entry of code "SIZE_LIMIT" and no content hashes.
type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
	// Provenance resolves exec_target paths to their owning package.
	// Nil defaults to core.NoopProvenance (every lookup returns
	// Unknown so existing golden tests stay byte-identical).
	Provenance core.Provenance
	// LiveProcessSet membership check for the live_process_attached
	// signal. Nil defaults to core.NoopLiveProcessSet (every lookup
	// returns false, no signal emitted).
	LiveProcessSet core.LiveProcessSet
}

// DefaultMaxFileSize is the per-file size limit when Options.MaxFileSize
// is zero. Crontab files in the wild are < 50 KiB; 1 MiB is a generous
// safety net.
const DefaultMaxFileSize = 1 << 20

// Module collects cron-family persistence artifacts.
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

// Name returns "cron".
func (m *Module) Name() string { return "cron" }

// SiteClasses returns the four site_class values this module emits.
func (m *Module) SiteClasses() []string {
	return []string{"cron.d", "cron.user", "cron.periodic", "cron.anacron"}
}

// Collect walks the configured loci and emits Records via the callback.
func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error

	// cron.d: /etc/crontab + /etc/cron.d/*
	if err := m.collectCrontabFile(ctx, "/etc/crontab", "cron.d", true, emit); err != nil {
		errs = append(errs, err)
	}
	if err := m.collectCrontabDir(ctx, "/etc/cron.d", "cron.d", true, emit); err != nil {
		errs = append(errs, err)
	}

	// cron.user: /var/spool/cron/crontabs/* (Debian) + /var/spool/cron/* (RHEL)
	for _, dir := range []string{"/var/spool/cron/crontabs", "/var/spool/cron"} {
		if err := m.collectCrontabDir(ctx, dir, "cron.user", false, emit); err != nil {
			errs = append(errs, err)
		}
	}

	// cron.periodic: /etc/cron.{hourly,daily,weekly,monthly}/*
	for _, dir := range []string{
		"/etc/cron.hourly",
		"/etc/cron.daily",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
	} {
		if err := m.collectPeriodicDir(ctx, dir, emit); err != nil {
			errs = append(errs, err)
		}
	}

	// cron.anacron: /etc/anacrontab (own format, parsed elsewhere).
	if err := m.collectAnacrontab(ctx, "/etc/anacrontab", emit); err != nil {
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

// collectCrontabFile collects records from a single crontab-format
// file. siteClass is "cron.d" or "cron.user"; hasUser flags whether
// the format includes a USER column.
func (m *Module) collectCrontabFile(ctx context.Context, logical, siteClass string, hasUser bool, emit func(core.Record)) error {
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
	m.processCrontabFile(ctx, logical, real, info, siteClass, hasUser, emit)
	return nil
}

// collectCrontabDir walks a directory of crontab-format files.
func (m *Module) collectCrontabDir(ctx context.Context, logicalDir, siteClass string, hasUser bool, emit func(core.Record)) error {
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
		m.processCrontabFile(ctx, logical, real, info, siteClass, hasUser, emit)
	}
	return nil
}

// skipDirEntry returns true for dpkg backup files, dotfiles, and
// editor-style backups that cron also ignores.
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

// processCrontabFile reads, parses and emits records for one crontab
// file. Per-line records are emitted; size and read errors degrade
// gracefully to a single envelope record with errors[] populated.
func (m *Module) processCrontabFile(ctx context.Context, logical, real string, info os.FileInfo, siteClass string, hasUser bool, emit func(core.Record)) {
	if info.Size() > m.opts.MaxFileSize {
		emit(m.envelopeRecord(logical, info, siteClass, []core.RecordError{
			{Field: "content_sha256", Code: "SIZE_LIMIT"},
		}, nil))
		return
	}

	raw, err := core.ReadFileCapped(real, m.opts.MaxFileSize)
	if err != nil {
		emit(m.envelopeRecord(logical, info, siteClass, []core.RecordError{
			{Field: "content_sha256", Code: errnoCode(err), Msg: err.Error()},
		}, nil))
		return
	}
	if len(raw) == 0 {
		// Empty crontab adds no records; presence alone is uninteresting.
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
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" {
			continue
		}
		pl := parseCrontabLine(rawLine, hasUser)
		if pl.kind == lineEmpty {
			continue
		}
		emit(m.recordFromParsedLine(logical, info, siteClass, pl))
	}
}

// recordFromParsedLine builds the per-line Record.
func (m *Module) recordFromParsedLine(logical string, info os.FileInfo, siteClass string, pl parsedLine) core.Record {
	canon := canonicalLine(pl)
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         siteClass,
		MITRE:             []string{mitreCron},
		Locus:             logical,
		ContentSHA256:     core.HashHexString(pl.raw),
		ContentNormSHA256: core.HashHexString(canon),
		ContentSnippet:    snippet(canon),
	}
	core.FillFileMeta(&rec, info)
	signals := m.baseSignals(info, logical)

	switch pl.kind {
	case lineVarAssignment:
		signals = append(signals, core.SignalCronVarAssignment)
	case lineScheduleEntry:
		if pl.schedule == "@reboot" {
			signals = append(signals, core.SignalAtReboot)
		}
		first := firstToken(pl.command)
		if first != "" {
			rec.ExecTarget = first
			if strings.HasPrefix(first, "/") {
				if sum, ok := core.HashFileCapped(m.resolve(first), m.opts.MaxFileSize); ok {
					rec.ExecTargetSHA256 = sum
				}
			}
			signals = append(signals, m.execTargetSignals(first)...)
			// A packaged interpreter (python3/bash/...) running a parked
			// payload: exec_target is the owned interpreter, so the SCRIPT
			// ARGUMENT is otherwise invisible. Resolve it and check both
			// halves of the ownership/integrity asymmetry -- orphan (not
			// packaged) AND owned-but-tampered (digest mismatch).
			if arg, ok := core.InterpreterScriptArg(strings.Fields(pl.command)); ok {
				if _, st := m.opts.Provenance.LookupPath(arg); st == core.PkgStatusOrphan {
					signals = append(signals, core.SignalInterpreterRunsOrphanScript)
				}
				if v, ok := m.opts.Provenance.(interface {
					VerifyPath(string) core.PkgVerifyStatus
				}); ok {
					signals = append(signals, core.TamperSignal(v.VerifyPath(arg))...)
				}
			}
		}
	case lineMalformed:
		rec.Errors = append(rec.Errors, core.RecordError{Field: "schedule", Code: pl.parseErr})
	}

	rec.Signals = core.DedupSignals(signals)
	core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
	core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
	return rec
}

// envelopeRecord builds a record that represents the file itself
// rather than a parsed line. Used for SIZE_LIMIT, EACCES, and for
// empty cron.periodic scripts.
func (m *Module) envelopeRecord(logical string, info os.FileInfo, siteClass string, errs []core.RecordError, extraSignals []string) core.Record {
	rec := core.Record{
		Module:    m.Name(),
		SiteClass: siteClass,
		MITRE:     []string{mitreCron},
		Locus:     logical,
		Errors:    errs,
	}
	core.FillFileMeta(&rec, info)
	rec.Signals = core.DedupSignals(append(m.baseSignals(info, logical), extraSignals...))
	return rec
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

// execTargetSignals derives signals from an exec_target string alone.
// A single os.Stat is reused to feed both exec_target_orphan (when
// the target is missing) and recent_target_mtime_7d (when present
// and modified within the last 7 days).
func (m *Module) execTargetSignals(target string) []string {
	var out []string
	if !strings.HasPrefix(target, "/") {
		out = append(out, core.SignalUnqualifiedExecTarget)
		if _, ok := shellInterps[target]; ok {
			out = append(out, core.SignalShellIndirect)
		}
		return out
	}
	for _, prefix := range core.TmpDirs {
		if strings.HasPrefix(target, prefix) {
			out = append(out, core.SignalInterpreterInTmp)
			break
		}
	}
	// Resolve against the configured Root for orphan detection AND
	// target-mtime evaluation; the two signals are mutually exclusive
	// because mtime requires the target to exist.
	info, err := os.Stat(m.resolve(target))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			out = append(out, core.SignalExecTargetOrphan)
		}
	} else {
		delta := m.opts.Now().Sub(info.ModTime().UTC())
		if delta >= 0 && delta < 7*24*time.Hour {
			out = append(out, core.SignalRecentTargetMtime7d)
		}
	}
	base := filepath.Base(target)
	if _, ok := shellInterps[base]; ok {
		out = append(out, core.SignalShellIndirect)
	}
	return out
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

// firstToken returns the first whitespace-separated token of a command.
// Quoting is intentionally NOT honored in v0.1.0; commands using shell
// quoting around the executable name are rare in cron and the
// unqualified_exec_target signal already flags them for backend review.
func firstToken(s string) string {
	for i, r := range s {
		if r == ' ' || r == '\t' {
			return s[:i]
		}
	}
	return s
}

// snippet returns the first 256 bytes of s, byte-truncated to keep the
// field bounded regardless of UTF-8 boundaries.
func snippet(s string) string {
	const max = 256
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// errnoCode returns the POSIX errno mnemonic for an os error when
// detectable, otherwise "IO_ERROR". Used to populate RecordError.Code.
func errnoCode(err error) string {
	if errors.Is(err, fs.ErrNotExist) {
		return "ENOENT"
	}
	if errors.Is(err, fs.ErrPermission) {
		return "EACCES"
	}
	return "IO_ERROR"
}

// collectPeriodicDir walks one of /etc/cron.{hourly,daily,weekly,monthly}.
// One Record per regular file; the file IS the executable.
func (m *Module) collectPeriodicDir(ctx context.Context, logicalDir string, emit func(core.Record)) error {
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
		// Follow symlinks for hashing but keep locus = logical.
		if info.Mode()&os.ModeSymlink != 0 {
			info, err = os.Stat(real)
			if err != nil {
				continue
			}
		}
		if !info.Mode().IsRegular() {
			continue
		}
		m.processPeriodicFile(ctx, logical, real, info, emit)
	}
	return nil
}

// processPeriodicFile emits one Record per script. Normalization for
// cron.periodic is identity (the file is a script, not a crontab),
// so content_norm_sha256 == content_sha256.
func (m *Module) processPeriodicFile(ctx context.Context, logical, real string, info os.FileInfo, emit func(core.Record)) {
	const siteClass = "cron.periodic"
	if info.Size() > m.opts.MaxFileSize {
		emit(m.envelopeRecord(logical, info, siteClass, []core.RecordError{
			{Field: "content_sha256", Code: "SIZE_LIMIT"},
		}, nil))
		return
	}
	raw, err := core.ReadFileCapped(real, m.opts.MaxFileSize)
	if err != nil {
		emit(m.envelopeRecord(logical, info, siteClass, []core.RecordError{
			{Field: "content_sha256", Code: errnoCode(err), Msg: err.Error()},
		}, nil))
		return
	}

	rec := core.Record{
		Module:    m.Name(),
		SiteClass: siteClass,
		MITRE:     []string{mitreCron},
		Locus:     logical,
	}
	core.FillFileMeta(&rec, info)
	rec.ContentSHA256 = core.HashHex(raw)
	rec.ContentNormSHA256 = rec.ContentSHA256
	rec.ContentSnippet = snippet(string(raw))
	rec.ExecTarget = logical
	rec.ExecTargetSHA256 = rec.ContentSHA256

	signals := m.baseSignals(info, logical)
	if len(raw) == 0 {
		signals = append(signals, core.SignalEmptyFile)
	}
	if info.Mode().Perm()&0o111 == 0 {
		rec.Errors = append(rec.Errors, core.RecordError{
			Field: "mode", Code: "NOT_EXECUTABLE",
		})
	}
	rec.Signals = core.DedupSignals(signals)
	core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
	core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
	emit(rec)
}

// collectAnacrontab parses /etc/anacrontab. Format per anacrontab(5):
//
//	period delay job-identifier command
//	@period delay job-identifier command
//
// Lines that match VAR=VALUE before the first schedule line are
// variable assignments. Same site_class shape as cron.d in terms of
// per-line records.
func (m *Module) collectAnacrontab(ctx context.Context, logical string, emit func(core.Record)) error {
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
	const siteClass = "cron.anacron"
	if info.Size() > m.opts.MaxFileSize {
		emit(m.envelopeRecord(logical, info, siteClass, []core.RecordError{
			{Field: "content_sha256", Code: "SIZE_LIMIT"},
		}, nil))
		return nil
	}
	raw, err := core.ReadFileCapped(real, m.opts.MaxFileSize)
	if err != nil {
		emit(m.envelopeRecord(logical, info, siteClass, []core.RecordError{
			{Field: "content_sha256", Code: errnoCode(err), Msg: err.Error()},
		}, nil))
		return nil
	}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if ctx.Err() != nil {
			return nil
		}
		line := sc.Text()
		if isLeadingComment(line) {
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		pl := parseAnacrontabLine(line)
		if pl.kind == lineEmpty {
			continue
		}
		emit(m.recordFromParsedLine(logical, info, siteClass, pl))
	}
	return nil
}

// parseAnacrontabLine handles the 4-field anacrontab format:
// period delay jobid command. Variable assignments share format with
// crontab and reuse the same detector.
func parseAnacrontabLine(line string) parsedLine {
	line = stripInlineComment(line)
	if line == "" {
		return parsedLine{kind: lineEmpty}
	}
	if name, val, ok := tryVarAssignment(line); ok {
		return parsedLine{kind: lineVarAssignment, raw: line, varName: name, varValue: val}
	}
	fields := splitWS(line)
	if len(fields) < 4 {
		return parsedLine{kind: lineMalformed, raw: line, parseErr: "PARSE_ERROR"}
	}
	// period (numeric or @keyword), delay (numeric), jobid (identifier), command (rest)
	pl := parsedLine{
		kind:     lineScheduleEntry,
		raw:      line,
		schedule: fields[0] + " " + fields[1],
		user:     fields[2], // jobid stored in user slot for canonicalLine reuse
		command:  strings.Join(fields[3:], " "),
	}
	return pl
}
