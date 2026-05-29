// Package ssh implements the linpersist collector for SSH
// authorized-keys persistence on Linux.
//
// Site_class emitted by this module:
//
//   - ssh.authkeys   one record per non-comment, non-blank key line
//     found in any of:
//     /etc/ssh/authorized_keys
//     /etc/ssh/authorized_keys.d/*
//     /root/.ssh/authorized_keys
//     /root/.ssh/authorized_keys2
//     /home/<user>/.ssh/authorized_keys
//     /home/<user>/.ssh/authorized_keys2
//
// MITRE ATT&CK T1098.004 (Account Manipulation: SSH Authorized Keys).
//
// Privacy policy (ADR-0003): the public-key blob is NEVER emitted
// as a string. Only its sha256 lands in exec_target_sha256, and
// the 12-char prefix appears in content_snippet as
// "<sha256:abcdef012345>".
package ssh

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
const mitreSSHAuthKeys = "T1098.004"

// Options configures a Module instance.
type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
	// Provenance annotates exec_target paths (forced commands) with
	// their owning package. Nil defaults to core.NoopProvenance.
	Provenance core.Provenance
	// LiveProcessSet membership check for the live_process_attached
	// signal. Nil defaults to core.NoopLiveProcessSet.
	LiveProcessSet core.LiveProcessSet
}

// DefaultMaxFileSize is generous; real-world authorized_keys files
// rarely exceed a few KiB.
const DefaultMaxFileSize = 1 << 20

// Module collects ssh.authkeys persistence artifacts.
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

// Name returns "ssh".
func (m *Module) Name() string { return "ssh" }

// SiteClasses returns the site_class values this module emits in v0.1.0.
// sshd.config will land in a follow-up iteration as a separate
// site_class.
func (m *Module) SiteClasses() []string {
	return []string{"ssh.authkeys"}
}

// Collect walks every configured authorized_keys locus.
func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error

	// /etc/ssh/authorized_keys (used by AuthorizedKeysFile when configured
	// to read from a shared file). Rare but legal.
	if err := m.collectAuthkeysFile(ctx, "/etc/ssh/authorized_keys", emit); err != nil {
		errs = append(errs, err)
	}
	// /etc/ssh/authorized_keys.d/<user> drop-in directory.
	if err := m.collectAuthkeysDir(ctx, "/etc/ssh/authorized_keys.d", emit); err != nil {
		errs = append(errs, err)
	}
	// /root/.ssh/authorized_keys{,2}
	for _, name := range []string{"authorized_keys", "authorized_keys2"} {
		if err := m.collectAuthkeysFile(ctx, filepath.Join("/root/.ssh", name), emit); err != nil {
			errs = append(errs, err)
		}
	}
	// /home/<user>/.ssh/authorized_keys{,2}
	if err := m.collectHomeAuthkeys(ctx, "/home", emit); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// resolve prepends Options.Root to a logical path for unit tests.
func (m *Module) resolve(logical string) string {
	if m.opts.Root == "" {
		return logical
	}
	return filepath.Join(m.opts.Root, logical)
}

// collectAuthkeysFile reads a single authorized_keys file and emits
// one record per non-comment, non-blank line.
func (m *Module) collectAuthkeysFile(ctx context.Context, logical string, emit func(core.Record)) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	real := m.resolve(logical)
	info, err := os.Lstat(real)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		// EACCES surfaces as an envelope record; other errors propagate.
		if errors.Is(err, fs.ErrPermission) {
			emit(m.envelopeRecord(logical, nil, []core.RecordError{
				{Field: "content_sha256", Code: "EACCES", Msg: err.Error()},
			}))
			return nil
		}
		return fmt.Errorf("lstat %s: %w", logical, err)
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	m.processAuthkeysFile(ctx, logical, real, info, emit)
	return nil
}

// collectAuthkeysDir walks /etc/ssh/authorized_keys.d and processes
// each regular file inside as a separate locus.
func (m *Module) collectAuthkeysDir(ctx context.Context, logicalDir string, emit func(core.Record)) error {
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
		m.processAuthkeysFile(ctx, logical, real, info, emit)
	}
	return nil
}

// collectHomeAuthkeys enumerates /home/, and for each subdir
// attempts to read .ssh/authorized_keys and .ssh/authorized_keys2.
// Missing or unreadable files are tolerated silently per-user
// (an EACCES surfaces as an envelope record).
func (m *Module) collectHomeAuthkeys(ctx context.Context, logicalDir string, emit func(core.Record)) error {
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
		for _, name := range []string{"authorized_keys", "authorized_keys2"} {
			logical := filepath.Join(logicalDir, e.Name(), ".ssh", name)
			if err := m.collectAuthkeysFile(ctx, logical, emit); err != nil {
				// best-effort: log via the errors join would be nicer but
				// keeps the per-user walk inside Collect's error budget
				_ = err
			}
		}
	}
	return nil
}

// processAuthkeysFile reads the file, scans non-comment non-blank
// lines, parses each, and emits one record per well-formed key line.
// Malformed lines are silently skipped in v0.1.0.
func (m *Module) processAuthkeysFile(ctx context.Context, logical, real string, info os.FileInfo, emit func(core.Record)) {
	const siteClass = "ssh.authkeys"
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
		return
	}

	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if ctx.Err() != nil {
			return
		}
		rawLine := sc.Text()
		pk, ok := parseAuthKeyLine(rawLine)
		if !ok {
			continue
		}
		emit(m.recordFromAuthKey(logical, info, siteClass, pk))
	}
}

// recordFromAuthKey builds the per-key Record. ADR-0003 governs
// every field that touches the blob.
func (m *Module) recordFromAuthKey(logical string, info os.FileInfo, siteClass string, pk parsedAuthKey) core.Record {
	targetSHA := core.HashHex(pk.blobBytes)
	prefix12 := targetSHA[:12]

	csInput := reconstructLine(pk.rawOpts, pk.keytype, prefix12, pk.comment)
	cnsInput := reconstructLine(pk.canonOpts, pk.keytype, prefix12, "")

	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         siteClass,
		MITRE:             []string{mitreSSHAuthKeys},
		Locus:             logical,
		ContentSHA256:     core.HashHexString(csInput),
		ContentNormSHA256: core.HashHexString(cnsInput),
		ContentSnippet:    csInput,
		ExecTargetSHA256:  targetSHA,
	}
	// exec_target is argv[0] of the forced command (the binary that
	// sshd actually executes), NOT the full command string with all
	// arguments. Capturing the full string defeats provenance lookup
	// (the dpkg manifest has /usr/bin/rsync, not "rsync --server
	// --sender -v..." as a path) and pollutes Q11's stacking by
	// treating every distinct invocation as a unique non-package
	// path. See lab-realistic v0.2.0 report Q6/Q11.
	if pk.command != "" {
		rec.ExecTarget = firstCommandToken(pk.command)
	}
	core.FillFileMeta(&rec, info)

	signals := m.baseSignals(info, logical)
	if pk.rawOpts != "" {
		signals = append(signals, core.SignalSSHOptionsPresent)
	}
	if pk.command != "" {
		signals = append(signals, core.SignalSSHForcedCommand)
	}
	signals = append(signals, m.execTargetSignals(rec.ExecTarget)...)
	if m.targetMtimeRecent(rec.ExecTarget) {
		signals = append(signals, core.SignalRecentTargetMtime7d)
	}
	rec.Signals = core.DedupSignals(signals)
	core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
	core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
	return rec
}

// firstCommandToken returns the first whitespace-delimited token of
// cmd, with surrounding double quotes stripped. Single quotes are NOT
// special in sshd_config Command= values per sshd(8) -- the parser
// is shell-like but limited. Returns "" if cmd is empty.
//
// Matches the parsing minimalism used by xdg.normalize.firstArg.
// Does NOT implement full shell escape handling: the persistence
// signal that matters is the binary the forced command runs, not
// its arguments.
func firstCommandToken(cmd string) string {
	cmd = strings.TrimLeft(cmd, " \t")
	if cmd == "" {
		return ""
	}
	if cmd[0] == '"' {
		end := strings.IndexByte(cmd[1:], '"')
		if end < 0 {
			return strings.Trim(cmd, `"`)
		}
		return cmd[1 : 1+end]
	}
	if idx := strings.IndexAny(cmd, " \t"); idx >= 0 {
		return cmd[:idx]
	}
	return cmd
}

// envelopeRecord builds a record that represents the file itself
// rather than a parsed line. info may be nil when even Lstat failed.
func (m *Module) envelopeRecord(logical string, info os.FileInfo, errs []core.RecordError) core.Record {
	rec := core.Record{
		Module:    m.Name(),
		SiteClass: "ssh.authkeys",
		MITRE:     []string{mitreSSHAuthKeys},
		Locus:     logical,
		Errors:    errs,
	}
	if info != nil {
		core.FillFileMeta(&rec, info)
		rec.Signals = core.DedupSignals(m.baseSignals(info, logical))
	}
	return rec
}

// baseSignals returns the per-file signals.
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

// execTargetSignals derives signals from a forced-command path.
// Returns no signals when target is empty (the most common case --
// most authorized_keys lines have no command="...").
func (m *Module) execTargetSignals(target string) []string {
	var out []string
	if target == "" {
		return out
	}
	for _, prefix := range core.TmpDirs {
		if strings.HasPrefix(target, prefix) {
			out = append(out, core.SignalInterpreterInTmp)
			break
		}
	}
	if strings.HasPrefix(target, "/") {
		if _, err := os.Stat(m.resolve(target)); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				out = append(out, core.SignalExecTargetOrphan)
			}
		}
	}
	return out
}

// targetMtimeRecent reports whether the resolved forced-command
// has an mtime within the last 7 days. Returns false when target
// is empty, missing, or not a regular file.
func (m *Module) targetMtimeRecent(target string) bool {
	if target == "" || !strings.HasPrefix(target, "/") {
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
// /sbin where uid != 0 ownership is anomalous. /root and /home are
// NOT system paths -- ownership on user homes is naturally non-root.
func isSystemPath(p string) bool {
	for _, prefix := range []string{"/etc/", "/usr/", "/lib/", "/bin/", "/sbin/"} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// skipDirEntry skips dotfiles, editor backups and packaging detritus.
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

// errnoCode maps an os error to a short code for Record.Errors.
func errnoCode(err error) string {
	if errors.Is(err, fs.ErrNotExist) {
		return "ENOENT"
	}
	if errors.Is(err, fs.ErrPermission) {
		return "EACCES"
	}
	return "IO_ERROR"
}
