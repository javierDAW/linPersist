// Package tmpfiles implements the linpersist collector for
// systemd-tmpfiles configuration -- the boot-time file creation
// mechanism that systemd uses to populate /var, /run and similar.
//
// Site_class emitted:
//
//   - systemd.tmpfiles   /etc/tmpfiles.d/*.conf, /usr/lib/tmpfiles.d/*.conf,
//     /run/tmpfiles.d/*.conf. Per-directive granularity. A line that
//     creates an executable under /tmp at boot (`f /tmp/.x/payload 0755
//     root root - <inline>`) is a known persistence pattern; the
//     dropped binary lives across reboots because systemd-tmpfiles
//     restores it on every boot.
//
// Format per tmpfiles.d(5): each non-comment, non-blank line is
//
//	type path mode user group age argument
//
// Type letters cover create/modify/copy/delete/etc. of files,
// directories, symlinks and FIFOs. Lines with trailing backslash
// are NOT joined (tmpfiles.d does not support continuations per
// the manpage).
//
// MITRE T1543.002 (Systemd Service is the closest documented
// sub-technique; tmpfiles is a sibling vector with no dedicated
// MITRE id as of May 2026).
package tmpfiles

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

const (
	siteClass = "systemd.tmpfiles"
	mitre     = "T1543.002"
)

// loci is the ordered list of tmpfiles.d source directories systemd
// scans. /etc takes precedence at runtime, then /run, then
// /usr/lib; we collect from all three.
var loci = []string{
	"/etc/tmpfiles.d",
	"/run/tmpfiles.d",
	"/usr/lib/tmpfiles.d",
}

// Options configures a Module instance.
type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
}

// DefaultMaxFileSize caps a single tmpfiles.d source at 256 KiB --
// the largest stock entry today is under 8 KiB.
const DefaultMaxFileSize = 256 << 10

// Module collects systemd-tmpfiles directives.
type Module struct{ opts Options }

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

var _ core.Module = (*Module)(nil)

func (m *Module) Name() string          { return "tmpfiles" }
func (m *Module) SiteClasses() []string { return []string{siteClass} }

func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error
	for _, dir := range loci {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := m.collectDir(ctx, dir, emit); err != nil {
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

func (m *Module) collectDir(ctx context.Context, logicalDir string, emit func(core.Record)) error {
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
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".conf") {
			continue
		}
		logical := filepath.Join(logicalDir, name)
		realPath := filepath.Join(realDir, name)
		info, err := os.Lstat(realPath)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		m.processFile(ctx, logical, realPath, info, emit)
	}
	return nil
}

func (m *Module) processFile(ctx context.Context, logical, real string, info os.FileInfo, emit func(core.Record)) {
	if info.Size() > m.opts.MaxFileSize {
		emit(m.envelope(logical, info, []core.RecordError{{Field: "content_sha256", Code: "SIZE_LIMIT"}}))
		return
	}
	f, err := os.Open(real)
	if err != nil {
		emit(m.envelope(logical, info, []core.RecordError{{Field: "content_sha256", Code: errnoCode(err), Msg: err.Error()}}))
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	any := false
	for sc.Scan() {
		if ctx.Err() != nil {
			return
		}
		raw := strings.TrimRight(sc.Text(), " \t\r")
		t := strings.TrimLeft(raw, " \t")
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		any = true
		emit(m.recordFromLine(logical, info, raw))
	}
	if !any {
		// Empty / all-comment file. Emit a single envelope record
		// so the analyst sees the file's presence in the dataset.
		emit(m.envelope(logical, info, nil))
	}
}

// recordFromLine builds one record per tmpfiles directive. Canonical
// form is the line with whitespace collapsed to a single space
// outside quoted segments; type and path are preserved verbatim.
func (m *Module) recordFromLine(logical string, info os.FileInfo, raw string) core.Record {
	canon := canonicalDirective(raw)
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         siteClass,
		MITRE:             []string{mitre},
		Locus:             logical,
		ContentSHA256:     core.HashHexString(raw),
		ContentNormSHA256: core.HashHexString(canon),
		ContentSnippet:    snippet(canon),
	}
	fields := parseFields(canon)
	// NOTE (v0.3.0 calibration): we used to assign fields[1] (the
	// path tmpfiles.d operates on) to ExecTarget so the standard
	// exec_target_orphan / interpreter_in_tmp helpers could enrich
	// the record. That mapping was wrong: ExecTarget by contract
	// means "the binary the persistence invokes", and tmpfiles.d
	// does not invoke a binary -- it just touches a path. The wrong
	// mapping polluted Q9 (exec_target_in_tmp) with hundreds of
	// baseline X11 / systemd-private / dnf paths. The tmpfiles-
	// specific signal directiveSignals() emits is sufficient on its
	// own; the target path remains visible in content_snippet.
	_ = fields
	core.FillFileMeta(&rec, info)
	signals := m.baseSignals(info, logical)
	signals = append(signals, directiveSignals(fields)...)
	rec.Signals = core.DedupSignals(signals)
	return rec
}

func (m *Module) envelope(logical string, info os.FileInfo, errs []core.RecordError) core.Record {
	rec := core.Record{
		Module:    m.Name(),
		SiteClass: siteClass,
		MITRE:     []string{mitre},
		Locus:     logical,
		Errors:    errs,
	}
	if info != nil {
		core.FillFileMeta(&rec, info)
		rec.Signals = core.DedupSignals(append(m.baseSignals(info, logical), core.SignalEmptyFile))
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

// directiveSignals fires module-specific signals from the parsed
// fields. fields[0] is the tmpfiles type letter, fields[1] is the
// target path; everything else is mode/user/group/age/argument.
//
// Calibration (v0.3.0-coverage): the v1 implementation flagged any
// create-class type letter targeting a tmp-class path. That fired
// 108 times across the 75-host lab fleet on stock baseline
// directives (X11 socket dirs, systemd-private sandbox dirs, dnf
// lock dirs). The refined rule below restricts the signal to:
//
//   - Type letters that create FILES (f, F, w, w+) -- not d/D (dirs)
//     since X11 sockets / systemd-private are dirs. L (symlinks),
//     C/c (copy), b/p (block/fifo) are also out: they are vendor
//     baseline patterns rather than implant ones.
//   - Path WITHOUT tmpfiles.d glob/template metacharacters
//     (*, ?, %, [, ]). systemd-private-%b-* and dnf*/locks/* are
//     templated by design; an attacker plants a fixed path.
//   - Path NOT in the well-known X11 socket-dir allow-list. These
//     are baseline-of-baseline (any host with xorg libs has them),
//     including container images that link against X11 indirectly.
//
// The pre-refinement, broader signal still fires informationally
// in Q5 (raw counts) because the catalog signal stays defined;
// the corresponding Q7 detection rule
// (tmpfiles_creates_payload_at_boot) only triggers on the refined
// subset.
func directiveSignals(fields []string) []string {
	var out []string
	if len(fields) < 2 {
		return out
	}
	typeCode := fields[0]
	path := fields[1]
	if len(typeCode) == 0 {
		return out
	}
	// Restrict to file-creating type letters. Strip any "+" or "!"
	// modifier suffix per tmpfiles.d(5) by looking at the first byte.
	first := typeCode[0]
	if first != 'f' && first != 'F' && first != 'w' {
		return out
	}
	// Reject glob / template paths -- baseline patterns.
	if strings.ContainsAny(path, "*?%[") {
		return out
	}
	// X11 socket dir allow-list: baseline-of-baseline across distros.
	for _, baseline := range []string{
		"/tmp/.X11-unix",
		"/tmp/.ICE-unix",
		"/tmp/.XIM-unix",
		"/tmp/.font-unix",
		"/tmp/.Test-unix",
	} {
		if path == baseline {
			return out
		}
	}
	// Finally, the implant fingerprint: a fixed file path under a
	// tmp-class directory created at boot.
	for _, p := range core.TmpDirs {
		if strings.HasPrefix(path, p) {
			out = append(out, core.SignalTmpfilesCreatesUnderTmp)
			return out
		}
	}
	return out
}

// parseFields splits a tmpfiles directive into whitespace-separated
// fields, respecting double-quoted segments. The grammar is per
// tmpfiles.d(5).
func parseFields(line string) []string {
	var out []string
	var b strings.Builder
	inQ := false
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			inQ = !inQ
		case (c == ' ' || c == '\t') && !inQ:
			flush()
		default:
			b.WriteByte(c)
		}
	}
	flush()
	return out
}

// canonicalDirective collapses whitespace outside quoted segments
// to a single space, strips trailing whitespace. Type letter and
// path stay verbatim so the LFA grouping captures
// "same-rule-different-comments".
func canonicalDirective(line string) string {
	line = strings.TrimSpace(line)
	var b strings.Builder
	inQ := false
	lastWS := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			inQ = !inQ
			b.WriteByte(c)
			lastWS = false
		case (c == ' ' || c == '\t') && !inQ:
			if !lastWS {
				b.WriteByte(' ')
				lastWS = true
			}
		default:
			b.WriteByte(c)
			lastWS = false
		}
	}
	return strings.TrimSpace(b.String())
}

func isSystemPath(p string) bool {
	for _, prefix := range []string{"/etc/", "/usr/", "/lib/", "/run/"} {
		if strings.HasPrefix(p, prefix) {
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
