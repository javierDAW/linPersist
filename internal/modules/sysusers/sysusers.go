// Package sysusers implements the linpersist collector for
// systemd-sysusers configuration -- the boot-time mechanism systemd
// uses to declaratively create system users and groups without
// editing /etc/passwd or /etc/group directly.
//
// Site_class emitted:
//
//   - systemd.sysusers   /etc/sysusers.d/*.conf and
//     /usr/lib/sysusers.d/*.conf. Per-directive granularity. A
//     directive that creates a uid-0 user with a non-"root" name
//     hides a second root account from the passwd module's view if
//     /etc/passwd is empty -- documented sub-vector of T1136.001
//     (Local Account creation).
//
// Format per sysusers.d(5): each non-comment, non-blank line is
//
//	type name id "gecos" home shell
//
// Type letter is one of u (user), g (group), m (membership), r
// (range reservation). The id field carries the uid (for u) or gid
// (for g); a literal "-" means "let systemd pick".
//
// MITRE T1136.001 (Local Account creation, parent technique
// already used by the passwd module). Pair this site_class with
// the passwd module's findings: a sysusers.d directive that creates
// a uid-0 non-root account AND a corresponding passwd.user entry
// is the redundant double-write attack pattern.
package sysusers

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
	siteClass = "systemd.sysusers"
	mitre     = "T1136.001"
)

var loci = []string{
	"/etc/sysusers.d",
	"/usr/lib/sysusers.d",
}

// Options configures a Module instance.
type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
}

// DefaultMaxFileSize caps each sysusers.d source at 64 KiB.
const DefaultMaxFileSize = 64 << 10

// Module collects systemd-sysusers directives.
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

func (m *Module) Name() string          { return "sysusers" }
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
		emit(m.envelope(logical, info, nil))
	}
}

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
	fillFileMeta(&rec, info)
	signals := m.baseSignals(info, logical)
	signals = append(signals, directiveSignals(fields)...)
	rec.Signals = dedupSignals(signals)
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
		fillFileMeta(&rec, info)
		rec.Signals = dedupSignals(append(m.baseSignals(info, logical), core.SignalEmptyFile))
	}
	return rec
}

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

// directiveSignals fires module-specific signals based on parsed
// fields. Format: type name id "gecos" home shell.
// We fire sysusers_uid_zero when type==u AND id=="0" AND name!="root".
func directiveSignals(fields []string) []string {
	var out []string
	if len(fields) < 3 {
		return out
	}
	if fields[0] != "u" {
		return out
	}
	name := fields[1]
	id := fields[2]
	if id == "0" && name != "root" {
		out = append(out, core.SignalSysusersUIDZero)
	}
	return out
}

// parseFields splits a sysusers directive into whitespace-separated
// fields, respecting double-quoted segments (for the gecos field).
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
