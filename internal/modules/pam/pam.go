// Package pam implements the linpersist collector for PAM
// authentication-stack persistence on Linux.
//
// Site_class emitted: pam (MITRE T1556.003).
// Loci:
//
//   - /etc/pam.conf            (legacy single-file format)
//   - /etc/pam.d/<service>/*   (modern per-service drop-in files)
//
// Per-line granularity. exec_target is the module path; core signals
// (exec_target_orphan, interpreter_in_tmp, recent_target_mtime_7d)
// cover the textbook implant pattern: attacker drops a .so under /tmp
// and references it from /etc/pam.d/<some-service>.
package pam

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

const mitrePAM = "T1556.003"

var tmpDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"}

type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
	// Provenance annotates exec_target (the resolved module-path) with
	// its owning package. Nil defaults to core.NoopProvenance.
	Provenance core.Provenance
	// LiveProcessSet membership check for the live_process_attached
	// signal. PAM modules are .so files loaded by sshd/login/sudo, not
	// standalone executables, so this rarely fires; included for API
	// symmetry and to catch the unusual case of a PAM module path
	// that happens to also be an /proc/<pid>/exe target.
	LiveProcessSet core.LiveProcessSet
}

const DefaultMaxFileSize = 1 << 20

type Module struct {
	opts Options
}

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

var _ core.Module = (*Module)(nil)

func (m *Module) Name() string { return "pam" }

func (m *Module) SiteClasses() []string { return []string{"pam"} }

func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error
	if err := m.collectPamConf(ctx, "/etc/pam.conf", emit); err != nil {
		errs = append(errs, err)
	}
	if err := m.collectPamD(ctx, "/etc/pam.d", emit); err != nil {
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

func (m *Module) collectPamConf(ctx context.Context, logical string, emit func(core.Record)) error {
	raw, info, err := m.readFile(ctx, logical, emit)
	if err != nil || raw == nil {
		return err
	}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if ctx.Err() != nil {
			return nil
		}
		pr, ok := parsePamConfLine(sc.Text())
		if !ok {
			continue
		}
		emit(m.recordFromRule(logical, info, pr))
	}
	return nil
}

func (m *Module) collectPamD(ctx context.Context, logicalDir string, emit func(core.Record)) error {
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
		m.processPamDFile(ctx, logical, real, info, emit)
	}
	return nil
}

func (m *Module) processPamDFile(ctx context.Context, logical, real string, info os.FileInfo, emit func(core.Record)) {
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
		pr, ok := parsePamDLine(sc.Text())
		if !ok {
			continue
		}
		emit(m.recordFromRule(logical, info, pr))
	}
}

// readFile is a small helper that handles ENOENT / SIZE_LIMIT /
// EACCES paths for /etc/pam.conf (the only single-file locus).
func (m *Module) readFile(ctx context.Context, logical string, emit func(core.Record)) ([]byte, os.FileInfo, error) {
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	real := m.resolve(logical)
	info, err := os.Lstat(real)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("lstat %s: %w", logical, err)
	}
	if !info.Mode().IsRegular() {
		return nil, nil, nil
	}
	if info.Size() > m.opts.MaxFileSize {
		emit(m.envelopeRecord(logical, info, []core.RecordError{
			{Field: "content_sha256", Code: "SIZE_LIMIT"},
		}))
		return nil, info, nil
	}
	raw, err := os.ReadFile(real)
	if err != nil {
		emit(m.envelopeRecord(logical, info, []core.RecordError{
			{Field: "content_sha256", Code: errnoCode(err), Msg: err.Error()},
		}))
		return nil, info, nil
	}
	if len(raw) == 0 {
		return nil, info, nil
	}
	return raw, info, nil
}

func (m *Module) recordFromRule(logical string, info os.FileInfo, pr pamRule) core.Record {
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         "pam",
		MITRE:             []string{mitrePAM},
		Locus:             logical,
		ContentSHA256:     core.HashHexString(pr.raw),
		ContentNormSHA256: core.HashHexString(pr.canon),
		ContentSnippet:    snippet(pr.canon),
		ExecTarget:        pr.module,
	}
	fillFileMeta(&rec, info)
	signals := m.baseSignals(info, logical)
	signals = append(signals, m.execTargetSignals(pr.module)...)
	if m.targetMtimeRecent(pr.module) {
		signals = append(signals, core.SignalRecentTargetMtime7d)
	}
	rec.Signals = dedupSignals(signals)
	core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
	core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
	return rec
}

func (m *Module) envelopeRecord(logical string, info os.FileInfo, errs []core.RecordError) core.Record {
	rec := core.Record{
		Module:    m.Name(),
		SiteClass: "pam",
		MITRE:     []string{mitrePAM},
		Locus:     logical,
		Errors:    errs,
	}
	if info != nil {
		fillFileMeta(&rec, info)
		rec.Signals = dedupSignals(m.baseSignals(info, logical))
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

func (m *Module) execTargetSignals(target string) []string {
	var out []string
	if target == "" || !strings.HasPrefix(target, "/") {
		return out
	}
	for _, prefix := range tmpDirs {
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
