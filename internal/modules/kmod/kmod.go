// Package kmod implements the linpersist collector for kernel-module
// auto-load and modprobe configuration persistence on Linux.
//
// Site_class emitted:
//
//   - kmod   /etc/modules, /etc/modules-load.d/*.conf,
//     /usr/lib/modules-load.d/*.conf, /run/modules-load.d/*.conf,
//     /etc/modprobe.d/*.conf, /lib/modprobe.d/*.conf,
//     /usr/lib/modprobe.d/*.conf, /run/modprobe.d/*.conf.
//
// Per-directive (per-line) record granularity. Each non-comment
// non-blank logical line in any of the loci files is emitted as its
// own record so the backend can stack on individual directives. The
// canonical form lowercases the first token, collapses runs of
// internal whitespace to a single space, and strips comment + blank
// lines + trailing whitespace; line continuations (`\` at EOL) are
// joined before canonicalization.
//
// MITRE T1547.006 (Boot or Logon Autostart Execution: Kernel Modules
// and Extensions). The `install` directive in modprobe.d is the
// textbook offensive vector: `install foo /bin/sh -c '...'` runs the
// command instead of loading the module.
package kmod

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

const mitreKmod = "T1547.006"

// staticListFiles are single-path module-load list files (one
// module name per line).
var staticListFiles = []string{
	"/etc/modules",
}

// modulesLoadDirs hold *.conf files where each line names a module
// to auto-load via systemd-modules-load.
var modulesLoadDirs = []string{
	"/etc/modules-load.d",
	"/usr/lib/modules-load.d",
	"/run/modules-load.d",
}

// modprobeDirs hold *.conf files where each line is a modprobe(5)
// directive (alias, blacklist, install, options, remove, softdep).
var modprobeDirs = []string{
	"/etc/modprobe.d",
	"/lib/modprobe.d",
	"/usr/lib/modprobe.d",
	"/run/modprobe.d",
}

// Options configures the kmod module.
type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
	// Provenance annotates exec_target paths (install/options/blacklist
	// directives that name a binary) with their owning package. Nil
	// defaults to core.NoopProvenance.
	Provenance core.Provenance
	// LiveProcessSet membership check for the live_process_attached
	// signal. An install directive whose argv[0] is currently running
	// indicates the modprobe-time payload is active right now.
	LiveProcessSet core.LiveProcessSet
}

const DefaultMaxFileSize = 1 << 20

// Module collects kernel-module persistence sites.
type Module struct {
	opts Options

	// koIndex maps a kernel-module name to the logical path of its
	// compiled .ko, parsed once from /lib/modules/<ver>/modules.dep.
	// Lets an autoload/options/softdep directive resolve to a real file
	// for provenance without walking the whole /lib/modules tree.
	koOnce  sync.Once
	koIndex map[string]string
}

// moduleKOPath returns the logical .ko path for a module name, or "".
// The index is built lazily from every /lib/modules/<ver>/modules.dep:
// each left-hand-side entry "kernel/.../foo.ko[.xz]:" maps basename
// "foo" -> "/lib/modules/<ver>/kernel/.../foo.ko[.xz]". First-wins.
func (m *Module) moduleKOPath(name string) string {
	m.koOnce.Do(func() {
		m.koIndex = map[string]string{}
		vers, err := os.ReadDir(m.resolve("/lib/modules"))
		if err != nil {
			return
		}
		for _, v := range vers {
			if !v.IsDir() {
				continue
			}
			depLogical := filepath.Join("/lib/modules", v.Name(), "modules.dep")
			data, err := core.ReadFileCapped(m.resolve(depLogical), 64*1024*1024)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				colon := strings.IndexByte(line, ':')
				if colon <= 0 {
					continue
				}
				rel := strings.TrimSpace(line[:colon])
				base := filepath.Base(rel)
				base = strings.TrimSuffix(base, ".xz")
				base = strings.TrimSuffix(base, ".zst")
				base = strings.TrimSuffix(base, ".gz")
				base = strings.TrimSuffix(base, ".ko")
				name := normalizeModName(base)
				if name == "" {
					continue
				}
				if _, dup := m.koIndex[name]; !dup {
					m.koIndex[name] = filepath.Join("/lib/modules", v.Name(), rel)
				}
			}
		}
	})
	return m.koIndex[normalizeModName(name)]
}

// normalizeModName canonicalizes a module name: kernel/modprobe treat
// '-' and '_' interchangeably, so the index and lookups use '_'.
func normalizeModName(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "-", "_")
}

// resolveModuleKO sets rec.ExecTarget to the named module's compiled .ko
// (and hashes it) when the module resolves via modules.dep, so the
// trailing AnnotateExecTargetProvenance flags a package-unowned .ko.
func (m *Module) resolveModuleKO(rec *core.Record, modName string) {
	ko := m.moduleKOPath(modName)
	if ko == "" {
		return
	}
	rec.ExecTarget = ko
	if sum, ok := core.HashFileCapped(m.resolve(ko), m.opts.MaxFileSize); ok {
		rec.ExecTargetSHA256 = sum
	}
}

// New constructs a kmod Module.
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

func (m *Module) Name() string          { return "kmod" }
func (m *Module) SiteClasses() []string { return []string{"kmod"} }

// Collect walks every locus and emits one record per directive line.
func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error
	for _, p := range staticListFiles {
		if err := m.collectListFile(ctx, p, emit); err != nil {
			errs = append(errs, err)
		}
	}
	for _, dir := range modulesLoadDirs {
		if err := m.walkDir(ctx, dir, kindModulesLoad, emit); err != nil {
			errs = append(errs, err)
		}
	}
	for _, dir := range modprobeDirs {
		if err := m.walkDir(ctx, dir, kindModprobe, emit); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// lineKind selects the per-line interpreter used for a given file
// family.
type lineKind int

const (
	// kindModulesList is /etc/modules or /etc/modules-load.d/*: each
	// non-comment line is a module name + optional kernel args.
	kindModulesList lineKind = iota
	// kindModulesLoad is identical to kindModulesList; the distinct
	// constant exists so the constant set lines up with the loci
	// families if future divergence is needed.
	kindModulesLoad
	// kindModprobe is /etc/modprobe.d/* and friends: each
	// non-comment logical line is a modprobe(5) directive.
	kindModprobe
)

func (m *Module) resolve(logical string) string {
	if m.opts.Root == "" {
		return logical
	}
	return filepath.Join(m.opts.Root, logical)
}

func (m *Module) collectListFile(ctx context.Context, logical string, emit func(core.Record)) error {
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
	m.processFile(ctx, logical, real, info, kindModulesList, emit)
	return nil
}

func (m *Module) walkDir(ctx context.Context, logicalDir string, kind lineKind, emit func(core.Record)) error {
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
		if skipName(name) {
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
		m.processFile(ctx, logical, real, info, kind, emit)
	}
	return nil
}

func (m *Module) processFile(ctx context.Context, logical, real string, info os.FileInfo, kind lineKind, emit func(core.Record)) {
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
	for _, line := range parseLogicalLines(raw) {
		rec := m.buildRecord(logical, info, line, kind)
		emit(rec)
	}
}

func (m *Module) buildRecord(logical string, info os.FileInfo, raw string, kind lineKind) core.Record {
	canon := normalizeLine(raw, kind)
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         "kmod",
		MITRE:             []string{mitreKmod},
		Locus:             logical,
		ContentSHA256:     core.HashHexString(raw + "\n"),
		ContentNormSHA256: core.HashHexString(canon + "\n"),
		ContentSnippet:    snippet(canon),
	}
	core.FillFileMeta(&rec, info)
	rec.Signals = m.baseSignals(info)

	// Directive-specific signals + exec_target.
	verb, rest := splitFirstToken(canon)
	switch kind {
	case kindModprobe:
		switch verb {
		case "install":
			// rest = "<module-name> <command...>". argv[0] of the
			// command is the second token of rest.
			_, cmd := splitFirstToken(rest)
			if cmd != "" {
				et, _ := splitFirstToken(cmd)
				if et != "" && !isModprobeSelfCall(et) {
					// The kmod_install_directive signal and the
					// exec_target enrichments only fire when argv[0]
					// is NOT modprobe itself. The recursive form
					// (`install snd-trident /sbin/modprobe
					// --ignore-install ...`) is a baseline pattern
					// shipped by every distro's alsa / dm-mod /
					// nvidia kernel config and is not a persistence
					// vector. The implant pattern is argv[0] being a
					// shell, an interpreter, or any other binary;
					// those still surface.
					rec.Signals = appendUnique(rec.Signals,
						core.SignalKmodInstallDirective)
					rec.ExecTarget = et
					if strings.HasPrefix(et, "/") {
						if sum, ok := core.HashFileCapped(m.resolve(et), m.opts.MaxFileSize); ok {
							rec.ExecTargetSHA256 = sum
						}
					}
					rec.Signals = m.execTargetSignals(rec.Signals, et)
				}
			}
		case "blacklist":
			rec.Signals = appendUnique(rec.Signals, core.SignalKmodBlacklistDirective)
		case "options", "softdep":
			// rest's first token is the module the directive configures;
			// resolve it to its .ko so a directive referencing a planted,
			// package-unowned module surfaces via non_package_path.
			if mod, _ := splitFirstToken(rest); mod != "" {
				m.resolveModuleKO(&rec, mod)
			}
		}
	default:
		// kindModulesList / kindModulesLoad: a bare module name (+ optional
		// params) scheduled to auto-load at boot. Resolve it to its .ko and
		// flag the autoload so a non-package .ko (planted LKM) surfaces.
		if mod, _ := splitFirstToken(canon); mod != "" {
			rec.Signals = appendUnique(rec.Signals, core.SignalKmodAutoload)
			m.resolveModuleKO(&rec, mod)
		}
	}

	core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
	core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
	return rec
}

func (m *Module) envelopeRecord(logical string, info os.FileInfo, errs []core.RecordError) core.Record {
	rec := core.Record{
		Module:    m.Name(),
		SiteClass: "kmod",
		MITRE:     []string{mitreKmod},
		Locus:     logical,
		Errors:    errs,
	}
	core.FillFileMeta(&rec, info)
	rec.Signals = m.baseSignals(info)
	return rec
}

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

func (m *Module) execTargetSignals(in []string, target string) []string {
	out := in
	if !filepath.IsAbs(target) {
		out = appendUnique(out, core.SignalUnqualifiedExecTarget)
		return out
	}
	if isInterpreterInTmp(target) {
		out = appendUnique(out, core.SignalInterpreterInTmp)
	}
	if isShellInterpreter(target) {
		out = appendUnique(out, core.SignalShellIndirect)
	}
	// Orphan / recent-mtime checks on the exec_target file itself.
	info, err := os.Stat(m.resolve(target))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		out = appendUnique(out, core.SignalExecTargetOrphan)
	case err == nil:
		delta := m.opts.Now().Sub(info.ModTime().UTC())
		if delta >= 0 && delta < 7*24*time.Hour {
			out = appendUnique(out, core.SignalRecentTargetMtime7d)
		}
	}
	return out
}

// parseLogicalLines walks the raw file bytes, joins backslash line
// continuations, drops comment-only and blank logical lines, and
// returns the surviving lines as plain strings (no trailing newline).
func parseLogicalLines(raw []byte) []string {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var physical []string
	for sc.Scan() {
		physical = append(physical, sc.Text())
	}
	var logical []string
	i := 0
	for i < len(physical) {
		text := physical[i]
		for {
			trimmed := strings.TrimRight(text, " \t")
			if !strings.HasSuffix(trimmed, "\\") {
				break
			}
			if i+1 >= len(physical) {
				text = trimmed[:len(trimmed)-1]
				break
			}
			text = trimmed[:len(trimmed)-1]
			i++
			text += physical[i]
		}
		t := strings.TrimSpace(text)
		if t == "" || strings.HasPrefix(t, "#") {
			i++
			continue
		}
		logical = append(logical, text)
		i++
	}
	return logical
}

// splitFirstToken returns the first whitespace-separated token and the
// remainder of s, both trimmed.
func splitFirstToken(s string) (first, rest string) {
	s = strings.TrimLeft(s, " \t")
	idx := strings.IndexAny(s, " \t")
	if idx < 0 {
		return s, ""
	}
	return s[:idx], strings.TrimLeft(s[idx:], " \t")
}

// isModprobeSelfCall returns true if argv[0] of a modprobe `install`
// directive's replacement command is the modprobe binary itself.
// Distros ship recursive-modprobe install lines for hardware aliases
// (e.g. /lib/modprobe.d/dist-alsa.conf carries
// `install snd-trident /sbin/modprobe --ignore-install snd-pcm ...`).
// These are baseline configuration, not persistence vectors, and
// firing kmod_install_directive on them generates Q7 / Q11 noise
// proportional to host count. Both the historical /sbin/modprobe
// and the usr-merged /usr/sbin/modprobe forms are recognised.
func isModprobeSelfCall(argv0 string) bool {
	return argv0 == "/sbin/modprobe" || argv0 == "/usr/sbin/modprobe"
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

func isInterpreterInTmp(p string) bool {
	switch {
	case strings.HasPrefix(p, "/tmp/"),
		strings.HasPrefix(p, "/var/tmp/"),
		strings.HasPrefix(p, "/dev/shm/"),
		strings.HasPrefix(p, "/run/shm/"):
		return true
	}
	return false
}

func isShellInterpreter(p string) bool {
	base := filepath.Base(p)
	switch base {
	case "sh", "bash", "dash", "zsh", "ash", "ksh",
		"python", "python2", "python3",
		"perl", "ruby", "php", "node", "nodejs", "lua":
		return true
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
