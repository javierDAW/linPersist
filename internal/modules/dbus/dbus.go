// Package dbus implements the linpersist collector for D-Bus
// service-file persistence on Linux.
//
// Site_classes emitted:
//
//   - dbus.system    one record per *.service file under
//     /usr/share/dbus-1/system-services/ (and the
//     /etc/dbus-1/system-services/ override dir).
//     The system bus daemon dbus-daemon(1) reads these
//     INI-style files at startup and exec()s the
//     `Exec=` value with root privilege whenever a
//     client process requests the named bus name. An
//     attacker who can write one of these files gets
//     on-demand root code execution any time something
//     bus-activates the service — every desktop and
//     most server distros have at least one bus
//     client running constantly.
//
//   - dbus.session   same as dbus.system but for the session bus:
//     /usr/share/dbus-1/services/ and the user's
//     override dir. The activated process runs as
//     the user whose session bus called it; useful
//     for user-level persistence on workstations.
//
// MITRE T1543 (Create or Modify System Process). ATT&CK has no
// Linux-dbus sub-technique as of May 2026; documented in
// matrix.yaml notes alongside the netdispatch family.
//
// The .service file format is the freedesktop INI flavour: a single
// `[D-BUS Service]` section with `Name=`, `Exec=`, optional `User=`
// and `SystemdService=` keys. Parsing is shared with the freedesktop
// .desktop format used by the xdg module (both predate systemd unit
// files and share the syntax).
package dbus

import (
	"bufio"
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

const (
	mitreDBus = "T1543"

	siteClassSystem  = "dbus.system"
	siteClassSession = "dbus.session"
)

// systemServiceDirs are the directories scanned for system-bus
// service files. Distros honour both the /usr/share copy
// (package-managed) and the /etc copy (operator overrides).
var systemServiceDirs = []string{
	"/usr/share/dbus-1/system-services",
	"/etc/dbus-1/system-services",
}

// sessionServiceDirs are the equivalent for the session bus. Per-
// user override dirs (XDG_DATA_HOME) are intentionally NOT walked
// here — the agent emits records for system-wide and root-shipped
// session files; per-user dirs land under their own home walker if
// the operator chooses to extend the scope.
var sessionServiceDirs = []string{
	"/usr/share/dbus-1/services",
	"/etc/dbus-1/services",
}

// DefaultMaxFileSize bounds one .service file. Real entries are
// well under 1 KiB; 256 KiB is more than generous and matches the
// project-wide pattern.
const DefaultMaxFileSize = 256 * 1024

// Options configures the dbus module.
type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
	// Provenance annotates the Exec= path of each service. Vast
	// majority of dbus services on a stock system come from the
	// distro (PolicyKit, NetworkManager, ModemManager, accounts
	// daemon, etc.); non_package_path is therefore a high-signal
	// indicator on a default install.
	Provenance core.Provenance
	// LiveProcessSet check is informational for dbus: the service is
	// bus-activated, so it may or may not be running at snapshot
	// time. live_process_attached fires when the Exec target is
	// currently running.
	LiveProcessSet core.LiveProcessSet
}

// Module collects D-Bus service-file persistence sites.
type Module struct{ opts Options }

// New constructs a dbus Module with default fallbacks.
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
func (m *Module) Name() string { return "dbus" }

// SiteClasses returns both classes this module can emit.
func (m *Module) SiteClasses() []string {
	return []string{siteClassSystem, siteClassSession}
}

// Collect walks every configured directory and emits one record per
// .service file. Missing dirs are silent (most hosts have one or
// the other, not all four).
func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error
	for _, d := range systemServiceDirs {
		if err := m.walkDir(ctx, d, siteClassSystem, emit); err != nil {
			errs = append(errs, err)
		}
	}
	for _, d := range sessionServiceDirs {
		if err := m.walkDir(ctx, d, siteClassSession, emit); err != nil {
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

func (m *Module) walkDir(ctx context.Context, logicalDir, siteClass string, emit func(core.Record)) error {
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
		if !strings.HasSuffix(name, ".service") {
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
		m.processFile(ctx, logical, real, info, siteClass, emit)
	}
	return nil
}

func (m *Module) processFile(ctx context.Context, logical, real string, info os.FileInfo, siteClass string, emit func(core.Record)) {
	if info.Size() > m.opts.MaxFileSize {
		emit(m.envelopeRecord(logical, info, siteClass, []core.RecordError{
			{Field: "content_sha256", Code: "SIZE_LIMIT"},
		}))
		return
	}
	raw, err := core.ReadFileCapped(real, m.opts.MaxFileSize)
	if err != nil {
		emit(m.envelopeRecord(logical, info, siteClass, []core.RecordError{
			{Field: "content_sha256", Code: errnoCode(err), Msg: err.Error()},
		}))
		return
	}
	parsed := parseService(raw)
	canon := canonical(parsed)
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         siteClass,
		MITRE:             []string{mitreDBus},
		Locus:             logical,
		ContentSHA256:     core.HashHex(raw),
		ContentNormSHA256: core.HashHex([]byte(canon)),
		ContentSnippet:    snippet(canon),
	}
	core.FillFileMeta(&rec, info)
	signals := m.baseSignals(info, logical)

	// Extract argv[0] of the Exec= line as the persistence target.
	// dbus-daemon honours POSIX-sh quoting: if the value starts with
	// a quote, argv[0] is the content up to the matching close-quote
	// (path-with-spaces is legal). Otherwise argv[0] is everything
	// up to the first whitespace.
	exec := extractExecArg0(parsed["Exec"])
	if exec != "" {
		rec.ExecTarget = exec
		if !strings.HasPrefix(exec, "/") {
			signals = append(signals, core.SignalUnqualifiedExecTarget)
			if _, isShell := shellInterps[exec]; isShell {
				signals = append(signals, core.SignalShellIndirect)
			}
		} else {
			for _, prefix := range core.TmpDirs {
				if strings.HasPrefix(exec, prefix) {
					signals = append(signals, core.SignalInterpreterInTmp)
					break
				}
			}
			if _, err := os.Stat(m.resolve(exec)); err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					signals = append(signals, core.SignalExecTargetOrphan)
				}
			}
		}
		base := filepath.Base(exec)
		if _, isShell := shellInterps[base]; isShell {
			signals = append(signals, core.SignalShellIndirect)
		}
	}
	rec.Signals = core.DedupSignals(signals)
	core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
	core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
	emit(rec)
}

func (m *Module) envelopeRecord(logical string, info os.FileInfo, siteClass string, errs []core.RecordError) core.Record {
	rec := core.Record{
		Module:    m.Name(),
		SiteClass: siteClass,
		MITRE:     []string{mitreDBus},
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
		if st.Uid != 0 && isSystemPath(logical) {
			out = append(out, core.SignalNonRootOwner)
		}
	}
	return out
}

// parseService reads the INI-style body of a .service file and
// returns the key=value pairs found inside the [D-BUS Service]
// section. Other sections (and lines outside any section) are
// ignored; dbus-daemon does the same.
func parseService(raw []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 64*1024), 256*1024)
	inSection := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inSection = strings.EqualFold(line, "[D-BUS Service]")
			continue
		}
		if !inSection {
			continue
		}
		i := strings.IndexByte(line, '=')
		if i <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:i])
		val := strings.TrimSpace(line[i+1:])
		out[key] = val
	}
	return out
}

// canonical renders the parsed service as a deterministic byte
// stream for content_norm_sha256. Keys are sorted; only the keys
// that affect persistence semantics are included so cosmetic
// formatting drift across hosts collapses into one Q1 group.
func canonical(parsed map[string]string) string {
	keys := []string{"Name", "Exec", "User", "SystemdService"}
	var b strings.Builder
	for _, k := range keys {
		v, ok := parsed[k]
		if !ok {
			continue
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
		b.WriteByte('\n')
	}
	return b.String()
}

// shellInterps is the set of common Unix shell / interpreter
// basenames that indicate the Exec= value points at a wrapper
// rather than at the actual payload. Same list used by ssh / xdg.
var shellInterps = map[string]struct{}{
	"sh":     {},
	"bash":   {},
	"dash":   {},
	"zsh":    {},
	"ash":    {},
	"ksh":    {},
	"python": {}, "python2": {}, "python3": {},
	"perl": {}, "ruby": {}, "php": {}, "node": {}, "nodejs": {}, "lua": {},
}

// extractExecArg0 returns argv[0] of a freedesktop-style Exec value.
// If s starts with a single or double quote, argv[0] is the content
// up to the matching close-quote (a path that legitimately contains
// spaces). Otherwise argv[0] is everything up to the first
// whitespace. Returns "" for empty or unmatched-quote input — the
// caller treats both as "no exec target inferred".
func extractExecArg0(s string) string {
	s = strings.TrimLeft(s, " \t")
	if s == "" {
		return ""
	}
	c := s[0]
	if c == '"' || c == '\'' {
		if i := strings.IndexByte(s[1:], c); i >= 0 {
			return s[1 : 1+i]
		}
		return ""
	}
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			return s[:i]
		}
	}
	return s
}

// skipName mirrors the convention every other module uses: hide
// dotfiles, backup files, and dpkg/rpm leftovers.
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

func isSystemPath(p string) bool {
	for _, prefix := range []string{"/etc/", "/usr/", "/lib/", "/bin/", "/sbin/"} {
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
