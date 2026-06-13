// Package confexec collects "config-embedded exec-edge" persistence sites:
// configuration files whose grammar turns a string into a root-exec or
// dlopen edge that no dedicated module parses. The duel-3 red/blue duel
// showed this is an entire FAMILY of blind spots in a disk-walk collector
// — a parsed config's semantics ARE the persistence, yet the payload it
// points at is never lifted to a record, so it evades both per-record
// detection and LFA (the payload binary is package-owned and benign on its
// own; only the config edge naming it is malicious).
//
// The module is table-driven: each site is (site_class, MITRE, loci globs,
// grammar). A grammar reads one config file and yields zero or more exec
// EDGES — each an absolute command/.so path the config would run/load. The
// module lifts each edge to a record's ExecTarget and runs the SAME central
// provenance pipeline every other module uses (non_package_path /
// exec_target_orphan / recent_* / package_file_tampered), so a single
// per-site detection gated on the non-package/orphan co-indicator does the
// rest. The large legitimate populations (mailman pipe aliases, needrestart
// apt hooks, systemctl postrotate, packaged libnss_sss, stock sudoers.so)
// resolve OWNED and stay silent.
//
// Crucially a record is emitted ONLY when a grammar finds an exec edge, so
// a clean config (an /etc/aliases with no pipe alias, an /etc/nsswitch.conf
// with only vendor tokens) yields NOTHING — zero FP by construction, the
// same property the initramfs module's empty /etc dirs have.
//
// Sites covered (duel-3 backlog): mail aliases, incron, logrotate,
// package-manager hooks (apt/dnf/yum), sudo.conf plugins, NSS modules,
// X11 session scripts. Inline shell RHS (an EnvironmentFile body, a
// PROMPT_COMMAND) is NOT decoded — the documented inline-code boundary
// (scope.md 8.1); only a resolvable command/.so path is lifted.
package confexec

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

// Edge is one config-embedded exec edge: an absolute command or shared-object
// path the config file would run or dlopen, plus a short human snippet of the
// source directive for triage.
type Edge struct {
	Target  string
	Snippet string
}

// grammarFn parses one config file's bytes and returns the exec edges it
// declares. logical is the host-absolute path; m gives the grammar access
// to root resolution and the linker-path lib resolver (for NSS).
type grammarFn func(raw []byte, logical string, m *Module) []Edge

// site binds a site_class to its loci and grammar.
type site struct {
	class string
	mitre []string
	// loci are host-absolute glob patterns (filepath.Glob semantics, so
	// /home/*/.forward and /etc/apt/apt.conf.d/* both work). A bare path
	// with no metacharacter matches just that file.
	loci  []string
	parse grammarFn
}

// sites is the full table. Adding a persistence site = one entry + one
// grammar; the record/provenance/detection machinery is shared.
var sites = []site{
	{
		class: "mail.aliases",
		mitre: []string{"T1546.004"},
		loci:  []string{"/etc/aliases", "/etc/mail/aliases", "/root/.forward", "/home/*/.forward"},
		parse: parseAliases,
	},
	{
		class: "incron.d",
		mitre: []string{"T1053.003"},
		loci:  []string{"/etc/incron.d/*", "/var/spool/incron/*"},
		parse: parseIncron,
	},
	{
		// core.hooksPath redirect: git runs hooks from this dir on every
		// operation in scope — a quiet exec primitive on dev/CI/build hosts.
		class: "git.hookspath",
		mitre: []string{"T1546"},
		loci: []string{
			"/etc/gitconfig", "/root/.gitconfig", "/home/*/.gitconfig",
			"/root/.config/git/config", "/home/*/.config/git/config",
		},
		parse: parseGitConfig,
	},
	{
		class: "logrotate.d",
		mitre: []string{"T1546"},
		loci:  []string{"/etc/logrotate.conf", "/etc/logrotate.d/*"},
		parse: parseLogrotate,
	},
	{
		class: "pkgmgr.hook",
		mitre: []string{"T1546.016"},
		loci: []string{
			"/etc/apt/apt.conf", "/etc/apt/apt.conf.d/*",
			"/etc/dnf/plugins/post-transaction-actions.d/*.action",
			"/etc/yum/post-actions/*.action",
		},
		parse: parsePkgmgrHook,
	},
	{
		class: "sudo.conf.plugin",
		mitre: []string{"T1574"},
		loci:  []string{"/etc/sudo.conf"},
		parse: parseSudoConf,
	},
	{
		class: "nss.nsswitch",
		mitre: []string{"T1556"},
		loci:  []string{"/etc/nsswitch.conf"},
		parse: parseNsswitch,
	},
	{
		class: "php.ini",
		mitre: []string{"T1546"},
		loci: []string{
			"/etc/php.ini", "/etc/php/*/*/php.ini", "/etc/php*/php.ini", "/etc/php.d/*.ini",
		},
		parse: parsePhpIni,
	},
	{
		class: "environment.d",
		mitre: []string{"T1574.006"},
		loci: []string{
			"/etc/environment.d/*.conf", "/run/environment.d/*.conf",
			"/usr/lib/environment.d/*.conf",
			"/root/.config/environment.d/*.conf", "/home/*/.config/environment.d/*.conf",
		},
		parse: parseEnvironmentD,
	},
	{
		class: "xsession.d",
		mitre: []string{"T1037"},
		loci: []string{
			"/etc/X11/Xsession.d/*", "/etc/X11/xinit/xinitrc.d/*",
			"/root/.xprofile", "/home/*/.xprofile",
			"/root/.xsession", "/home/*/.xsession",
		},
		parse: parseShellBody,
	},
	{
		class: "maintscript.dpkg",
		mitre: []string{"T1546.016"},
		loci: []string{
			"/var/lib/dpkg/info/*.preinst", "/var/lib/dpkg/info/*.postinst",
			"/var/lib/dpkg/info/*.prerm", "/var/lib/dpkg/info/*.postrm",
			"/var/lib/dpkg/info/*.config",
		},
		parse: parseMaintscript,
	},
}

// DefaultMaxFileSize bounds one config file read.
const DefaultMaxFileSize = 1 << 20

// Options configures the confexec module.
type Options struct {
	Root           string
	Now            func() time.Time
	MaxFileSize    int64
	Provenance     core.Provenance
	LiveProcessSet core.LiveProcessSet
}

// Module collects config-embedded exec-edge persistence sites.
type Module struct {
	opts Options

	stdLibDirs    []string
	stdLibDirsSet bool
}

// New constructs a confexec Module with default fallbacks.
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

func (m *Module) Name() string { return "confexec" }

func (m *Module) SiteClasses() []string {
	out := make([]string, 0, len(sites))
	for _, s := range sites {
		out = append(out, s.class)
	}
	return out
}

func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error
	for _, s := range sites {
		if err := m.collectSite(ctx, s, emit); err != nil {
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

func (m *Module) logicalize(real string) string {
	if m.opts.Root == "" {
		return real
	}
	rel, err := filepath.Rel(m.opts.Root, real)
	if err != nil {
		return real
	}
	return "/" + rel
}

func (m *Module) collectSite(ctx context.Context, s site, emit func(core.Record)) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	seen := map[string]struct{}{}
	for _, pattern := range s.loci {
		matches, err := filepath.Glob(m.resolve(pattern))
		if err != nil {
			continue // bad pattern; skip
		}
		sort.Strings(matches)
		for _, real := range matches {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if _, dup := seen[real]; dup {
				continue
			}
			seen[real] = struct{}{}
			info, err := os.Lstat(real)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			if info.Size() > m.opts.MaxFileSize {
				continue
			}
			raw, err := core.ReadFileCapped(real, m.opts.MaxFileSize)
			if err != nil || len(raw) == 0 {
				continue
			}
			logical := m.logicalize(real)
			for _, e := range s.parse(raw, logical, m) {
				if e.Target == "" {
					continue
				}
				emit(m.recordFor(s, logical, info, e))
			}
		}
	}
	return nil
}

func (m *Module) recordFor(s site, logical string, info os.FileInfo, e Edge) core.Record {
	// content_norm hashes the (locus, edge-target) pair so two hosts with
	// the same planted edge in the same file stack as one Q1 group, while a
	// benign per-host edge stays distinct.
	norm := core.HashHexString(logical + "\x00" + e.Target)
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         s.class,
		MITRE:             s.mitre,
		Locus:             logical,
		ContentSHA256:     core.HashHex([]byte(e.Snippet)),
		ContentNormSHA256: norm,
		ContentSnippet:    snippet(e.Snippet),
		ExecTarget:        e.Target,
		FullExecLine:      e.Snippet, // Tier-B behavioral scan over the full line
	}
	core.FillFileMeta(&rec, info)
	sigs := m.baseSignals(info, logical)
	sigs = append(sigs, m.execTargetStatSignals(e.Target)...)
	if strings.HasPrefix(e.Target, "/") {
		if sum, ok := core.HashFileCapped(m.resolve(e.Target), m.opts.MaxFileSize); ok {
			rec.ExecTargetSHA256 = sum
		}
	}
	rec.Signals = core.DedupSignals(sigs)
	core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, e.Target)
	core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, e.Target)
	rec.Signals = core.DedupSignals(rec.Signals)
	return rec
}

func (m *Module) baseSignals(info os.FileInfo, logical string) []string {
	var out []string
	delta := m.opts.Now().Sub(info.ModTime().UTC())
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

// execTargetStatSignals mirrors the per-module helper: interpreter_in_tmp
// when the edge target lives under a tmp-class dir, exec_target_orphan when
// it is absent, recent_target_mtime_7d when freshly written.
func (m *Module) execTargetStatSignals(target string) []string {
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
	info, err := os.Stat(m.resolve(target))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		out = append(out, core.SignalExecTargetOrphan)
	case err == nil:
		delta := m.opts.Now().Sub(info.ModTime().UTC())
		if delta >= 0 && delta < 7*24*time.Hour {
			out = append(out, core.SignalRecentTargetMtime7d)
		}
	}
	return out
}

func isSystemPath(p string) bool {
	for _, prefix := range []string{"/etc/", "/usr/", "/var/", "/lib/", "/bin/", "/sbin/"} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

func snippet(s string) string {
	const max = 256
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max]
}
