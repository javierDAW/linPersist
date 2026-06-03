// Package runtimeinit implements the linpersist collector for
// language-runtime startup-file persistence — the interpreter-level
// analogue of the shell-init (profile) and dynamic-linker (ldso)
// surfaces. An interpreter that auto-imports/sources a file at startup
// gives an attacker code execution in EVERY invocation of that runtime
// (every script, cron job, CGI, or `python3 -c` one-liner), with no unit
// or cron entry.
//
// Site_classes emitted:
//
//   - runtime.python   the Python startup-hook files that CPython's
//     site.py auto-executes at interpreter startup, found on the
//     standard site/dist-packages search dirs:
//   - sitecustomize.py / usercustomize.py  — auto-imported by site.py
//   - *.pth files carrying a code line (a line beginning `import`,
//     which CPython exec()s — the textbook `import os; os.system(...)`
//     persistence .pth). Plain path-only .pth (sys.path additions) are
//     the search-path-injection shape and are left to LFA, mirroring
//     how ldso treats a bare ld.so.conf.d dir entry.
//
// ExecTarget is the startup file itself (the runtime runs it), so the
// central provenance pipeline applies directly: a packaged sitecustomize
// / distutils-precedence.pth resolves OWNED and stays silent, while a
// PLANTED file (non_package_path) or an in-place-edited owned one
// (package_file_tampered) surfaces. This provenance gate is load-bearing
// — code-form .pth and a shipped sitecustomize.py are both common and
// package-owned on a stock host, so "has an import line" alone is NOT a
// tell; "unowned/tampered" is.
//
// MITRE T1546 (Event Triggered Execution) — there is no Python-specific
// Linux sub-technique; T1059.006 (Python) is the command/scripting
// interpreter, not the persistence trigger.
//
// Out of scope (left to LFA or other modules): env-var runtime hooks
// (PYTHONSTARTUP, NODE_OPTIONS, PERL5OPT, RUBYOPT) live in env-config
// files and are handled by the confexec environment.d / profile env-hook
// grammars; inline `-M`/`-r` module NAMES (not paths) are content
// singletons left to LFA per the inline-code boundary (scope.md 8.1).
package runtimeinit

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

const (
	mitreRuntime = "T1546"

	siteClassPython = "runtime.python"
)

// pythonSiteGlobs are the directories CPython's site.py searches for
// sitecustomize/usercustomize and *.pth files, across distro layouts
// (Debian dist-packages, RHEL/Arch site-packages, /usr/lib64 on 64-bit
// RPM, /usr/local, and per-user ~/.local). Globbed so the python3.X
// version component is matched on any host.
var pythonSiteGlobs = []string{
	"/usr/lib/python3*",
	"/usr/lib/python3*/dist-packages",
	"/usr/lib/python3*/site-packages",
	"/usr/lib64/python3*",
	"/usr/lib64/python3*/site-packages",
	"/usr/local/lib/python3*/dist-packages",
	"/usr/local/lib/python3*/site-packages",
	"/root/.local/lib/python3*/site-packages",
	"/home/*/.local/lib/python3*/site-packages",
}

// DefaultMaxFileSize bounds one startup file read.
const DefaultMaxFileSize = 1 << 20

// Options configures the runtimeinit module.
type Options struct {
	Root           string
	Now            func() time.Time
	MaxFileSize    int64
	Globs          []string // overrides pythonSiteGlobs (tests)
	Provenance     core.Provenance
	LiveProcessSet core.LiveProcessSet
}

// Module collects language-runtime startup-hook persistence sites.
type Module struct{ opts Options }

// New constructs a runtimeinit Module with default fallbacks.
func New(opts Options) *Module {
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = DefaultMaxFileSize
	}
	if len(opts.Globs) == 0 {
		opts.Globs = pythonSiteGlobs
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

func (m *Module) Name() string { return "runtimeinit" }

func (m *Module) SiteClasses() []string { return []string{siteClassPython} }

func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error
	seen := map[string]struct{}{}
	for _, g := range m.opts.Globs {
		matches, err := filepath.Glob(m.resolve(g))
		if err != nil {
			continue
		}
		for _, realDir := range matches {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err := m.scanDir(realDir, seen, emit); err != nil {
				errs = append(errs, err)
			}
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

func (m *Module) scanDir(realDir string, seen map[string]struct{}, emit func(core.Record)) error {
	entries, err := os.ReadDir(realDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		isHook := name == "sitecustomize.py" || name == "usercustomize.py"
		isPth := strings.HasSuffix(name, ".pth")
		if !isHook && !isPth {
			continue
		}
		real := filepath.Join(realDir, name)
		if _, dup := seen[real]; dup {
			continue
		}
		seen[real] = struct{}{}
		// os.Stat (NOT Lstat) so a SYMLINKED hook is followed: Debian ships
		// /usr/lib/pythonX/sitecustomize.py as a symlink to
		// /etc/pythonX/sitecustomize.py (outside any site dir), so an Lstat
		// IsRegular() check would miss it entirely. The Locus/ExecTarget
		// stay the site-dir path (what the interpreter loads and what the
		// package owns); the content is read through the link.
		info, ierr := os.Stat(real)
		if ierr != nil || !info.Mode().IsRegular() || info.Size() > m.opts.MaxFileSize {
			continue
		}
		raw, rerr := core.ReadFileCapped(real, m.opts.MaxFileSize)
		if rerr != nil || len(raw) == 0 {
			continue
		}
		// Skip setuptools/pip plumbing .pth (distutils-precedence.pth,
		// __editable__*.pth, the _distutils_hack/editable-finder imports).
		// pip editable installs and setuptools write these by the dozen on
		// dev/CI/data-science boxes; they carry an `import` line but are NOT
		// package-owned, so without this they each fire a HIGH Q7
		// python_runtime_hook_unmanaged verdict (15-40 per workstation,
		// zero true positives — the duel-final flood). They are a fixed,
		// recognizable shape; a real planted .pth does not match it.
		if isPth && isSetuptoolsPlumbing(name, raw) {
			continue
		}
		// A *.pth file is only an exec hook when it carries a code line
		// (CPython exec()s lines beginning with `import`). Plain path-list
		// .pth are sys.path additions (search-path injection) — left to LFA.
		if isPth && !pthHasCodeLine(raw) {
			continue
		}
		emit(m.recordFor(m.logicalize(real), info, raw))
	}
	return nil
}

func (m *Module) recordFor(logical string, info os.FileInfo, raw []byte) core.Record {
	sum := core.HashHex(raw)
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         siteClassPython,
		MITRE:             []string{mitreRuntime},
		Locus:             logical,
		ContentSHA256:     sum,
		ContentNormSHA256: sum,
		ContentSnippet:    snippet(string(raw)),
		// The startup file IS the persistence target — the interpreter
		// runs/imports it. ExecTarget=self lets provenance flag a planted
		// file and the sink's package_file_tampered catch an in-place edit.
		ExecTarget:       logical,
		ExecTargetSHA256: sum,
	}
	core.FillFileMeta(&rec, info)
	rec.Signals = core.DedupSignals(m.baseSignals(info, logical))
	core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
	core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
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
		if st.Uid != 0 {
			out = append(out, core.SignalNonRootOwner)
		}
	}
	return out
}

// isSetuptoolsPlumbing recognizes the fixed-shape .pth files setuptools and
// pip editable installs write. These carry an `import` line but are benign
// package-management plumbing, ubiquitous on any host with pip-installed or
// editable packages. Matched by the canonical filenames and by an import
// line that only references the setuptools/editable finder machinery.
func isSetuptoolsPlumbing(name string, raw []byte) bool {
	if name == "distutils-precedence.pth" || strings.HasPrefix(name, "__editable__") {
		return true
	}
	sawImport := false
	for _, line := range strings.Split(string(raw), "\n") {
		t := strings.TrimLeft(line, " \t")
		if !strings.HasPrefix(t, "import ") {
			continue
		}
		sawImport = true
		// A code line that touches anything other than the known finders
		// means it is NOT pure plumbing -> do not skip.
		if !strings.Contains(t, "__editable__") &&
			!strings.Contains(t, "_distutils_hack") &&
			!strings.Contains(t, "_virtualenv") {
			return false
		}
	}
	return sawImport // every import line was setuptools/editable plumbing
}

// pthHasCodeLine reports whether a .pth body has a line CPython would
// exec — site.py runs any line beginning with `import` (after left-trim).
func pthHasCodeLine(raw []byte) bool {
	for _, line := range strings.Split(string(raw), "\n") {
		t := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(t, "import ") || strings.HasPrefix(t, "import\t") {
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
