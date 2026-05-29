// Package udev implements the linpersist collector for udev rule
// persistence on Linux.
//
// Site_class emitted:
//
//   - udev   /etc/udev/rules.d/*.rules, /lib/udev/rules.d/*.rules,
//     /usr/lib/udev/rules.d/*.rules, /run/udev/rules.d/*.rules.
//
// Per-rule (per-logical-line) record granularity. Each non-comment
// non-blank logical line in a *.rules file is one udev rule and one
// emitted record. Line continuations (`\` at EOL) are joined before
// parsing. The canonical form collapses runs of whitespace OUTSIDE
// quoted values to a single space and standardizes spacing around
// commas; key-op-value triples retain their source order (udev's
// semantics are sensitive to order for assignment-side operators
// like RUN+= and IMPORT{program}=).
//
// MITRE T1546 (Event Triggered Execution, parent technique). The
// ATT&CK matrix does not (as of May 2026) carry a Linux-udev
// sub-technique. RUN+="..." is the textbook offensive vector:
// arbitrary command execution under whatever uid udevd invokes
// (typically root) every time a matching device event fires.
package udev

import (
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

const mitreUdev = "T1546"

var udevLoci = []string{
	"/etc/udev/rules.d",
	"/lib/udev/rules.d",
	"/usr/lib/udev/rules.d",
	"/run/udev/rules.d",
}

// Options configures the udev module.
type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
	// Provenance annotates exec_target paths (RUN+= and PROGRAM=
	// argv[0]) with their owning package. Nil defaults to
	// core.NoopProvenance.
	Provenance core.Provenance
	// LiveProcessSet membership check for the live_process_attached
	// signal. A RUN+= target with a live PID means udev fired the
	// rule recently AND the spawned process is still running.
	LiveProcessSet core.LiveProcessSet
}

const DefaultMaxFileSize = 1 << 20

// Module collects udev rule persistence sites.
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

func (m *Module) Name() string          { return "udev" }
func (m *Module) SiteClasses() []string { return []string{"udev"} }

// Collect walks every udev rules.d locus and emits one record per
// rule (one logical line after backslash-continuation join).
func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error
	for _, dir := range udevLoci {
		if err := m.walkDir(ctx, dir, emit); err != nil {
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

func (m *Module) walkDir(ctx context.Context, logicalDir string, emit func(core.Record)) error {
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
		if !strings.HasSuffix(name, ".rules") {
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
		m.processFile(ctx, logical, real, info, emit)
	}
	return nil
}

func (m *Module) processFile(ctx context.Context, logical, real string, info os.FileInfo, emit func(core.Record)) {
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
	rules := parseRules(raw)
	for _, rule := range rules {
		rec := m.buildRecord(logical, info, rule)
		emit(rec)
	}
}

func (m *Module) buildRecord(logical string, info os.FileInfo, raw string) core.Record {
	canon := normalizeRule(raw)
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         "udev",
		MITRE:             []string{mitreUdev},
		Locus:             logical,
		ContentSHA256:     core.HashHexString(raw + "\n"),
		ContentNormSHA256: core.HashHexString(canon + "\n"),
		ContentSnippet:    snippet(canon),
	}
	core.FillFileMeta(&rec, info)
	rec.Signals = m.baseSignals(info)

	// exec_target + directive-class signals.
	if et, ok := extractAssignmentValue(canon, "RUN"); ok {
		rec.Signals = appendUnique(rec.Signals, core.SignalUdevRunDirective)
		// The value of RUN+= can be either "program args..." or
		// "program:program args..." (older syntax uses RUN+= with
		// a "program" key). Take the first whitespace-token.
		first := firstToken(et)
		if first != "" {
			rec.ExecTarget = first
			rec.Signals = m.execTargetSignals(rec.Signals, first)
		}
	}
	if _, ok := extractAssignmentValue(canon, "PROGRAM"); ok {
		rec.Signals = appendUnique(rec.Signals, core.SignalUdevProgramDirective)
	}

	core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
	core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
	return rec
}

func (m *Module) envelopeRecord(logical string, info os.FileInfo, errs []core.RecordError) core.Record {
	rec := core.Record{
		Module:    m.Name(),
		SiteClass: "udev",
		MITRE:     []string{mitreUdev},
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
