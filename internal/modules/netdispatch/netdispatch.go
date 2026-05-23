// Package netdispatch implements the linpersist collector for
// network-event dispatcher script persistence on Linux.
//
// Site_class emitted:
//
//   - network.dispatchers   one record per executable script (or
//     single-file hook) under any of the four well-known
//     network-stack dispatcher families: NetworkManager,
//     dhclient, dhcpcd, and ifupdown. Each script is invoked by
//     its respective daemon on a network state change; an attacker
//     who can write one gets recurring code execution every time
//     the host's network re-converges.
//
// MITRE T1546 (Event Triggered Execution, parent technique). ATT&CK
// has no Linux-network-dispatcher sub-technique as of May 2026.
// Documented in matrix.yaml notes; PANIX, Mandiant, and The DFIR
// Report have all flagged this family in real campaigns.
package netdispatch

import (
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

// MITRE ATT&CK technique applied to every record this module emits.
const mitreNetDispatch = "T1546"

// dispatcherDirs are directories of executable scripts that one of
// the network daemons invokes on a network event. Order matters for
// determinism.
var dispatcherDirs = []string{
	// NetworkManager
	"/etc/NetworkManager/dispatcher.d",
	"/etc/NetworkManager/dispatcher.d/pre-up.d",
	"/etc/NetworkManager/dispatcher.d/pre-down.d",
	"/etc/NetworkManager/dispatcher.d/no-wait.d",
	// dhclient
	"/etc/dhcp/dhclient-enter-hooks.d",
	"/etc/dhcp/dhclient-exit-hooks.d",
	// ifupdown (Debian classic)
	"/etc/network/if-pre-up.d",
	"/etc/network/if-up.d",
	"/etc/network/if-down.d",
	"/etc/network/if-post-down.d",
}

// dispatcherFiles are single-file hook scripts. dhcpcd uses two of
// these on systems that ship its config out-of-the-box.
var dispatcherFiles = []string{
	"/etc/dhcpcd.enter.hook",
	"/etc/dhcpcd.exit.hook",
}

// DefaultMaxFileSize bounds one dispatcher script. Real scripts are
// well under 4 KiB; 1 MiB is the project-wide safety net.
const DefaultMaxFileSize = 1 << 20

// Options configures the netdispatch module.
type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
	// Provenance annotates exec_target (the script path itself) with
	// its owning package. Most legitimate dispatcher scripts are
	// distro-shipped (cloud-init, NetworkManager-config-routing,
	// etc.) so non_package_path is a strong signal for "operator or
	// attacker put this here".
	Provenance core.Provenance
	// LiveProcessSet is wired uniformly across modules. Dispatcher
	// scripts are short-lived: they run once per network event and
	// exit. live_process_attached fires only if the agent happens
	// to snapshot /proc during an active dispatch -- rare but
	// possible.
	LiveProcessSet core.LiveProcessSet
}

// Module collects network-dispatcher persistence sites.
type Module struct {
	opts Options
}

// New constructs a netdispatch Module. Zero-valued Options is valid.
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
func (m *Module) Name() string { return "netdispatch" }

// SiteClasses returns the single site_class this module emits.
func (m *Module) SiteClasses() []string { return []string{"network.dispatchers"} }

// Collect walks every dispatcher locus and emits one record per
// script.
func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error
	for _, d := range dispatcherDirs {
		if err := m.walkDir(ctx, d, emit); err != nil {
			errs = append(errs, err)
		}
	}
	for _, f := range dispatcherFiles {
		if err := m.collectFile(ctx, f, emit); err != nil {
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

// walkDir lists every regular file under one dispatcher directory
// and emits a record per file. Dotfiles, backup files, and dpkg/rpm
// leftovers are skipped (matches dispatcher daemon behavior).
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

// collectFile handles a single fixed-path hook script (dhcpcd uses
// two of these). Absence is silent.
func (m *Module) collectFile(ctx context.Context, logical string, emit func(core.Record)) error {
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
	m.processFile(ctx, logical, real, info, emit)
	return nil
}

// processFile reads, normalizes, hashes, and emits one record per
// dispatcher script.
func (m *Module) processFile(ctx context.Context, logical, real string, info os.FileInfo, emit func(core.Record)) {
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
		rec := m.baseRecord(logical, info)
		rec.Signals = appendUnique(rec.Signals, core.SignalEmptyFile)
		emit(rec)
		return
	}
	canon := Normalize(raw)
	rec := m.baseRecord(logical, info)
	rec.ContentSHA256 = core.HashHex(raw)
	rec.ContentNormSHA256 = core.HashHex(canon)
	rec.ContentSnippet = snippet(string(canon))
	// The script itself is the persistence target: the dispatcher
	// daemon executes it as a shell script on network events. Same
	// model as cron.periodic and motd-shell.
	rec.ExecTarget = logical
	rec.ExecTargetSHA256 = rec.ContentSHA256
	// Surface mode bits: a non-executable dispatcher script is a
	// dead drop (NetworkManager skips non-x files) but still worth
	// noting in errors[] for the analyst.
	if info.Mode().Perm()&0o111 == 0 {
		rec.Errors = append(rec.Errors, core.RecordError{
			Field: "mode", Code: "NOT_EXECUTABLE",
		})
	}
	core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
	core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
	emit(rec)
}

func (m *Module) baseRecord(logical string, info os.FileInfo) core.Record {
	rec := core.Record{
		Module:    m.Name(),
		SiteClass: "network.dispatchers",
		MITRE:     []string{mitreNetDispatch},
		Locus:     logical,
	}
	core.FillFileMeta(&rec, info)
	rec.Signals = m.baseSignals(info)
	return rec
}

func (m *Module) envelopeRecord(logical string, info os.FileInfo, errs []core.RecordError) core.Record {
	rec := m.baseRecord(logical, info)
	rec.Errors = errs
	return rec
}

// baseSignals returns the per-file signals: recent_mtime_*,
// world_writable, non_root_owner.
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
