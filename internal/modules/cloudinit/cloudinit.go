// Package cloudinit implements the linpersist collector for
// cloud-init persistence on Linux.
//
// cloud-init is the de-facto first-boot configuration system on
// every modern cloud image (AWS EC2, GCE, Azure VMs) and many
// on-prem hypervisor templates. It runs as a privileged daemon
// on every boot, reading a stack of YAML config files and a tree
// of executable scripts. Both are attractive persistence loci
// because the operator rarely audits them after image rollout.
//
// Site_classes emitted:
//
//   - cloudinit.config   one record per YAML config under
//     /etc/cloud/cloud.cfg or /etc/cloud/cloud.cfg.d/*.cfg.
//     These files declare modules (runcmd, write_files,
//     bootcmd, users, ssh_authorized_keys, etc.) that
//     cloud-init executes at boot. content_norm_sha256
//     is the raw bytes — YAML re-serialization is too
//     fragile to be a stacking key; in practice the
//     operator pushes identical files via image
//     templating, so raw-hash collides correctly
//     across fleet baseline.
//
//   - cloudinit.script   one record per executable file under any of the
//     per-boot / per-instance / per-once script
//     directories: /var/lib/cloud/scripts/{per-boot,
//     per-instance,per-once}/*. cloud-init invokes
//     every script in lexical order at the matching
//     boot phase. exec_target = the script path
//     (the script IS the persistence target, same
//     pattern as cron.periodic and netdispatch).
//
// MITRE T1543 (Create or Modify System Process) for the daemon-
// behavioural angle, plus T1547 (Boot or Logon Autostart Execution)
// for the script-on-boot angle. The two technique IDs are recorded
// on every cloudinit.* record.
package cloudinit

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

const (
	mitreCreateProcess = "T1543"
	mitreAutostart     = "T1547"

	siteClassConfig = "cloudinit.config"
	siteClassScript = "cloudinit.script"
)

// configFiles are explicit single-file YAML config loci. The main
// cloud.cfg lives here; per-instance overrides also drop here on
// some distros.
var configFiles = []string{
	"/etc/cloud/cloud.cfg",
}

// configDirs hold .cfg drop-ins merged into the cloud-init module
// pipeline at startup.
var configDirs = []string{
	"/etc/cloud/cloud.cfg.d",
}

// scriptDirs are the three execution phases cloud-init exposes. Order
// is load-bearing for determinism:
//   - per-boot:     runs on every boot
//   - per-instance: runs once per cloud-init instance ID (typically
//     once per image clone)
//   - per-once:     runs literally once across the host's lifetime
var scriptDirs = []string{
	"/var/lib/cloud/scripts/per-boot",
	"/var/lib/cloud/scripts/per-instance",
	"/var/lib/cloud/scripts/per-once",
}

// DefaultMaxFileSize bounds one cloud-init artefact. cloud.cfg.d
// drop-ins are typically < 8 KiB; scripts < 4 KiB. 1 MiB is the
// project-wide safety net.
const DefaultMaxFileSize = 1 << 20

// Options configures the cloudinit module.
type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
	// Provenance annotates exec_target for cloudinit.script records.
	// Vendor-shipped cloud-init scripts are package-managed on most
	// distros; an operator-or-attacker drop under per-boot/ shows up
	// as non_package_path.
	Provenance core.Provenance
	// LiveProcessSet check applies to cloudinit.script when the
	// script happens to be running at snapshot time (e.g. the agent
	// runs during a cloud-init iteration).
	LiveProcessSet core.LiveProcessSet
}

// Module collects cloud-init persistence sites.
type Module struct{ opts Options }

// New constructs a cloudinit Module with default fallbacks.
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
func (m *Module) Name() string { return "cloudinit" }

// SiteClasses returns both classes this module can emit.
func (m *Module) SiteClasses() []string {
	return []string{siteClassConfig, siteClassScript}
}

// Collect walks every configured locus and emits one record per
// artefact. Missing loci are silent — most hosts have either the
// config or the scripts populated, rarely both.
func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error
	for _, f := range configFiles {
		if err := m.collectConfigFile(ctx, f, emit); err != nil {
			errs = append(errs, err)
		}
	}
	for _, d := range configDirs {
		if err := m.walkConfigDir(ctx, d, emit); err != nil {
			errs = append(errs, err)
		}
	}
	for _, d := range scriptDirs {
		if err := m.walkScriptDir(ctx, d, emit); err != nil {
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

func (m *Module) collectConfigFile(ctx context.Context, logical string, emit func(core.Record)) error {
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
	m.processConfig(logical, real, info, emit)
	return nil
}

func (m *Module) walkConfigDir(ctx context.Context, logicalDir string, emit func(core.Record)) error {
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
		if !strings.HasSuffix(name, ".cfg") {
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
		m.processConfig(logical, real, info, emit)
	}
	return nil
}

func (m *Module) walkScriptDir(ctx context.Context, logicalDir string, emit func(core.Record)) error {
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
		m.processScript(logical, real, info, emit)
	}
	return nil
}

// processConfig builds a cloudinit.config record. content_sha256
// and content_norm_sha256 are both the raw bytes — YAML
// re-serialization for normalisation is too fragile (key ordering,
// quoting style, anchors) to give a useful stacking key, and in
// practice operators push byte-identical files from image templates.
func (m *Module) processConfig(logical, real string, info os.FileInfo, emit func(core.Record)) {
	if info.Size() > m.opts.MaxFileSize {
		emit(m.envelopeRecord(logical, info, siteClassConfig, []core.RecordError{
			{Field: "content_sha256", Code: "SIZE_LIMIT"},
		}))
		return
	}
	raw, err := os.ReadFile(real)
	if err != nil {
		emit(m.envelopeRecord(logical, info, siteClassConfig, []core.RecordError{
			{Field: "content_sha256", Code: errnoCode(err), Msg: err.Error()},
		}))
		return
	}
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         siteClassConfig,
		MITRE:             []string{mitreCreateProcess, mitreAutostart},
		Locus:             logical,
		ContentSHA256:     core.HashHex(raw),
		ContentNormSHA256: core.HashHex(raw),
		ContentSnippet:    snippet(string(raw)),
	}
	core.FillFileMeta(&rec, info)
	rec.Signals = core.DedupSignals(m.baseSignals(info, logical))
	emit(rec)
}

// processScript builds a cloudinit.script record. The script itself
// IS the persistence target (cloud-init exec()s it directly), so
// ExecTarget = locus. Same model as cron.periodic / motd-shell /
// network.dispatchers.
func (m *Module) processScript(logical, real string, info os.FileInfo, emit func(core.Record)) {
	if info.Size() > m.opts.MaxFileSize {
		emit(m.envelopeRecord(logical, info, siteClassScript, []core.RecordError{
			{Field: "content_sha256", Code: "SIZE_LIMIT"},
		}))
		return
	}
	raw, err := os.ReadFile(real)
	if err != nil {
		emit(m.envelopeRecord(logical, info, siteClassScript, []core.RecordError{
			{Field: "content_sha256", Code: errnoCode(err), Msg: err.Error()},
		}))
		return
	}
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         siteClassScript,
		MITRE:             []string{mitreCreateProcess, mitreAutostart},
		Locus:             logical,
		ContentSHA256:     core.HashHex(raw),
		ContentNormSHA256: core.HashHex(raw),
		ContentSnippet:    snippet(string(raw)),
		ExecTarget:        logical,
		ExecTargetSHA256:  core.HashHex(raw),
	}
	core.FillFileMeta(&rec, info)
	signals := m.baseSignals(info, logical)
	// cloud-init silently skips non-executable scripts (no shebang
	// fallback for executable-bit-missing files). Record it as an
	// error so the analyst sees a dead drop rather than a live
	// vector.
	if info.Mode().Perm()&0o111 == 0 {
		rec.Errors = append(rec.Errors, core.RecordError{
			Field: "mode", Code: "NOT_EXECUTABLE",
		})
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
		MITRE:     []string{mitreCreateProcess, mitreAutostart},
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
	for _, prefix := range []string{"/etc/", "/usr/", "/lib/", "/bin/", "/sbin/", "/var/lib/cloud/"} {
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
