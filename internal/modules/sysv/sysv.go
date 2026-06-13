// Package sysv implements the linpersist collector for sysv-style
// init script persistence on Linux.
//
// Site_class emitted:
//
//   - sysv.init   /etc/init.d/* and /etc/rc.d/init.d/*, plus
//     external-target symlinks under /etc/rc[0-6].d/ and
//     /etc/rc.d/rc[0-6].d/ (the enablement directories).
//
// Per-file record granularity. MITRE T1037.004 (Boot or Logon
// Initialization Scripts: RC Scripts).
package sysv

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

const mitreSysvInit = "T1037.004"

// initdLoci are the directories where actual init scripts live.
// Files under these paths are emitted as their own records. Symlinks
// inside these directories pointing to other init.d files are rare;
// they are skipped (the target's own walk handles it).
var initdLoci = []string{
	"/etc/init.d",
	"/etc/rc.d/init.d",
}

// rcLocalFiles are single-file fixed-path init scripts. /etc/rc.local
// is documented in matrix.yaml as a sysv.init locus; it is invoked at
// the end of system initialization on distros that still ship a
// compatibility shim. Treated as a regular init script for content
// hashing and signal computation.
var rcLocalFiles = []string{
	"/etc/rc.local",
	"/etc/rc.d/rc.local",
}

// runlevelLoci are the directories that hold the enablement symlinks
// (e.g. /etc/rc2.d/S99sshd -> /etc/init.d/sshd). The walker visits
// each entry and emits a record only when the symlink target resolves
// OUTSIDE every initdLoci prefix -- the offensive pattern of enabling
// a payload kept under /tmp, /opt, etc., without touching the
// canonical /etc/init.d/ directory.
var runlevelLoci = []string{
	"/etc/rc0.d",
	"/etc/rc1.d",
	"/etc/rc2.d",
	"/etc/rc3.d",
	"/etc/rc4.d",
	"/etc/rc5.d",
	"/etc/rc6.d",
	"/etc/rcS.d",
	"/etc/rc.d/rc0.d",
	"/etc/rc.d/rc1.d",
	"/etc/rc.d/rc2.d",
	"/etc/rc.d/rc3.d",
	"/etc/rc.d/rc4.d",
	"/etc/rc.d/rc5.d",
	"/etc/rc.d/rc6.d",
}

// Options configures the sysv module.
type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
	// Provenance annotates exec_target paths (resolved init-script
	// targets) with their owning package. Nil defaults to
	// core.NoopProvenance.
	Provenance core.Provenance
	// LiveProcessSet membership check for the live_process_attached
	// signal.
	LiveProcessSet core.LiveProcessSet
}

// DefaultMaxFileSize is the per-file byte cap. Init scripts are small;
// 1 MiB is generous headroom for unusual generated scripts.
const DefaultMaxFileSize = 1 << 20

// Module collects sysv-style init script persistence sites.
type Module struct {
	opts Options
}

// New constructs a sysv Module. Zero-valued Options is valid.
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

// Name returns the module identifier.
func (m *Module) Name() string { return "sysv" }

// SiteClasses returns the canonical site_class values this module
// emits.
func (m *Module) SiteClasses() []string {
	return []string{"sysv.init"}
}

// Collect walks both the init.d and rc?.d locus families, emitting
// one record per init script and one record per external-target
// enablement symlink.
func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error
	for _, dir := range initdLoci {
		if err := m.walkInitd(ctx, dir, emit); err != nil {
			errs = append(errs, err)
		}
	}
	for _, p := range rcLocalFiles {
		if err := m.collectStaticFile(ctx, p, emit); err != nil {
			errs = append(errs, err)
		}
	}
	for _, dir := range runlevelLoci {
		if err := m.walkRunlevel(ctx, dir, emit); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// collectStaticFile handles a fixed-path single-file locus
// (/etc/rc.local). Treated the same as an init.d/* file for
// content hashing and signal computation.
func (m *Module) collectStaticFile(ctx context.Context, logical string, emit func(core.Record)) error {
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
	m.processInitFile(ctx, logical, real, info, emit)
	return nil
}

func (m *Module) resolve(logical string) string {
	if m.opts.Root == "" {
		return logical
	}
	return filepath.Join(m.opts.Root, logical)
}

// walkInitd lists one init.d locus and emits a record per regular
// file found. Symlinks inside init.d are skipped; they typically
// point at /lib/lsb/init-functions or similar helper code that is
// not itself a persistence site.
func (m *Module) walkInitd(ctx context.Context, logicalDir string, emit func(core.Record)) error {
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
		logical := filepath.Join(logicalDir, name)
		real := filepath.Join(realDir, name)
		info, err := os.Lstat(real)
		if err != nil {
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		m.processInitFile(ctx, logical, real, info, emit)
	}
	return nil
}

// walkRunlevel lists one rc?.d locus and emits a record per symlink
// whose target resolves outside the init.d locus prefixes.
func (m *Module) walkRunlevel(ctx context.Context, logicalDir string, emit func(core.Record)) error {
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
		logical := filepath.Join(logicalDir, name)
		real := filepath.Join(realDir, name)
		info, err := os.Lstat(real)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		m.processRunlevelSymlink(ctx, logical, real, info, emit)
	}
	return nil
}

func (m *Module) processInitFile(ctx context.Context, logical, real string, info os.FileInfo, emit func(core.Record)) {
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
		rec := m.baseRecord(logical, info)
		rec.Signals = appendUnique(rec.Signals, core.SignalEmptyFile)
		emit(rec)
		return
	}
	rec := m.buildRecord(logical, info, raw)
	// An init script's persistence intent is the command it runs; parse the
	// body for a /tmp or orphan payload so it escalates past "just a
	// non-package script" the same way cron/systemd do.
	core.AnnotatePayloadExec(&rec, raw, m.resolve, m.opts.Now(), m.opts.MaxFileSize)
	core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
	core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
	emit(rec)
}

func (m *Module) processRunlevelSymlink(ctx context.Context, logical, real string, info os.FileInfo, emit func(core.Record)) {
	target, err := os.Readlink(real)
	if err != nil {
		return
	}
	absTarget := target
	if !filepath.IsAbs(absTarget) {
		absTarget = filepath.Clean(filepath.Join(filepath.Dir(logical), absTarget))
	}
	if m.targetInsideInitdLoci(absTarget) {
		// Internal symlink: the init.d/* target is emitted by its
		// own walk pass.
		return
	}
	realTarget := m.resolve(absTarget)
	targetInfo, terr := os.Stat(realTarget)
	if terr != nil {
		rec := m.baseRecord(logical, info)
		rec.Signals = appendUnique(rec.Signals, core.SignalSysvExternalInitSymlink)
		rec.Signals = appendUnique(rec.Signals, core.SignalExecTargetOrphan)
		rec.ExecTarget = absTarget
		core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
		core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
		emit(rec)
		return
	}
	if !targetInfo.Mode().IsRegular() {
		return
	}
	if targetInfo.Size() > m.opts.MaxFileSize {
		rec := m.baseRecord(logical, info)
		rec.Signals = appendUnique(rec.Signals, core.SignalSysvExternalInitSymlink)
		rec.Errors = append(rec.Errors, core.RecordError{Field: "content_sha256", Code: "SIZE_LIMIT"})
		emit(rec)
		return
	}
	raw, err := core.ReadFileCapped(realTarget, m.opts.MaxFileSize)
	if err != nil {
		rec := m.baseRecord(logical, info)
		rec.Signals = appendUnique(rec.Signals, core.SignalSysvExternalInitSymlink)
		rec.Errors = append(rec.Errors, core.RecordError{Field: "content_sha256", Code: errnoCode(err), Msg: err.Error()})
		emit(rec)
		return
	}
	rec := m.buildRecord(logical, info, raw)
	rec.Signals = appendUnique(rec.Signals, core.SignalSysvExternalInitSymlink)
	rec.ExecTarget = absTarget
	if strings.HasPrefix(absTarget, "/") {
		if sum, ok := core.HashFileCapped(m.resolve(absTarget), m.opts.MaxFileSize); ok {
			rec.ExecTargetSHA256 = sum
		}
	}
	if isInterpreterInTmp(absTarget) {
		rec.Signals = appendUnique(rec.Signals, core.SignalInterpreterInTmp)
	}
	core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
	core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
	emit(rec)
}

func (m *Module) baseRecord(logical string, info os.FileInfo) core.Record {
	rec := core.Record{
		Module:    m.Name(),
		SiteClass: "sysv.init",
		MITRE:     []string{mitreSysvInit},
		Locus:     logical,
	}
	core.FillFileMeta(&rec, info)
	rec.Signals = m.baseSignals(info, logical)
	return rec
}

func (m *Module) buildRecord(logical string, info os.FileInfo, raw []byte) core.Record {
	canon := Normalize(raw)
	rec := m.baseRecord(logical, info)
	rec.ContentSHA256 = core.HashHex(raw)
	rec.ContentNormSHA256 = core.HashHex(canon)
	rec.ContentSnippet = snippet(string(canon))
	rec.FullExecLine = string(canon) // Tier-B behavioral scan over the script body
	rec.ExecTarget = logical
	rec.ExecTargetSHA256 = rec.ContentSHA256
	return rec
}

func (m *Module) envelopeRecord(logical string, info os.FileInfo, errs []core.RecordError) core.Record {
	rec := m.baseRecord(logical, info)
	rec.Errors = errs
	return rec
}

// targetInsideInitdLoci returns true iff abs is inside one of the
// init.d directories. Used to classify a runlevel symlink as
// internal (skip) or external (emit).
func (m *Module) targetInsideInitdLoci(abs string) bool {
	abs = filepath.Clean(abs)
	for _, p := range initdLoci {
		cp := filepath.Clean(p)
		if abs == cp || strings.HasPrefix(abs, cp+string(filepath.Separator)) {
			return true
		}
	}
	return false
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
	// Documentation files mixed into init.d directories. The
	// distro-shipped initscripts package on RHEL / CentOS / AmazonLinux
	// drops a README under /etc/init.d/ and /etc/rc.d/init.d/ that
	// describes the deprecation of sysv init. The file is not honored
	// as a boot script by any sysv init implementation -- it is purely
	// documentation -- and emitting it as a sysv.init record only
	// adds noise (lab-realistic v0.2.0 surfaced it on 15 hosts in Q11
	// as a non_package_path false positive). Skip files whose
	// lowercased name is `readme` or whose extension is one of the
	// common documentation extensions.
	lower := strings.ToLower(name)
	if lower == "readme" {
		return true
	}
	for _, ext := range []string{".md", ".txt", ".rst", ".html"} {
		if strings.HasSuffix(lower, ext) {
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
