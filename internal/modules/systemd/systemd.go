package systemd

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

const (
	mitreSystemdUnit  = "T1543.002"
	mitreSystemdTimer = "T1053.006"
)

// Extensions that classify as systemd.unit. Order matches the matrix
// note in matrix.yaml. The set deliberately excludes .slice and
// .scope per ADR-0007 §4.
var unitExtensions = map[string]struct{}{
	".service":   {},
	".socket":    {},
	".path":      {},
	".mount":     {},
	".automount": {},
	".swap":      {},
	".target":    {},
}

// Extensions that classify as systemd.timer.
var timerExtensions = map[string]struct{}{
	".timer": {},
}

// systemLoci is the fixed set of system-mode directories the walker
// recurses into for unit/timer collection.
var systemLoci = []string{
	"/etc/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
	"/run/systemd/system",
}

// userModeLoci is the fixed set of user-mode system-installed
// directories the walker recurses into. Per-user loci under /home/*
// and /root/ are handled separately.
var userModeLoci = []string{
	"/etc/systemd/user",
	"/usr/lib/systemd/user",
}

// systemdDefaultPath is the documented systemd.exec(5) default PATH
// used to resolve a relative ExecStart= command. Strict order matches
// systemd's own.
var systemdDefaultPath = []string{
	"/usr/local/sbin",
	"/usr/local/bin",
	"/usr/sbin",
	"/usr/bin",
	"/sbin",
	"/bin",
}

// Options configures the systemd module. Zero-value is usable; the
// Root field is the chroot under which all logical paths resolve and
// is set by golden tests against a fixture tree.
type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
	// Provenance annotates exec_target paths (first ExecStart=) with
	// their owning package. Nil defaults to core.NoopProvenance.
	Provenance core.Provenance
	// LiveProcessSet membership check for the live_process_attached
	// signal. Service units whose ExecStart binary has a live PID
	// are by definition active services right now.
	LiveProcessSet core.LiveProcessSet
}

// DefaultMaxFileSize is the per-file byte cap. Unit files in the wild
// are well under 32 KiB; 1 MiB gives orders-of-magnitude headroom for
// generated units (LXC, NixOS) without letting a runaway file dominate
// memory.
const DefaultMaxFileSize = 1 << 20

// Module collects systemd unit and timer persistence sites.
type Module struct {
	opts Options
	// walkedLoci is the set of absolute locus prefixes used to
	// classify symlink targets as internal vs external. Computed
	// once at module construction; immutable after that.
	walkedLoci []string
}

// New constructs a systemd Module. opts is captured by value; later
// mutation does not affect the returned module.
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
	m := &Module{opts: opts}
	// Fixed walked-loci prefixes. The /home/<user>/.config/systemd/user
	// case is matched in targetInsideWalkedLoci by a path-shape check
	// rather than a static prefix, so an offensive symlink to an
	// unrelated /home/<user>/<file> still classifies as external.
	m.walkedLoci = append(m.walkedLoci, systemLoci...)
	m.walkedLoci = append(m.walkedLoci, userModeLoci...)
	m.walkedLoci = append(m.walkedLoci, "/root/.config/systemd/user")
	return m
}

var _ core.Module = (*Module)(nil)

// Name returns the module identifier registered in matrix.yaml.
func (m *Module) Name() string { return "systemd" }

// SiteClasses returns the canonical site_class values this module
// emits. Drop-in records inherit the site_class of their parent unit
// type, so the list is just the two top-level classes.
func (m *Module) SiteClasses() []string {
	return []string{"systemd.unit", "systemd.timer", "systemd.generator"}
}

// Collect walks every system-mode and user-mode locus and emits one
// Record per unit/timer/drop-in file encountered. Symlinks resolving
// inside walked loci are skipped to avoid double-counting; symlinks
// resolving outside become first-class records with the
// systemd_external_unit_symlink signal.
func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error

	// System-mode loci.
	for _, dir := range systemLoci {
		if err := m.walkLocus(ctx, dir, false, emit); err != nil {
			errs = append(errs, err)
		}
	}
	// User-mode static loci.
	for _, dir := range userModeLoci {
		if err := m.walkLocus(ctx, dir, true, emit); err != nil {
			errs = append(errs, err)
		}
	}
	// Per-user loci: /root/.config/systemd/user/.
	if err := m.walkLocus(ctx, "/root/.config/systemd/user", true, emit); err != nil {
		errs = append(errs, err)
	}
	// Per-user loci: /home/<user>/.config/systemd/user/.
	if err := m.collectHomeUserUnits(ctx, emit); err != nil {
		errs = append(errs, err)
	}
	// Generator dirs: executables (not unit files) that run as root at
	// early boot. A separate walk because they carry no unit extension.
	for _, dir := range generatorLoci {
		if err := m.collectGenerators(ctx, dir, emit); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// generatorLoci are the system-generator directories systemd executes at
// early boot. See systemd.generator(7).
var generatorLoci = []string{
	"/etc/systemd/system-generators",
	"/usr/lib/systemd/system-generators",
	"/run/systemd/system-generators",
}

// collectGenerators emits one record per regular file in a generator dir.
// Generators are executables with no unit extension, so the unit walker
// skips them entirely; here ExecTarget is the generator itself, so
// AnnotateExecTargetProvenance surfaces a planted (unowned) generator via
// non_package_path and the central sink integrity-checks it via the locus.
func (m *Module) collectGenerators(ctx context.Context, logicalDir string, emit func(core.Record)) error {
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
		if e.IsDir() {
			continue
		}
		logical := filepath.Join(logicalDir, e.Name())
		info, err := os.Lstat(filepath.Join(realDir, e.Name()))
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		rec := core.Record{
			Module:     m.Name(),
			SiteClass:  "systemd.generator",
			MITRE:      []string{mitreSystemdUnit},
			Locus:      logical,
			ExecTarget: logical,
		}
		core.FillFileMeta(&rec, info)
		rec.Signals = appendUnique(rec.Signals, core.SignalSystemdGenerator)
		if sum, ok := core.HashFileCapped(filepath.Join(realDir, e.Name()), m.opts.MaxFileSize); ok {
			rec.ContentSHA256 = sum
			rec.ContentNormSHA256 = sum
		}
		core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, logical)
		core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, logical)
		rec.Signals = core.DedupSignals(rec.Signals)
		emit(rec)
	}
	return nil
}

func (m *Module) resolve(logical string) string {
	if m.opts.Root == "" {
		return logical
	}
	return filepath.Join(m.opts.Root, logical)
}

// collectHomeUserUnits walks /home/<user>/.config/systemd/user/ for
// every direct subdirectory of /home.
func (m *Module) collectHomeUserUnits(ctx context.Context, emit func(core.Record)) error {
	realHome := m.resolve("/home")
	entries, err := os.ReadDir(realHome)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("readdir /home: %w", err)
	}
	var errs []error
	for _, e := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !e.IsDir() {
			continue
		}
		logical := filepath.Join("/home", e.Name(), ".config", "systemd", "user")
		if err := m.walkLocus(ctx, logical, true, emit); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// walkLocus recursively walks one locus directory, emitting records
// for matching unit files and recursing into known sub-directories
// (*.d for drop-ins, *.wants / *.requires for external symlinks).
//
// userMode is true for user-mode loci, used to set the
// systemd_user_unit signal.
func (m *Module) walkLocus(ctx context.Context, logicalDir string, userMode bool, emit func(core.Record)) error {
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
		logical := filepath.Join(logicalDir, name)
		real := filepath.Join(realDir, name)
		info, err := os.Lstat(real)
		if err != nil {
			continue
		}
		switch {
		case info.IsDir():
			// Sub-directory: drop-in dir (*.d), wants/requires, or
			// some other systemd convention. Recurse for the
			// recognized cases.
			switch {
			case strings.HasSuffix(name, ".d"):
				// drop-in directory for a unit
				if siteClass, ok := siteClassForDropinDir(name); ok {
					if err := m.walkDropinDir(ctx, logical, siteClass, userMode, emit); err != nil {
						// non-fatal; continue siblings
						_ = err
					}
				}
			case strings.HasSuffix(name, ".wants"),
				strings.HasSuffix(name, ".requires"),
				strings.HasSuffix(name, ".wants.d"),
				strings.HasSuffix(name, ".requires.d"):
				if err := m.walkWantsDir(ctx, logical, userMode, emit); err != nil {
					_ = err
				}
			default:
				// Unknown sub-directory shape; skip.
			}
		case info.Mode().IsRegular():
			m.processUnitFile(ctx, logical, real, info, userMode, false, emit)
		case info.Mode()&os.ModeSymlink != 0:
			m.processSymlink(ctx, logical, real, info, userMode, emit)
		}
	}
	return nil
}

// walkDropinDir walks one *.d directory. Only *.conf files are
// emitted; other contents are ignored per systemd convention.
func (m *Module) walkDropinDir(ctx context.Context, logicalDir, siteClass string, userMode bool, emit func(core.Record)) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	realDir := m.resolve(logicalDir)
	entries, err := os.ReadDir(realDir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		name := e.Name()
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
		m.processDropinFile(ctx, logical, real, info, siteClass, userMode, emit)
	}
	return nil
}

// walkWantsDir walks a *.wants / *.requires directory. Its contents
// are typically symlinks to unit files in walked loci (internal,
// skipped) or external paths (emitted as records).
func (m *Module) walkWantsDir(ctx context.Context, logicalDir string, userMode bool, emit func(core.Record)) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	realDir := m.resolve(logicalDir)
	entries, err := os.ReadDir(realDir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		name := e.Name()
		logical := filepath.Join(logicalDir, name)
		real := filepath.Join(realDir, name)
		info, err := os.Lstat(real)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			m.processSymlink(ctx, logical, real, info, userMode, emit)
		}
	}
	return nil
}

// processSymlink decides whether the symlink at real resolves inside
// any walked locus. If yes, the link is skipped (the target will be
// visited in its own walk pass). If no, a record is emitted with the
// content of the resolved target and the systemd_external_unit_symlink
// signal.
func (m *Module) processSymlink(ctx context.Context, logical, real string, info os.FileInfo, userMode bool, emit func(core.Record)) {
	_, _, ok := classifyExtension(filepath.Base(logical))
	if !ok {
		return
	}
	target, err := os.Readlink(real)
	if err != nil {
		emit(m.errorEnvelope(logical, info, classifyByLogical(logical), userMode, []core.RecordError{
			{Field: "locus", Code: errnoCode(err), Msg: err.Error()},
		}))
		return
	}
	// resolve relative symlink target relative to the symlink's
	// containing directory.
	absTarget := target
	if !filepath.IsAbs(absTarget) {
		absTarget = filepath.Clean(filepath.Join(filepath.Dir(logical), absTarget))
	}
	if m.targetInsideWalkedLoci(absTarget) {
		// internal — skip; the target's own walk pass emits it.
		return
	}
	// External symlink: read the content of the resolved file (within
	// the agent's root context) and emit.
	realTarget := m.resolve(absTarget)
	targetInfo, err := os.Stat(realTarget)
	if err != nil {
		// External symlink whose target is missing on this host.
		// Still emit the symlink as a persistence site; mark as
		// orphan via signal.
		rec := m.envelope(logical, info, classifyByLogical(logical), userMode)
		rec.Signals = appendUnique(rec.Signals, core.SignalSystemdExternalUnitSymlink)
		rec.Signals = appendUnique(rec.Signals, core.SignalExecTargetOrphan)
		rec.ExecTarget = absTarget
		emit(rec)
		return
	}
	if !targetInfo.Mode().IsRegular() {
		return
	}
	if targetInfo.Size() > m.opts.MaxFileSize {
		rec := m.envelope(logical, info, classifyByLogical(logical), userMode)
		rec.Errors = append(rec.Errors, core.RecordError{Field: "content_sha256", Code: "SIZE_LIMIT"})
		rec.Signals = appendUnique(rec.Signals, core.SignalSystemdExternalUnitSymlink)
		emit(rec)
		return
	}
	raw, err := core.ReadFileCapped(realTarget, m.opts.MaxFileSize)
	if err != nil {
		rec := m.envelope(logical, info, classifyByLogical(logical), userMode)
		rec.Errors = append(rec.Errors, core.RecordError{Field: "content_sha256", Code: errnoCode(err), Msg: err.Error()})
		emit(rec)
		return
	}
	rec := m.buildRecord(logical, info, classifyByLogical(logical), userMode, raw)
	rec.Signals = appendUnique(rec.Signals, core.SignalSystemdExternalUnitSymlink)
	// External symlinks override exec_target with the target's
	// resolved path (more useful for the analyst than an ExecStart=
	// resolution against the symlink's target).
	if rec.ExecTarget == "" {
		rec.ExecTarget = absTarget
		if strings.HasPrefix(absTarget, "/") {
			if sum, ok := core.HashFileCapped(m.resolve(absTarget), m.opts.MaxFileSize); ok {
				rec.ExecTargetSHA256 = sum
			}
		}
	}
	emit(rec)
}

// processUnitFile reads a regular unit file at real, builds the
// canonical record, and emits it.
func (m *Module) processUnitFile(ctx context.Context, logical, real string, info os.FileInfo, userMode, isDropin bool, emit func(core.Record)) {
	siteClass, _, ok := classifyExtension(filepath.Base(logical))
	if !ok {
		return
	}
	m.emitRegular(ctx, logical, real, info, siteClass, userMode, isDropin, emit)
}

// processDropinFile reads a *.conf drop-in and emits it. siteClass
// is derived from the parent *.<ext>.d directory name by the caller.
func (m *Module) processDropinFile(ctx context.Context, logical, real string, info os.FileInfo, siteClass string, userMode bool, emit func(core.Record)) {
	m.emitRegular(ctx, logical, real, info, siteClass, userMode, true, emit)
}

func (m *Module) emitRegular(ctx context.Context, logical, real string, info os.FileInfo, siteClass string, userMode, isDropin bool, emit func(core.Record)) {
	if info.Size() > m.opts.MaxFileSize {
		rec := m.envelope(logical, info, siteClass, userMode)
		rec.Errors = append(rec.Errors, core.RecordError{Field: "content_sha256", Code: "SIZE_LIMIT"})
		if isDropin {
			rec.Signals = appendUnique(rec.Signals, core.SignalSystemdDropin)
		}
		emit(rec)
		return
	}
	raw, err := core.ReadFileCapped(real, m.opts.MaxFileSize)
	if err != nil {
		rec := m.envelope(logical, info, siteClass, userMode)
		rec.Errors = append(rec.Errors, core.RecordError{Field: "content_sha256", Code: errnoCode(err), Msg: err.Error()})
		if isDropin {
			rec.Signals = appendUnique(rec.Signals, core.SignalSystemdDropin)
		}
		emit(rec)
		return
	}
	if len(raw) == 0 {
		return
	}
	rec := m.buildRecord(logical, info, siteClass, userMode, raw)
	if isDropin {
		rec.Signals = appendUnique(rec.Signals, core.SignalSystemdDropin)
	}
	emit(rec)
}

// buildRecord assembles a fully populated Record from raw file bytes.
// File metadata is filled, the canonical form is computed, exec_target
// is resolved, and all module-specific signals are evaluated.
func (m *Module) buildRecord(logical string, info os.FileInfo, siteClass string, userMode bool, raw []byte) core.Record {
	canon := Normalize(raw)
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         siteClass,
		MITRE:             []string{mitreForSiteClass(siteClass)},
		Locus:             logical,
		ContentSHA256:     core.HashHex(raw),
		ContentNormSHA256: core.HashHex(canon),
		ContentSnippet:    snippet(string(canon)),
		FullExecLine:      string(canon), // Tier-B behavioral scan (ExecStart= lines)
	}
	core.FillFileMeta(&rec, info)

	sections, parseErrs := ParseUnitFile(raw)
	for _, pe := range parseErrs {
		rec.Errors = append(rec.Errors, core.RecordError{
			Field: "content",
			Code:  "PARSE_ERROR",
			Msg:   pe.Error(),
		})
	}

	target, multi, hasExec, resolved := m.resolveExecTarget(sections)
	if target != "" {
		rec.ExecTarget = target
		// Compute exec_target_sha256 and the orphan / interpreter /
		// recent_target_mtime signals against the real file.
		realTarget := m.resolve(target)
		ti, terr := os.Stat(realTarget)
		switch {
		case terr == nil && ti.Mode().IsRegular():
			// Use the hardened reader (O_NONBLOCK + fstat-regular +
			// MaxFileSize bound), consistent with the external-symlink
			// path below and every other module. realTarget is already
			// root-resolved.
			if sum, ok := core.HashFileCapped(realTarget, m.opts.MaxFileSize); ok {
				rec.ExecTargetSHA256 = sum
			}
			tdelta := m.opts.Now().Sub(ti.ModTime().UTC())
			if tdelta >= 0 && tdelta < 7*24*time.Hour {
				rec.Signals = appendUnique(rec.Signals, core.SignalRecentTargetMtime7d)
			}
		case errors.Is(terr, fs.ErrNotExist):
			rec.Signals = appendUnique(rec.Signals, core.SignalExecTargetOrphan)
		}
	}
	// A packaged interpreter ExecStart (/usr/bin/python3 /opt/x.py) running
	// a parked payload: exec_target is the owned interpreter, so the SCRIPT
	// ARGUMENT is otherwise invisible. Resolve it and check both halves of
	// the ownership/integrity asymmetry -- orphan AND owned-but-tampered.
	if arg, ok := core.InterpreterScriptArg(m.firstExecStartFields(sections)); ok {
		if _, st := m.opts.Provenance.LookupPath(arg); st == core.PkgStatusOrphan {
			rec.Signals = appendUnique(rec.Signals, core.SignalInterpreterRunsOrphanScript)
		}
		if v, ok := m.opts.Provenance.(interface {
			VerifyPath(string) core.PkgVerifyStatus
		}); ok {
			for _, s := range core.TamperSignal(v.VerifyPath(arg)) {
				rec.Signals = appendUnique(rec.Signals, s)
			}
		}
	}
	if m.auxExecUnmanaged(sections) {
		rec.Signals = appendUnique(rec.Signals, core.SignalSystemdAuxExecUnmanaged)
	}
	if hasExec && multi {
		rec.Signals = appendUnique(rec.Signals, core.SignalSystemdMultiExecStart)
	}
	if hasExec && !resolved && target == "" {
		rec.Signals = appendUnique(rec.Signals, core.SignalSystemdExecUnresolved)
	}
	if target != "" {
		if isInterpreterInTmp(target) {
			rec.Signals = appendUnique(rec.Signals, core.SignalInterpreterInTmp)
		}
		if isShellInterpreter(target) {
			rec.Signals = appendUnique(rec.Signals, core.SignalShellIndirect)
		}
		if !filepath.IsAbs(target) {
			rec.Signals = appendUnique(rec.Signals, core.SignalUnqualifiedExecTarget)
		}
	}

	// User-mode signal.
	if userMode {
		rec.Signals = appendUnique(rec.Signals, core.SignalSystemdUserUnit)
	}
	// Template-unit signal: the basename has "@" immediately before
	// the extension (e.g. foo@.service).
	if isTemplateUnit(logical) {
		rec.Signals = appendUnique(rec.Signals, core.SignalSystemdTemplateUnit)
	}
	// Install Alias= external signal.
	if m.hasExternalAlias(sections) {
		rec.Signals = appendUnique(rec.Signals, core.SignalSystemdInstallAliasExternal)
	}
	// getty/agetty/login autologin -- a console/serial credential bypass.
	if gettyAutologin(sections) {
		rec.Signals = appendUnique(rec.Signals, core.SignalGettyAutologin)
	}

	// Mtime-based signals on the locus file.
	now := m.opts.Now()
	mt := info.ModTime().UTC()
	delta := now.Sub(mt)
	switch {
	case delta >= 0 && delta < 7*24*time.Hour:
		rec.Signals = appendUnique(rec.Signals, core.SignalRecentMtime7d)
	case delta >= 7*24*time.Hour && delta < 30*24*time.Hour:
		rec.Signals = appendUnique(rec.Signals, core.SignalRecentMtime30d)
	}
	if info.Mode().Perm()&0o002 != 0 {
		rec.Signals = appendUnique(rec.Signals, core.SignalWorldWritable)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		// Non-root-owner signal applies only under system loci (any
		// /etc/, /usr/, /lib/, /run/ prefix). User-mode units under
		// /home/ /root/ are expected to be non-root-owned.
		if st.Uid != 0 && isSystemPath(logical) {
			rec.Signals = appendUnique(rec.Signals, core.SignalNonRootOwner)
		}
	}

	// Relationship edges (OnFailure=/Requires=/Wants= and [Path] watches
	// → activated unit) for backend/Q12 chain reconstruction. NOT a Q7
	// verdict — the payload arm is flagged independently by the
	// exec/orphan rules; this records the trigger→payload edge.
	if edges, relSigs := m.relationEdges(sections, logical); len(edges) > 0 {
		rec.Relations = edges
		for _, s := range relSigs {
			rec.Signals = appendUnique(rec.Signals, s)
		}
	}

	rec.Signals = core.DedupSignals(rec.Signals)
	core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
	core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
	return rec
}

// unitRefKeys are the [Unit] activation/trigger directives whose targets
// are captured as Relations edges. After=/Before= (pure ordering, no
// activation) are deliberately excluded. OnFailure= additionally raises a
// marker signal; Requires=/Wants= are edge-only (ubiquitous dependency
// links, no signal, so the human report and Q7 stay clean).
var unitRefKeys = []string{"OnFailure", "Requires", "Wants"}

// pathWatchKeys are the [Path] directives that arm a .path unit. When the
// watched filesystem event fires, systemd starts the activated unit.
var pathWatchKeys = []string{
	"PathModified", "PathChanged", "PathExists", "PathExistsGlob", "DirectoryNotEmpty",
}

// timerArmKeys are the [Timer] directives that schedule activation. A
// .timer with any of these starts its activated unit (Unit=, or the
// implicit <name>.service) -- the #1 cron-replacement persistence shape.
var timerArmKeys = []string{
	"OnCalendar", "OnBootSec", "OnStartupSec", "OnActiveSec", "OnUnitActiveSec", "OnUnitInactiveSec",
}

// socketListenKeys are the [Socket] directives that arm socket activation.
// A .socket with any of these starts its activated unit (Service=, or the
// implicit <name>.service) on the first connection.
var socketListenKeys = []string{
	"ListenStream", "ListenDatagram", "ListenSequentialPacket", "ListenFIFO",
	"ListenSpecial", "ListenNetlink", "ListenMessageQueue", "ListenUSBFunction",
}

// relationEdges extracts the trigger/dependency edges this unit declares
// and returns them as "Key=Value" strings plus any marker signals. The
// edges feed backend/Q12 chain reconstruction; they are never a Q7 input.
//
// Coverage: [Unit] OnFailure=/Requires=/Wants=, [Path] watch->Unit=,
// [Timer] schedule->Unit=, [Socket] listen->Service=, and [Service]
// EnvironmentFile=. The .timer and .socket edges complete the activation
// surface the .path branch started: the payload unit's ExecStart already
// surfaces via the orphan/non_package rules; these edges let the backend
// reconstruct trigger->payload for .timer/.socket the same way it does for
// .path. EnvironmentFile= is a pure correlation crumb (the file's RHS shell
// stays unparsed per the inline-code boundary, scope.md 8.1).
func (m *Module) relationEdges(sections []Section, logical string) (edges []string, sigs []string) {
	var hasOnFailure, hasPathWatch, pathUnitExplicit bool
	var hasTimerArm, timerUnitExplicit bool
	var hasSocketListen, socketUnitExplicit bool
	var pathUnit, timerUnit, socketUnit string
	for _, s := range sections {
		switch {
		case strings.EqualFold(s.Name, "Unit"):
			for _, e := range s.Entries {
				for _, k := range unitRefKeys {
					if !strings.EqualFold(e.Key, k) {
						continue
					}
					for _, tok := range strings.Fields(e.Value) {
						edges = append(edges, k+"="+tok)
					}
					if strings.EqualFold(k, "OnFailure") && strings.TrimSpace(e.Value) != "" {
						hasOnFailure = true
					}
				}
			}
		case strings.EqualFold(s.Name, "Path"):
			for _, e := range s.Entries {
				for _, k := range pathWatchKeys {
					if strings.EqualFold(e.Key, k) && strings.TrimSpace(e.Value) != "" {
						edges = append(edges, k+"="+strings.TrimSpace(e.Value))
						hasPathWatch = true
					}
				}
				if strings.EqualFold(e.Key, "Unit") && strings.TrimSpace(e.Value) != "" {
					pathUnit = strings.TrimSpace(e.Value)
					pathUnitExplicit = true
				}
			}
		case strings.EqualFold(s.Name, "Timer"):
			for _, e := range s.Entries {
				for _, k := range timerArmKeys {
					if strings.EqualFold(e.Key, k) && strings.TrimSpace(e.Value) != "" {
						hasTimerArm = true
					}
				}
				if strings.EqualFold(e.Key, "Unit") && strings.TrimSpace(e.Value) != "" {
					timerUnit = strings.TrimSpace(e.Value)
					timerUnitExplicit = true
				}
			}
		case strings.EqualFold(s.Name, "Socket"):
			for _, e := range s.Entries {
				for _, k := range socketListenKeys {
					if strings.EqualFold(e.Key, k) && strings.TrimSpace(e.Value) != "" {
						hasSocketListen = true
					}
				}
				if strings.EqualFold(e.Key, "Service") && strings.TrimSpace(e.Value) != "" {
					socketUnit = strings.TrimSpace(e.Value)
					socketUnitExplicit = true
				}
			}
		case strings.EqualFold(s.Name, "Service"):
			for _, e := range s.Entries {
				if strings.EqualFold(e.Key, "EnvironmentFile") && strings.TrimSpace(e.Value) != "" {
					// Strip a leading "-" (optional-file marker) like systemd does.
					v := strings.TrimPrefix(strings.TrimSpace(e.Value), "-")
					edges = append(edges, "EnvironmentFile="+v)
				}
			}
		}
	}
	if hasPathWatch {
		if !pathUnitExplicit {
			pathUnit = implicitPathUnit(logical)
		}
		if pathUnit != "" {
			edges = append(edges, "Unit="+pathUnit)
		}
		sigs = append(sigs, core.SignalSystemdPathTrigger)
	}
	if hasTimerArm {
		if !timerUnitExplicit {
			timerUnit = implicitUnitFor(logical, ".timer")
		}
		if timerUnit != "" {
			edges = append(edges, "Unit="+timerUnit)
		}
		sigs = append(sigs, core.SignalSystemdTimerTrigger)
	}
	if hasSocketListen {
		if !socketUnitExplicit {
			socketUnit = implicitUnitFor(logical, ".socket")
		}
		if socketUnit != "" {
			edges = append(edges, "Unit="+socketUnit)
		}
		sigs = append(sigs, core.SignalSystemdSocketTrigger)
	}
	if hasOnFailure {
		sigs = append(sigs, core.SignalSystemdHasOnFailure)
	}
	return edges, sigs
}

// implicitPathUnit returns the unit a .path file activates when it
// carries no explicit [Path] Unit=: systemd defaults to the same
// basename with a .service suffix (monitor.path → monitor.service).
func implicitPathUnit(logical string) string {
	return implicitUnitFor(logical, ".path")
}

// implicitUnitFor returns the implicit <name>.service a trigger unit
// activates when it names no explicit target: systemd maps foo.<ext> to
// foo.service. Returns "" if the basename does not carry the extension.
func implicitUnitFor(logical, ext string) string {
	base := filepath.Base(logical)
	if strings.HasSuffix(base, ext) {
		return strings.TrimSuffix(base, ext) + ".service"
	}
	return ""
}

// envelope returns a partially populated Record carrying file metadata
// and (when applicable) the user/dropin/template signals, but no
// content fields. Used when the file cannot be read.
func (m *Module) envelope(logical string, info os.FileInfo, siteClass string, userMode bool) core.Record {
	rec := core.Record{
		Module:    m.Name(),
		SiteClass: siteClass,
		MITRE:     []string{mitreForSiteClass(siteClass)},
		Locus:     logical,
	}
	if info != nil {
		core.FillFileMeta(&rec, info)
	}
	if userMode {
		rec.Signals = appendUnique(rec.Signals, core.SignalSystemdUserUnit)
	}
	if isTemplateUnit(logical) {
		rec.Signals = appendUnique(rec.Signals, core.SignalSystemdTemplateUnit)
	}
	return rec
}

func (m *Module) errorEnvelope(logical string, info os.FileInfo, siteClass string, userMode bool, errs []core.RecordError) core.Record {
	rec := m.envelope(logical, info, siteClass, userMode)
	rec.Errors = append(rec.Errors, errs...)
	return rec
}

// resolveExecTarget walks all sections, captures every ExecStart= and
// applies the empty-reset idiom, then resolves the first surviving
// command. Returns:
//   - path: the resolved executable path (absolute), or the bare
//     command if it did not resolve, or "" if no ExecStart= exists.
//   - multi: true if more than one surviving ExecStart= line.
//   - hasExec: true if any ExecStart= entry was present.
//   - resolved: true if the path is absolute OR a relative command
//     was found on the default PATH.
//
// auxExecUnmanaged reports whether any auxiliary Exec directive
// (ExecStartPre/StartPost/StopPost/Stop/Reload/Condition) names a first
// token that is orphan (missing), package-unowned, or under a tmp-class
// dir. resolveExecTarget only ever inspected the first ExecStart=, so
// these hooks -- the Turla drop-in `ExecStartPre=/opt/payload` injected
// into a vendor unit -- were unresolved. Gated on the suspicious
// co-indicator so legitimate ExecStartPre=/usr/bin/<packaged> stays quiet.
func (m *Module) auxExecUnmanaged(sections []Section) bool {
	isAux := func(k string) bool {
		switch {
		case strings.EqualFold(k, "ExecStartPre"),
			strings.EqualFold(k, "ExecStartPost"),
			strings.EqualFold(k, "ExecStopPost"),
			strings.EqualFold(k, "ExecStop"),
			strings.EqualFold(k, "ExecReload"),
			strings.EqualFold(k, "ExecCondition"):
			return true
		}
		return false
	}
	for _, s := range sections {
		for _, e := range s.Entries {
			if !isAux(e.Key) {
				continue
			}
			fields := strings.Fields(stripExecPrefixes(e.Value))
			if len(fields) == 0 {
				continue
			}
			tok := fields[0]
			if !strings.HasPrefix(tok, "/") {
				continue // bare/relative aux command: not resolved here
			}
			for _, d := range core.TmpDirs {
				if strings.HasPrefix(tok, d) {
					return true
				}
			}
			// Require the target to EXIST and be package-unowned: a parked
			// payload, NOT a vendor unit's reference to an optional/absent
			// binary. The latter (emergency.service, rescue.service, etc.)
			// floods on minimal/container bases where the optional binary
			// is simply not installed -- the lab caught exactly that. A
			// missing target is therefore skipped (its anomaly, if any, is
			// the main ExecStart's exec_target_orphan, not an aux hook).
			if _, err := os.Stat(m.resolve(tok)); err != nil {
				continue
			}
			if _, st := m.opts.Provenance.LookupPath(tok); st == core.PkgStatusOrphan {
				return true // present but package-unowned -> parked payload
			}
		}
	}
	return false
}

// gettyAutologin reports whether any Exec* line runs agetty/getty with
// --autologin / -a, or login with -f -- a console/serial credential
// bypass. Scans every Exec* value (a drop-in often adds the autologin via
// ExecStart= reset + a new ExecStart, or a different Exec verb).
func gettyAutologin(sections []Section) bool {
	for _, s := range sections {
		for _, e := range s.Entries {
			if !strings.HasPrefix(strings.ToLower(e.Key), "exec") {
				continue
			}
			fields := strings.Fields(stripExecPrefixes(e.Value))
			if len(fields) == 0 {
				continue
			}
			base := filepath.Base(fields[0])
			switch base {
			case "agetty", "getty":
				for _, f := range fields[1:] {
					if f == "--autologin" || f == "-a" || strings.HasPrefix(f, "--autologin=") {
						return true
					}
				}
			case "login":
				for _, f := range fields[1:] {
					if f == "-f" {
						return true
					}
				}
			}
		}
	}
	return false
}

// firstExecStartFields returns the whitespace-split tokens of the first
// surviving ExecStart= value (systemd prefixes stripped), or nil. Used by
// the interpreter_runs_orphan_script check, which needs the script
// argument that resolveExecTarget discards.
func (m *Module) firstExecStartFields(sections []Section) []string {
	var values []string
	for _, s := range sections {
		for _, e := range s.Entries {
			if strings.EqualFold(e.Key, "ExecStart") {
				values = append(values, e.Value)
			}
		}
	}
	survivors := applyEmptyReset(values)
	if len(survivors) == 0 {
		return nil
	}
	return strings.Fields(stripExecPrefixes(survivors[0]))
}

func (m *Module) resolveExecTarget(sections []Section) (path string, multi, hasExec, resolved bool) {
	var values []string
	for _, s := range sections {
		for _, e := range s.Entries {
			if strings.EqualFold(e.Key, "ExecStart") {
				values = append(values, e.Value)
			}
		}
	}
	if len(values) == 0 {
		return "", false, false, false
	}
	hasExec = true
	survivors := applyEmptyReset(values)
	if len(survivors) == 0 {
		return "", false, hasExec, false
	}
	multi = len(survivors) > 1
	first := stripExecPrefixes(survivors[0])
	fields := strings.Fields(first)
	if len(fields) == 0 {
		return "", multi, hasExec, false
	}
	cmd := fields[0]
	if strings.HasPrefix(cmd, "/") {
		return cmd, multi, hasExec, true
	}
	for _, p := range systemdDefaultPath {
		candidate := filepath.Join(p, cmd)
		if _, err := os.Stat(m.resolve(candidate)); err == nil {
			return candidate, multi, hasExec, true
		}
	}
	// Unresolved bare command. Per ADR-0007 §4 we leave exec_target
	// empty and signal the unresolution upstream.
	return "", multi, hasExec, false
}

// hasExternalAlias returns true iff any [Install] Alias= directive
// lists a token that does not resolve inside the walked loci.
func (m *Module) hasExternalAlias(sections []Section) bool {
	for _, s := range sections {
		if !strings.EqualFold(s.Name, "Install") {
			continue
		}
		for _, e := range s.Entries {
			if !strings.EqualFold(e.Key, "Alias") {
				continue
			}
			for _, tok := range strings.Fields(e.Value) {
				if filepath.IsAbs(tok) && !m.targetInsideWalkedLoci(tok) {
					return true
				}
			}
		}
	}
	return false
}

// targetInsideWalkedLoci returns true if abs is inside one of the
// known systemd locus directories. Used to classify a symlink target
// as internal (skip) or external (emit). The check is purely
// path-prefix based; it does not stat the target.
//
// /home/<user>/.config/systemd/user/<file> is the only per-user
// locus path shape: we match it explicitly rather than treating
// /home as a walked prefix, otherwise a symlink to an unrelated
// /home/<user>/<file> would be (incorrectly) skipped as internal.
func (m *Module) targetInsideWalkedLoci(abs string) bool {
	abs = filepath.Clean(abs)
	for _, prefix := range m.walkedLoci {
		p := filepath.Clean(prefix)
		if abs == p {
			return true
		}
		if strings.HasPrefix(abs, p+string(filepath.Separator)) {
			return true
		}
	}
	// /home/<user>/.config/systemd/user/<anything>
	const homePrefix = "/home/"
	if !strings.HasPrefix(abs, homePrefix) {
		return false
	}
	rest := abs[len(homePrefix):]
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return false
	}
	suffix := rest[slash:]
	switch {
	case suffix == "/.config/systemd/user":
		return true
	case strings.HasPrefix(suffix, "/.config/systemd/user/"):
		return true
	}
	return false
}
func mitreForSiteClass(siteClass string) string {
	switch siteClass {
	case "systemd.timer":
		return mitreSystemdTimer
	default:
		return mitreSystemdUnit
	}
}

// classifyExtension returns the site_class and extension for a unit
// filename, or ok=false if the file is not a recognized unit type.
func classifyExtension(name string) (siteClass, ext string, ok bool) {
	ext = filepath.Ext(name)
	if _, in := unitExtensions[ext]; in {
		return "systemd.unit", ext, true
	}
	if _, in := timerExtensions[ext]; in {
		return "systemd.timer", ext, true
	}
	return "", "", false
}

// classifyByLogical returns the site_class for a given logical path.
// Falls back to "systemd.unit" for filenames whose extension is not
// recognized; the caller is expected to have filtered already.
func classifyByLogical(logical string) string {
	sc, _, ok := classifyExtension(filepath.Base(logical))
	if !ok {
		return "systemd.unit"
	}
	return sc
}

// siteClassForDropinDir derives the site_class from a *.d directory
// name. e.g. "sshd.service.d" -> ("systemd.unit", true).
// "backup.timer.d" -> ("systemd.timer", true).
func siteClassForDropinDir(name string) (string, bool) {
	if !strings.HasSuffix(name, ".d") {
		return "", false
	}
	parent := strings.TrimSuffix(name, ".d")
	sc, _, ok := classifyExtension(parent)
	return sc, ok
}

// isTemplateUnit returns true iff the basename of logical contains a
// '@' immediately before its extension (the template-unit form, e.g.
// foo@.service).
func isTemplateUnit(logical string) bool {
	base := filepath.Base(logical)
	ext := filepath.Ext(base)
	if ext == "" {
		return false
	}
	stem := strings.TrimSuffix(base, ext)
	return strings.HasSuffix(stem, "@")
}

// stripExecPrefixes removes the leading systemd ExecStart= modifier
// characters (@, -, :, !, +). systemd allows them in any order and
// combination; the function consumes all known prefix chars from the
// front and trims any whitespace that follows.
func stripExecPrefixes(v string) string {
	v = strings.TrimLeft(v, " \t")
	for len(v) > 0 {
		c := v[0]
		if c == '@' || c == '-' || c == ':' || c == '!' || c == '+' {
			v = v[1:]
			continue
		}
		break
	}
	return strings.TrimLeft(v, " \t")
}

func isInterpreterInTmp(p string) bool {
	for _, prefix := range core.TmpDirs {
		if strings.HasPrefix(p, prefix) {
			return true
		}
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

func isSystemPath(p string) bool {
	for _, prefix := range []string{"/etc/", "/usr/", "/lib/", "/run/", "/var/lib/"} {
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
