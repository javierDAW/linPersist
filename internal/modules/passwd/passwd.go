// Package passwd implements the linpersist collector for local
// account persistence on Linux: /etc/passwd, /etc/shadow,
// /etc/group, /etc/gshadow.
//
// Site_classes emitted:
//
//   - passwd.user    one record per filtered passwd line
//   - passwd.shadow  one record per shadow line matching a filtered user
//   - passwd.group   one record per group line
//   - passwd.gshadow one record per gshadow line
//
// Privacy policy (ADR-0005): password hashes in /etc/shadow and
// /etc/gshadow are NEVER emitted. They are reduced to a status
// enum (set / locked / disabled / empty / unknown).
package passwd

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

const (
	mitrePasswd          = "T1136.001"
	mitreGroupPrivileged = "T1098.007"
)

// privilegedGroupSignals maps Linux group names whose membership grants
// privilege escalation (or read-everything access) to the signal that
// fires when a non-root user appears in their member list. See
// internal/core/signals.go for the full rationale per group.
var privilegedGroupSignals = map[string]string{
	"wheel":  core.SignalGroupWheelMembership,
	"sudo":   core.SignalGroupSudoMembership,
	"docker": core.SignalGroupDockerMembership,
	"adm":    core.SignalGroupAdmMembership,
	"lxd":    core.SignalGroupLxdMembership,
	"root":   core.SignalGroupRootMembership,
}

// nonRootMembers parses a sorted comma-separated group-member list and
// returns true if at least one member is not "root" and not empty.
// /etc/group's 4th field is the supplemental-member CSV; users with
// the group as their PRIMARY group don't appear there (they're listed
// in /etc/passwd's 4th field as a numeric gid). Per-line scope is
// fine for T1098.007 — supplemental membership is the documented
// vector for the implant we are surfacing.
func nonRootMembers(members string) bool {
	if members == "" {
		return false
	}
	for _, m := range strings.Split(members, ",") {
		if m == "" || m == "root" {
			continue
		}
		return true
	}
	return false
}

type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
	// Provenance annotates the exec_target shell field (when set on a
	// passwd.user record). Nil defaults to core.NoopProvenance.
	Provenance core.Provenance
	// LiveProcessSet membership check for the live_process_attached
	// signal. A shell of /usr/bin/zsh that is in the live set means
	// some user has an active shell session right now.
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

func (m *Module) Name() string { return "passwd" }

func (m *Module) SiteClasses() []string {
	return []string{
		"passwd.user", "passwd.shadow", "passwd.group",
		"passwd.group.privileged", "passwd.gshadow",
	}
}

// Collect reads the four passwd-family files in order. The set of
// "interesting" users built from /etc/passwd is reused to filter
// /etc/shadow so we only emit shadow records for users that passed
// the passwd filter.
func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error
	interesting := map[string]struct{}{}
	if err := m.collectPasswd(ctx, "/etc/passwd", interesting, emit); err != nil {
		errs = append(errs, err)
	}
	if err := m.collectShadow(ctx, "/etc/shadow", interesting, emit); err != nil {
		errs = append(errs, err)
	}
	if err := m.collectGroup(ctx, "/etc/group", emit); err != nil {
		errs = append(errs, err)
	}
	if err := m.collectGshadow(ctx, "/etc/gshadow", emit); err != nil {
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

// collectPasswd reads /etc/passwd, filters, and emits passwd.user
// records. Populates `interesting` with the usernames that passed
// the filter, for use by collectShadow.
func (m *Module) collectPasswd(ctx context.Context, logical string, interesting map[string]struct{}, emit func(core.Record)) error {
	raw, info, err := m.readFile(ctx, logical, "passwd.user", emit)
	if err != nil || raw == nil {
		return err
	}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if ctx.Err() != nil {
			return nil
		}
		pu, ok := parsePasswdLine(sc.Text())
		if !ok {
			continue
		}
		if !shouldEmitUser(pu) {
			continue
		}
		interesting[pu.user] = struct{}{}
		emit(m.recordFromPasswdUser(logical, info, pu))
	}
	return nil
}

func (m *Module) collectShadow(ctx context.Context, logical string, interesting map[string]struct{}, emit func(core.Record)) error {
	raw, info, err := m.readFile(ctx, logical, "passwd.shadow", emit)
	if err != nil || raw == nil {
		return err
	}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if ctx.Err() != nil {
			return nil
		}
		se, ok := parseShadowLine(sc.Text())
		if !ok {
			continue
		}
		if _, want := interesting[se.user]; !want {
			continue
		}
		emit(m.recordFromShadow(logical, info, se))
	}
	return nil
}

func (m *Module) collectGroup(ctx context.Context, logical string, emit func(core.Record)) error {
	raw, info, err := m.readFile(ctx, logical, "passwd.group", emit)
	if err != nil || raw == nil {
		return err
	}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if ctx.Err() != nil {
			return nil
		}
		ge, ok := parseGroupLine(sc.Text())
		if !ok {
			continue
		}
		emit(m.recordFromGroup(logical, info, ge))
	}
	return nil
}

func (m *Module) collectGshadow(ctx context.Context, logical string, emit func(core.Record)) error {
	raw, info, err := m.readFile(ctx, logical, "passwd.gshadow", emit)
	if err != nil || raw == nil {
		return err
	}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if ctx.Err() != nil {
			return nil
		}
		ge, ok := parseGshadowLine(sc.Text())
		if !ok {
			continue
		}
		emit(m.recordFromGshadow(logical, info, ge))
	}
	return nil
}

// readFile is a small helper that handles the common ENOENT /
// SIZE_LIMIT / EACCES paths shared by all four file readers.
// Returns (raw, info, nil) on a clean read of a regular file, or
// (nil, nil, err) when the caller should skip the locus.
func (m *Module) readFile(ctx context.Context, logical, siteClass string, emit func(core.Record)) ([]byte, os.FileInfo, error) {
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
		emit(m.envelopeRecord(logical, info, siteClass, []core.RecordError{
			{Field: "content_sha256", Code: "SIZE_LIMIT"},
		}))
		return nil, info, nil
	}
	raw, err := core.ReadFileCapped(real, m.opts.MaxFileSize)
	if err != nil {
		emit(m.envelopeRecord(logical, info, siteClass, []core.RecordError{
			{Field: "content_sha256", Code: errnoCode(err), Msg: err.Error()},
		}))
		return nil, info, nil
	}
	if len(raw) == 0 {
		return nil, info, nil
	}
	return raw, info, nil
}

func (m *Module) recordFromPasswdUser(logical string, info os.FileInfo, pu passwdUser) core.Record {
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         "passwd.user",
		MITRE:             []string{mitrePasswd},
		Locus:             logical,
		ContentSHA256:     core.HashHexString(pu.raw),
		ContentNormSHA256: core.HashHexString(pu.raw),
		ContentSnippet:    snippet(pu.raw),
		ExecTarget:        pu.shell,
	}
	core.FillFileMeta(&rec, info)
	signals := m.baseSignals(info, logical)
	if pu.uid == "0" && pu.user != "root" {
		signals = append(signals, core.SignalPasswdUIDZero)
	}
	signals = append(signals, m.execTargetSignals(pu.shell)...)
	if m.targetMtimeRecent(pu.shell) {
		signals = append(signals, core.SignalRecentTargetMtime7d)
	}
	rec.Signals = core.DedupSignals(signals)
	core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
	core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
	return rec
}

func (m *Module) recordFromShadow(logical string, info os.FileInfo, se shadowEntry) core.Record {
	// Per ADR-0005: BOTH content_sha256 and content_norm_sha256 are
	// computed over the canonical (hash-stripped) form. The raw hash
	// never enters any sha256 input.
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         "passwd.shadow",
		MITRE:             []string{mitrePasswd},
		Locus:             logical,
		ContentSHA256:     core.HashHexString(se.canon),
		ContentNormSHA256: core.HashHexString(se.canon),
		ContentSnippet:    snippet(se.canon),
	}
	core.FillFileMeta(&rec, info)
	signals := m.baseSignals(info, logical)
	if se.status == "empty" {
		signals = append(signals, core.SignalPasswdNoPassword)
	}
	rec.Signals = core.DedupSignals(signals)
	return rec
}

func (m *Module) recordFromGroup(logical string, info os.FileInfo, ge groupEntry) core.Record {
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         "passwd.group",
		MITRE:             []string{mitrePasswd},
		Locus:             logical,
		ContentSHA256:     core.HashHexString(ge.raw),
		ContentNormSHA256: core.HashHexString(ge.canon),
		ContentSnippet:    snippet(ge.canon),
	}
	core.FillFileMeta(&rec, info)
	signals := m.baseSignals(info, logical)

	// T1098.007 reclassification: if the group name is on the
	// privileged list AND at least one non-root user is listed as a
	// supplemental member, the record is reclassified to the
	// passwd.group.privileged site_class so MITRE coverage tracks
	// T1098.007 independently of T1136.001 in the fleet-wide panel.
	// Records for privileged groups with only root (or empty
	// membership) remain under passwd.group — they are baseline
	// system shape, not an escalation pivot.
	if sig, ok := privilegedGroupSignals[ge.name]; ok && nonRootMembers(ge.members) {
		rec.SiteClass = "passwd.group.privileged"
		rec.MITRE = []string{mitrePasswd, mitreGroupPrivileged}
		signals = append(signals, sig)
	}
	rec.Signals = core.DedupSignals(signals)
	return rec
}

func (m *Module) recordFromGshadow(logical string, info os.FileInfo, ge gshadowEntry) core.Record {
	// Same ADR-0005 policy as shadow: hash never enters any sha256.
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         "passwd.gshadow",
		MITRE:             []string{mitrePasswd},
		Locus:             logical,
		ContentSHA256:     core.HashHexString(ge.canon),
		ContentNormSHA256: core.HashHexString(ge.canon),
		ContentSnippet:    snippet(ge.canon),
	}
	core.FillFileMeta(&rec, info)
	rec.Signals = core.DedupSignals(m.baseSignals(info, logical))
	return rec
}

func (m *Module) envelopeRecord(logical string, info os.FileInfo, siteClass string, errs []core.RecordError) core.Record {
	rec := core.Record{
		Module:    m.Name(),
		SiteClass: siteClass,
		MITRE:     []string{mitrePasswd},
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
	for _, prefix := range core.TmpDirs {
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
