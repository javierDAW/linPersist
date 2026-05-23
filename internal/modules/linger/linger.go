// Package linger implements the linpersist collector for systemd
// user lingering -- the mechanism that lets a user's systemd --user
// units keep running after the user logs out.
//
// Site_class emitted:
//
//   - systemd.linger   /var/lib/systemd/linger/<username>. The mere
//     presence of a file there means linger is enabled for that
//     user. Documented persistence vector (PANIX, Mandiant): an
//     attacker who can write to /var/lib/systemd/linger/<low-priv>
//     enables that user's systemd user units to run without an
//     interactive session. Pair with xdg.autostart or with custom
//     user units under ~/.config/systemd/user/ (systemd.unit module
//     already walks those).
//
// MITRE T1546 (Event Triggered Execution, parent). ATT&CK has no
// dedicated sub-technique for systemd-linger as of May 2026.
package linger

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

const (
	siteClass  = "systemd.linger"
	mitre      = "T1546"
	lingerRoot = "/var/lib/systemd/linger"
)

// Options configures a Module instance.
type Options struct {
	Root string
	Now  func() time.Time
}

// Module collects systemd linger state.
type Module struct{ opts Options }

// New constructs a Module with default fallbacks.
func New(opts Options) *Module {
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Module{opts: opts}
}

// Compile-time interface conformance.
var _ core.Module = (*Module)(nil)

// Name returns "linger".
func (m *Module) Name() string { return "linger" }

// SiteClasses returns the single site_class this module emits.
func (m *Module) SiteClasses() []string { return []string{siteClass} }

// Collect walks /var/lib/systemd/linger and emits one record per
// linger-enabled user.
func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	real := lingerRoot
	if m.opts.Root != "" {
		real = filepath.Join(m.opts.Root, lingerRoot)
	}
	entries, err := os.ReadDir(real)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("readdir %s: %w", lingerRoot, err)
	}
	for _, e := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if e.IsDir() {
			continue
		}
		username := e.Name()
		logical := filepath.Join(lingerRoot, username)
		realPath := filepath.Join(real, username)
		info, err := os.Lstat(realPath)
		if err != nil {
			continue
		}
		emit(m.record(logical, username, info))
	}
	return nil
}

func (m *Module) record(logical, username string, info os.FileInfo) core.Record {
	// content_norm is the username only -- the file's body is
	// systemd-managed and always empty, so the discriminator for
	// stacking has to be the username itself. content_sha256 also
	// uses the username for parity (no semantic loss; the body is
	// empty by contract).
	canon := username
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         siteClass,
		MITRE:             []string{mitre},
		Locus:             logical,
		ContentSHA256:     core.HashHexString(canon),
		ContentNormSHA256: core.HashHexString(canon),
		ContentSnippet:    username,
	}
	core.FillFileMeta(&rec, info)
	rec.Signals = core.DedupSignals(append(m.baseSignals(info, logical), perUserSignals(username)...))
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
		if st.Uid != 0 {
			out = append(out, core.SignalNonRootOwner)
		}
	}
	return out
}

// perUserSignals fires the linger-specific signal for any username
// other than "root". root-with-linger is a baseline (no-op since
// root sessions never time out the way regular users do); any
// non-root user with linger enabled means their user-mode systemd
// units survive logout -- the persistence vector this module exists
// to surface.
func perUserSignals(username string) []string {
	if username == "" || username == "root" {
		return nil
	}
	return []string{core.SignalSystemdLingerNonRoot}
}
