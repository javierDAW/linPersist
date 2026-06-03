// Package initramfs implements the linpersist collector for early-boot
// initramfs/initrd hook persistence on Linux.
//
// Site_classes emitted:
//
//   - boot.initramfs.hook   one record per regular file found in the
//     hook/script directories of every major Linux initramfs
//     generator. Each such file is a script the generator copies into
//     the initrd image and runs AS ROOT very early at boot — before
//     the real root filesystem is mounted — so it is a high-value,
//     hard-to-spot persistence and pre-OS-boot locus. ExecTarget is
//     the file itself (the generator runs/sources it), so provenance
//     (non_package_path) and the central package_file_tampered /
//     recent_ctime signals apply directly.
//
// The module is generator-agnostic. It walks the hook directories of
// the three generators that, between them, cover essentially every
// mainstream Linux distribution:
//
//   - initramfs-tools  Debian, Ubuntu, Mint, Devuan, Pop!_OS, Kali,
//     Raspberry Pi OS
//   - dracut           RHEL/CentOS/Rocky/Alma, Fedora, openSUSE/SLES,
//     Mageia, modern Gentoo
//   - mkinitcpio       Arch, Manjaro, EndeavourOS, Artix
//
// Both the package-shipped default dirs (under /usr) and the local
// admin override dirs (under /etc) are walked. On a stock host the
// /etc dirs are empty, so any file there is an admin/attacker addition
// that surfaces via non_package_path; the /usr dirs are full of
// package-owned hooks that stack fleet-identically (no noise) and are
// covered for in-place tampering by the sink's package_file_tampered
// signal — the Bootkit-style overwrite an orphan-path check misses.
//
// MITRE T1542 (Pre-OS Boot). ATT&CK has no Linux-specific initramfs
// sub-technique as of June 2026; documented in matrix.yaml notes.
//
// Out of scope (documented boundary, mirrors scope.md): the COMPILED
// initrd image (/boot/initrd.img*, the cpio) is not unpacked, and the
// config-file file-baking vector (dracut.conf.d install_items+=,
// mkinitcpio.conf FILES=/BINARIES=) is a different shape than an
// executable hook and is left to its own future extension. This module
// covers the executable-hook surface, which is the common, unified
// model across all three generators.
package initramfs

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
	mitreInitramfs = "T1542"

	siteClassHook = "boot.initramfs.hook"
)

// hookDirs enumerates the executable-hook/script directories of every
// major Linux initramfs generator. Each is walked RECURSIVELY (dracut
// nests one level under modules.d/<NN>name/; initramfs-tools nests its
// scripts under per-stage subdirs), and every regular file found is a
// boot.initramfs.hook record. Missing dirs are silent — a given host
// runs exactly one generator, so most of these never exist.
var hookDirs = []string{
	// initramfs-tools (Debian/Ubuntu family). Local admin dirs first
	// (empty on a stock host), then the package defaults.
	"/etc/initramfs-tools/hooks",
	"/etc/initramfs-tools/scripts",
	"/usr/share/initramfs-tools/hooks",
	"/usr/share/initramfs-tools/scripts",

	// dracut (RHEL/Fedora/SUSE/Gentoo). Custom modules are dropped into
	// modules.d/<NN>name/ alongside the package-shipped ones, so the
	// package tree itself must be walked to catch a planted module.
	"/usr/lib/dracut/modules.d",
	"/etc/dracut/modules.d",

	// mkinitcpio (Arch family). install/ hooks run at build time,
	// hooks/ at boot; both are sourced shell scripts.
	"/etc/initcpio/hooks",
	"/etc/initcpio/install",
	"/usr/lib/initcpio/hooks",
	"/usr/lib/initcpio/install",
}

// DefaultMaxFileSize bounds one hook file. Hook scripts are small;
// 1 MiB is generous and matches the profile module's cap.
const DefaultMaxFileSize = 1 << 20

// Options configures the initramfs module.
type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
	// Dirs overrides hookDirs (test harness / operator scope tuning).
	Dirs []string
	// Provenance annotates each hook's path. The package-shipped hooks
	// come from initramfs-tools-core / dracut / mkinitcpio; a hook with
	// no owning package (non_package_path) on the early-boot surface is
	// a high-signal indicator.
	Provenance core.Provenance
	// LiveProcessSet is informational here — initramfs hooks run at boot
	// and are not normally resident processes at snapshot time — but is
	// wired for API symmetry with every other module.
	LiveProcessSet core.LiveProcessSet
}

// Module collects initramfs/initrd early-boot hook persistence sites.
type Module struct{ opts Options }

// New constructs an initramfs Module with default fallbacks.
func New(opts Options) *Module {
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = DefaultMaxFileSize
	}
	if len(opts.Dirs) == 0 {
		opts.Dirs = hookDirs
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
func (m *Module) Name() string { return "initramfs" }

// SiteClasses returns the single class this module emits.
func (m *Module) SiteClasses() []string {
	return []string{siteClassHook}
}

// Collect walks every configured hook directory recursively and emits
// one record per regular file. Missing dirs are silent.
func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error
	for _, d := range m.opts.Dirs {
		if err := m.walkDir(ctx, d, emit); err != nil {
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

// logicalize strips the test/scan root prefix back off a real path so
// the emitted Locus is the host-absolute path regardless of --root.
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

func (m *Module) walkDir(ctx context.Context, logicalDir string, emit func(core.Record)) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	realDir := m.resolve(logicalDir)
	if _, err := os.Lstat(realDir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("lstat %s: %w", logicalDir, err)
	}
	return filepath.WalkDir(realDir, func(real string, d fs.DirEntry, err error) error {
		if err != nil {
			// Unreadable subtree: skip it but keep walking siblings.
			if errors.Is(err, fs.ErrPermission) {
				return nil
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			return nil
		}
		// Only regular files are hooks. WalkDir uses lstat, so symlinks
		// report as non-regular and are skipped (a symlinked hook is
		// followed by its target's own record where it lives).
		if !d.Type().IsRegular() {
			return nil
		}
		name := d.Name()
		if skipName(name) {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		m.processFile(real, info, emit)
		return nil
	})
}

func (m *Module) processFile(real string, info os.FileInfo, emit func(core.Record)) {
	logical := m.logicalize(real)
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
	sum := core.HashHex(raw)
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         siteClassHook,
		MITRE:             []string{mitreInitramfs},
		Locus:             logical,
		ContentSHA256:     sum,
		ContentNormSHA256: sum,
		ContentSnippet:    snippet(string(raw)),
		// The hook IS the persistence target — the generator runs/sources
		// it at boot. ExecTarget=self lets provenance flag a non-package
		// hook and lets Q9/Q12 correlate it like any other exec target.
		ExecTarget:       logical,
		ExecTargetSHA256: sum,
	}
	core.FillFileMeta(&rec, info)
	rec.Signals = core.DedupSignals(m.baseSignals(info, logical))
	// Provenance on the hook itself: a script under any of these dirs
	// with no owning package is the planted-hook shape. AnnotateExec...
	// appends non_package_path when orphan; re-finalize signals after.
	core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
	core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
	rec.Signals = core.DedupSignals(rec.Signals)
	emit(rec)
}

func (m *Module) envelopeRecord(logical string, info os.FileInfo, errs []core.RecordError) core.Record {
	rec := core.Record{
		Module:    m.Name(),
		SiteClass: siteClassHook,
		MITRE:     []string{mitreInitramfs},
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
		if st.Uid != 0 {
			out = append(out, core.SignalNonRootOwner)
		}
	}
	return out
}

// skipName mirrors the convention every other module uses: hide
// dotfiles, editor backups, and dpkg/rpm packaging leftovers. (A real
// attacker payload is rarely a dotfile here; the cost of skipping them
// is near-zero and matches dbus/profile/etc.)
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
	if errors.Is(err, fs.ErrNotExist) {
		return "ENOENT"
	}
	if errors.Is(err, fs.ErrPermission) {
		return "EACCES"
	}
	return "IO_ERROR"
}
