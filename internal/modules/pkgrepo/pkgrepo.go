// Package pkgrepo collects package-MANAGER REPOSITORY configuration — the
// supply-chain surface ADR-0016 names as the "provenance trusts the package
// DB" assumption. A disk-walk agent cannot attest signatures or detect a
// poisoned upstream (that is Regime 3 / SBOM territory), but it CAN surface
// the two on-disk repo-config tells that turn the package manager into an
// attacker-controlled install channel:
//
//   - repo_gpgcheck_disabled — an apt `[trusted=yes]` / deb822 `Trusted: yes`
//     or a yum/dnf `gpgcheck=0`: the repo accepts UNSIGNED packages, so an
//     attacker who can MITM or stand up a mirror gets arbitrary root code at
//     the next apt/dnf run. Low legitimate prevalence; this is the high-signal
//     tell and the only one promoted to a Q7 verdict.
//   - repo_origin_added — an enabled repo whose base host is NOT in the small
//     embedded distro/vendor-canonical allowlist. Third-party repos (Docker,
//     NodeSource, corporate mirrors) are common and structurally identical to
//     an attacker repo, so this is SIGNAL-ONLY (LFA discriminates the rare
//     singleton); never a standalone verdict.
//
// A record is emitted ONLY when one of these signals applies, so a stock
// repo set (signed, canonical host) yields nothing — zero FP by construction.
// MITRE T1195.001 (Supply Chain Compromise: Software Dependencies and
// Development Tools) / T1546.016.
package pkgrepo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

const (
	mitreSupplyChain = "T1195.001"

	siteClassApt = "pkgrepo.apt"
	siteClassYum = "pkgrepo.yum"
)

// aptLoci / yumLoci are the repo-config globs.
var aptLoci = []string{"/etc/apt/sources.list", "/etc/apt/sources.list.d/*.list", "/etc/apt/sources.list.d/*.sources"}
var yumLoci = []string{"/etc/yum.repos.d/*.repo", "/etc/dnf/repos.d/*.repo", "/etc/zypp/repos.d/*.repo"}

// canonicalRepoHosts is the small allowlist of distro/vendor-canonical
// mirror hosts. A repo whose base URL host is outside this set (and not a
// mirror:// / file: scheme) raises repo_origin_added (signal-only). Kept
// deliberately conservative and distro-official; third-party repos are
// expected to trip the signal and be discriminated by LFA, not by growing
// this list forever.
var canonicalRepoHosts = map[string]struct{}{
	"deb.debian.org": {}, "security.debian.org": {}, "ftp.debian.org": {},
	"archive.ubuntu.com": {}, "security.ubuntu.com": {}, "ports.ubuntu.com": {},
	"dl.rockylinux.org": {}, "download.rockylinux.org": {}, "dl.almalinux.org": {}, "repo.almalinux.org": {},
	"dl.fedoraproject.org": {}, "download.fedoraproject.org": {}, "mirrors.fedoraproject.org": {},
	"download.opensuse.org": {}, "dl.google.com": {},
}

const DefaultMaxFileSize = 1 << 20

type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
	// Provenance/LiveProcessSet are unused (pkgrepo emits no exec_target)
	// but accepted for modset API symmetry.
	Provenance     core.Provenance
	LiveProcessSet core.LiveProcessSet
}

type Module struct{ opts Options }

func New(opts Options) *Module {
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = DefaultMaxFileSize
	}
	return &Module{opts: opts}
}

var _ core.Module = (*Module)(nil)

func (m *Module) Name() string { return "pkgrepo" }

func (m *Module) SiteClasses() []string { return []string{siteClassApt, siteClassYum} }

func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error
	if err := m.walk(ctx, aptLoci, siteClassApt, parseApt, emit); err != nil {
		errs = append(errs, err)
	}
	if err := m.walk(ctx, yumLoci, siteClassYum, parseYum, emit); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (m *Module) resolve(p string) string {
	if m.opts.Root == "" {
		return p
	}
	return filepath.Join(m.opts.Root, p)
}

func (m *Module) logicalize(real string) string {
	if m.opts.Root == "" {
		return real
	}
	if rel, err := filepath.Rel(m.opts.Root, real); err == nil {
		return "/" + rel
	}
	return real
}

// repoEntry is one parsed repo declaration (an apt deb line / deb822 stanza,
// or a yum [section]); signals lists the tells that apply.
type repoEntry struct {
	snippet string
	signals []string
}

type parseFn func(raw []byte) []repoEntry

func (m *Module) walk(ctx context.Context, loci []string, siteClass string, parse parseFn, emit func(core.Record)) error {
	seen := map[string]struct{}{}
	for _, pat := range loci {
		matches, err := filepath.Glob(m.resolve(pat))
		if err != nil {
			continue
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
			if err != nil || !info.Mode().IsRegular() || info.Size() > m.opts.MaxFileSize {
				continue
			}
			raw, err := core.ReadFileCapped(real, m.opts.MaxFileSize)
			if err != nil || len(raw) == 0 {
				continue
			}
			logical := m.logicalize(real)
			for _, e := range parse(raw) {
				if len(e.signals) == 0 {
					continue // clean repo entry -> no record (zero FP)
				}
				emit(m.recordFor(siteClass, logical, info, e))
			}
		}
	}
	return nil
}

func (m *Module) recordFor(siteClass, logical string, info os.FileInfo, e repoEntry) core.Record {
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         siteClass,
		MITRE:             []string{mitreSupplyChain},
		Locus:             logical,
		ContentSHA256:     core.HashHexString(e.snippet),
		ContentNormSHA256: core.HashHexString(e.snippet),
		ContentSnippet:    snippet(e.snippet),
	}
	core.FillFileMeta(&rec, info)
	rec.Signals = core.DedupSignals(append(m.baseSignals(info, logical), e.signals...))
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

func snippet(s string) string {
	const max = 256
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max]
}
