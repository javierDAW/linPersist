// Package webroot collects web-executable files under DocumentRoot-style
// paths -- the webshell surface (handoff "Still OPEN"). It is a pure
// COLLECTOR: it emits one record per candidate file with its content hash
// and a couple of cheap structural co-indicators, and ships NO detection.
//
// Why no detection (and no provenance): web content is almost never
// package-owned (WordPress, Drupal, vendored composer/npm trees, bespoke
// apps), so non_package_path is structurally always-true here and would
// flood -- it is deliberately NOT computed. Content heuristics
// (eval/base64 scanning) are the inline-code arms race scope.md 8.1
// forbids. So the discriminator is left to the backend: LFA content-hash
// SINGLETON-ness across a heterogeneous fleet (a webshell dropped on one
// host is the rare hash among a fleet of identical app servers), ranked by
// the recorded co-indicators recent_mtime_7d / world_writable. The agent's
// job is faithful collection; the backend decides (ADR-0001).
//
// MITRE T1505.003 (Server Software Component: Web Shell).
package webroot

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

const (
	mitreWebshell = "T1505.003"
	siteClass     = "webroot.script"
)

// docRoots are the conventional web document roots walked recursively.
var docRoots = []string{
	"/var/www", "/var/www/html", "/srv/www", "/srv/http",
	"/usr/share/nginx/html", "/usr/share/apache2/default-site",
	"/var/lib/tomcat/webapps", "/opt/lampp/htdocs",
}

// webExt is the set of server-executable extensions a webshell uses.
var webExt = map[string]struct{}{
	".php": {}, ".phtml": {}, ".php3": {}, ".php4": {}, ".php5": {}, ".php7": {}, ".phar": {},
	".jsp": {}, ".jspx": {}, ".asp": {}, ".aspx": {}, ".ashx": {}, ".cfm": {},
}

// DefaultMaxFileSize caps one hashed file; DefaultMaxRecords bounds the
// whole walk so a pathological docroot cannot blow up a point-in-time run.
const (
	DefaultMaxFileSize = 1 << 20
	DefaultMaxRecords  = 20000
)

type Options struct {
	Root        string
	Now         func() time.Time
	MaxFileSize int64
	MaxRecords  int
	Roots       []string
	// Provenance/LiveProcessSet accepted for modset symmetry but UNUSED:
	// web content is never package-owned, so provenance is meaningless here.
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
	if opts.MaxRecords <= 0 {
		opts.MaxRecords = DefaultMaxRecords
	}
	if len(opts.Roots) == 0 {
		opts.Roots = docRoots
	}
	return &Module{opts: opts}
}

var _ core.Module = (*Module)(nil)

func (m *Module) Name() string { return "webroot" }

func (m *Module) SiteClasses() []string { return []string{siteClass} }

func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	var errs []error
	emitted := 0
	seen := map[string]struct{}{}
	for _, root := range m.opts.Roots {
		realRoot := m.resolve(root)
		err := filepath.WalkDir(realRoot, func(real string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // unreadable subtree: skip, keep walking
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if emitted >= m.opts.MaxRecords {
				return fs.SkipAll
			}
			if d.IsDir() || !d.Type().IsRegular() {
				return nil
			}
			if !isWebScript(d.Name()) {
				return nil
			}
			if _, dup := seen[real]; dup {
				return nil
			}
			seen[real] = struct{}{}
			info, ierr := d.Info()
			if ierr != nil || info.Size() > m.opts.MaxFileSize {
				return nil
			}
			raw, rerr := core.ReadFileCapped(real, m.opts.MaxFileSize)
			if rerr != nil || len(raw) == 0 {
				return nil
			}
			emit(m.recordFor(m.logicalize(real), info, raw))
			emitted++
			return nil
		})
		if err != nil && !errors.Is(err, fs.SkipAll) {
			errs = append(errs, err)
		}
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

func (m *Module) recordFor(logical string, info fs.FileInfo, raw []byte) core.Record {
	sum := core.HashHex(raw)
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         siteClass,
		MITRE:             []string{mitreWebshell},
		Locus:             logical,
		ContentSHA256:     sum,
		ContentNormSHA256: sum, // raw hash IS the LFA pivot here
		ContentSnippet:    snippet(string(raw)),
	}
	core.FillFileMeta(&rec, info)
	rec.Signals = core.DedupSignals(m.coIndicators(info))
	return rec
}

// coIndicators emits only the cheap structural tells that RANK a webshell
// for the backend's LFA pass: recent_mtime_* and world_writable. It does
// NOT emit non_root_owner -- web content is owned by www-data/apache by
// design, so that signal would fire on every file and rank nothing.
func (m *Module) coIndicators(info fs.FileInfo) []string {
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
	return out
}

func isWebScript(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	if _, ok := webExt[ext]; ok {
		return true
	}
	// CGI scripts (.pl/.cgi/.py/.sh) only count under a cgi-bin path; the
	// caller already restricts to docroots, but the extension set for CGI
	// is broad, so gate it on the conventional cgi-bin marker via name.
	return ext == ".cgi"
}

func snippet(s string) string {
	const max = 256
	if len(s) <= max {
		return s
	}
	return s[:max]
}
