package pkgrepo

import (
	"bufio"
	"net/url"
	"strings"

	"github.com/jarmidaw/linpersist/internal/core"
)

// parseApt handles both the one-line sources.list format and the deb822
// .sources stanza format. A .list file yields entries only from the
// one-line pass; a .sources file only from the deb822 pass — running both
// on either is harmless (the other yields nothing).
func parseApt(raw []byte) []repoEntry {
	var out []repoEntry
	text := string(raw)

	// One-line: `deb [opt=val ...] <uri> <suite> <components...>`.
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		first := line
		if i := strings.IndexAny(line, " \t"); i >= 0 {
			first = line[:i]
		}
		if first != "deb" && first != "deb-src" {
			continue
		}
		rest := strings.TrimSpace(line[len(first):])
		trusted := false
		// Optional [k=v k=v] options block.
		if strings.HasPrefix(rest, "[") {
			if end := strings.IndexByte(rest, ']'); end >= 0 {
				opts := rest[1:end]
				trusted = aptOptTrusted(opts)
				rest = strings.TrimSpace(rest[end+1:])
			}
		}
		uri := firstField(rest)
		out = append(out, repoEntry{snippet: line, signals: repoSignals(trusted, uri)})
	}

	// deb822: stanzas separated by blank lines; keys Types/URIs/Trusted.
	for _, stanza := range strings.Split(text, "\n\n") {
		var isRepo, trusted bool
		var uris, snip string
		for _, ln := range strings.Split(stanza, "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" || strings.HasPrefix(ln, "#") {
				continue
			}
			k, v, ok := splitKV(ln, ':')
			if !ok {
				continue
			}
			switch strings.ToLower(k) {
			case "types":
				isRepo = true
				if snip == "" {
					snip = ln
				}
			case "uris":
				uris = v
				if snip == "" {
					snip = ln
				}
			case "trusted":
				trusted = strings.EqualFold(strings.TrimSpace(v), "yes")
			case "enabled":
				if strings.EqualFold(strings.TrimSpace(v), "no") {
					isRepo = false
				}
			}
		}
		if !isRepo {
			continue
		}
		for _, u := range strings.Fields(uris) {
			if sigs := repoSignals(trusted, u); len(sigs) > 0 {
				out = append(out, repoEntry{snippet: snip, signals: sigs})
			}
		}
	}
	return out
}

// parseYum handles the INI .repo format (yum/dnf/zypp).
func parseYum(raw []byte) []repoEntry {
	var out []repoEntry
	var section string
	enabled, gpgcheck := true, true
	var url, snip string
	flush := func() {
		if section == "" || !enabled {
			section, enabled, gpgcheck, url, snip = "", true, true, "", ""
			return
		}
		var sigs []string
		if !gpgcheck {
			sigs = append(sigs, core.SignalRepoGpgcheckDisabled)
		}
		if url != "" && !canonicalOrLocal(url) {
			sigs = append(sigs, core.SignalRepoOriginAdded)
		}
		if len(sigs) > 0 {
			out = append(out, repoEntry{snippet: snip, signals: sigs})
		}
		section, enabled, gpgcheck, url, snip = "", true, true, "", ""
	}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flush()
			section = line
			snip = line
			continue
		}
		k, v, ok := splitKV(line, '=')
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "enabled":
			enabled = v != "0"
		case "gpgcheck":
			gpgcheck = v != "0"
		case "baseurl", "metalink", "mirrorlist":
			if url == "" {
				url = firstField(v)
			}
		}
	}
	flush()
	return out
}

// repoSignals returns the tells for an apt entry given its trusted flag and
// base URI.
func repoSignals(trusted bool, uri string) []string {
	var sigs []string
	if trusted {
		sigs = append(sigs, core.SignalRepoGpgcheckDisabled)
	}
	if uri != "" && !canonicalOrLocal(uri) {
		sigs = append(sigs, core.SignalRepoOriginAdded)
	}
	return sigs
}

// aptOptTrusted reports whether an apt options block carries trusted=yes.
func aptOptTrusted(opts string) bool {
	for _, f := range strings.Fields(opts) {
		if k, v, ok := splitKV(f, '='); ok && strings.EqualFold(strings.TrimSpace(k), "trusted") &&
			strings.EqualFold(strings.TrimSpace(v), "yes") {
			return true
		}
	}
	return false
}

// canonicalOrLocal reports whether a repo URL is a distro/vendor-canonical
// network host OR a local (file:/cdrom:/mirror+file:) source -- i.e. NOT an
// attacker-style added origin. Unparseable or non-network schemes are
// treated as local (no origin signal).
func canonicalOrLocal(raw string) bool {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return true // can't classify -> don't raise the signal
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "ftp", "rsync":
		host := strings.ToLower(u.Hostname())
		_, ok := canonicalRepoHosts[host]
		return ok
	default:
		// file:, cdrom:, mirror+file:, copy:, or a bare path -> local.
		return true
	}
}

func firstField(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}

func splitKV(s string, sep byte) (string, string, bool) {
	i := strings.IndexByte(s, sep)
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
}
