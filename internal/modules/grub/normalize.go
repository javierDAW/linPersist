package grub

import (
	"bufio"
	"bytes"
	"strings"
)

// NormalizeConfigLine returns the canonical form of one
// /etc/default/grub line. The grub default file uses shell-style
// `KEY=VALUE` syntax with optional `export KEY=VALUE` prefix.
//
// Rules:
//   - Leading `export ` keyword is dropped (cosmetic).
//   - Surrounding double or single quotes around the VALUE are
//     preserved as-is (they affect how grub-mkconfig parses
//     embedded whitespace).
//   - Trailing whitespace is stripped.
//
// Two grub default lines that differ only in the optional `export`
// keyword produce the same canonical bytes.
func NormalizeConfigLine(line string) string {
	line = strings.TrimRight(line, " \t")
	trimmed := strings.TrimLeft(line, " \t")
	if strings.HasPrefix(trimmed, "export ") {
		trimmed = strings.TrimSpace(trimmed[len("export "):])
	}
	return trimmed
}

// ParseConfigLines returns the per-line records of a /etc/default/grub
// file. Each entry is one (key, raw_value, canonical_line) triple.
// Comment-only and blank lines are dropped. Multi-line values (the
// `\` continuation form) are joined before splitting on `=`.
//
// The function is permissive: a line without `=` is reported as a
// record with key="" and the raw line preserved, so a hand-edited
// stray fragment still surfaces in NDJSON for the analyst to see.
type ConfigEntry struct {
	Raw   string // the line as it appears on disk, before normalize
	Canon string // the canonical form of the line (post-normalize)
	Key   string // everything before the first '='
	Value string // everything after the first '='
}

// ParseConfig walks raw bytes of /etc/default/grub and returns one
// ConfigEntry per non-empty non-comment line.
func ParseConfig(raw []byte) []ConfigEntry {
	var out []ConfigEntry
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var pending strings.Builder
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Honor backslash-newline continuations.
		if strings.HasSuffix(line, "\\") {
			pending.WriteString(strings.TrimSuffix(line, "\\"))
			continue
		}
		if pending.Len() > 0 {
			pending.WriteString(line)
			line = pending.String()
			pending.Reset()
		}
		canon := NormalizeConfigLine(line)
		eq := strings.IndexByte(canon, '=')
		entry := ConfigEntry{Raw: line, Canon: canon}
		if eq > 0 {
			entry.Key = strings.TrimSpace(canon[:eq])
			entry.Value = canon[eq+1:]
		}
		out = append(out, entry)
	}
	return out
}

// NormalizeDropin returns the canonical form of one /etc/grub.d/*
// script file. Same rules as the motd-shell / profile / sysv / atjobs
// normalizers: strip `#` comments (including the shebang since it is
// cosmetic for stacking), strip blank lines, strip trailing whitespace
// per line.
func NormalizeDropin(raw []byte) []byte {
	var out bytes.Buffer
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \t")
		if line == "" {
			continue
		}
		if strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

// HasInitOverride returns true if value (the right-hand side of a
// GRUB_CMDLINE_LINUX* assignment) contains the kernel `init=` token.
// Quoting is handled minimally: strip surrounding `"..."` or `'...'`
// before searching.
func HasInitOverride(value string) bool {
	v := strings.TrimSpace(value)
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		v = v[1 : len(v)-1]
	}
	for _, tok := range strings.Fields(v) {
		if strings.HasPrefix(tok, "init=") {
			return true
		}
	}
	return false
}

// ExtractInit returns the path on the right-hand side of an `init=`
// token, or "" if not present. Used by the module to populate
// exec_target on records that carry the `grub_cmdline_init` signal.
func ExtractInit(value string) string {
	v := strings.TrimSpace(value)
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		v = v[1 : len(v)-1]
	}
	for _, tok := range strings.Fields(v) {
		if strings.HasPrefix(tok, "init=") {
			return strings.TrimPrefix(tok, "init=")
		}
	}
	return ""
}
