package xdg

import (
	"bytes"
	"sort"
	"strings"
)

// desktopSection is one INI-style section of a .desktop file.
// Keys are stored case-sensitive as they appear (per FreeDesktop
// Desktop Entry Specification §4); canonical form sorts them later.
type desktopSection struct {
	name string            // e.g. "Desktop Entry"
	keys map[string]string // canonical key -> raw value
}

// parsedDesktop holds the parsed structure of a .desktop file.
// Sections are kept in source order; canonical form preserves the
// first occurrence of [Desktop Entry] before any [Desktop Action *]
// blocks so the principal record stays at top.
type parsedDesktop struct {
	sections []desktopSection
}

// section returns the section with the given name, or nil if absent.
func (pd *parsedDesktop) section(name string) *desktopSection {
	for i := range pd.sections {
		if pd.sections[i].name == name {
			return &pd.sections[i]
		}
	}
	return nil
}

// parseDesktop parses raw bytes of a .desktop INI file.
//
// Per FreeDesktop Desktop Entry Specification:
//   - Lines starting with '#' (after any leading whitespace) are
//     comments.
//   - Blank lines are ignored.
//   - Section headers are [NAME] on their own line.
//   - Key=value entries belong to the most recent section.
//   - Locale-suffixed keys (Name[en], Comment[de], ...) are dropped
//     for canonical-form purposes since they are redundant with the
//     unlocalized variants for stacking.
//
// Malformed lines (no '=' outside a section, stray '[' without ']')
// are silently dropped; this parser is permissive on purpose so a
// hand-edited locale file does not break the entire collect pass.
func parseDesktop(raw []byte) parsedDesktop {
	var pd parsedDesktop
	var current *desktopSection
	lines := bytes.Split(raw, []byte("\n"))
	for _, lineBytes := range lines {
		line := strings.TrimRight(string(lineBytes), "\r")
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			end := strings.IndexByte(trimmed, ']')
			if end <= 1 {
				continue
			}
			name := trimmed[1:end]
			pd.sections = append(pd.sections, desktopSection{
				name: name,
				keys: map[string]string{},
			})
			current = &pd.sections[len(pd.sections)-1]
			continue
		}
		if current == nil {
			continue
		}
		eq := strings.IndexByte(trimmed, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimRight(trimmed[:eq], " \t")
		value := strings.TrimLeft(trimmed[eq+1:], " \t")
		// Drop locale-suffixed keys for the canonical form. The
		// unlocalized variant captures the same semantic content.
		if strings.IndexByte(key, '[') >= 0 {
			continue
		}
		// First occurrence wins on duplicate keys within a section
		// (matches GLib's GKeyFile behavior).
		if _, dup := current.keys[key]; dup {
			continue
		}
		current.keys[key] = strings.TrimRight(value, " \t")
	}
	return pd
}

// canonical returns the canonical-form bytes of a parsed .desktop.
//
// Rules:
//   - Sections in source order (preserves [Desktop Entry] first).
//   - Within each section, keys sorted alphabetically.
//   - Empty sections dropped.
//   - Comments and blank lines absent.
//   - Locale-suffixed keys absent (filtered at parse time).
//   - Trailing whitespace per value stripped (filtered at parse time).
//
// Two semantically-equivalent .desktop files (different key order,
// different whitespace, with or without locale variants) produce the
// same canonical bytes and therefore the same content_norm_sha256.
func canonical(pd parsedDesktop) []byte {
	var b bytes.Buffer
	for _, sec := range pd.sections {
		if len(sec.keys) == 0 {
			continue
		}
		b.WriteByte('[')
		b.WriteString(sec.name)
		b.WriteString("]\n")
		keys := make([]string, 0, len(sec.keys))
		for k := range sec.keys {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(sec.keys[k])
			b.WriteByte('\n')
		}
	}
	return b.Bytes()
}

// extractExec returns the argv[0] of the Exec= key in the [Desktop
// Entry] section, with FreeDesktop field codes (%U, %f, etc.) and
// shell quoting stripped. Returns "" if no Exec= is present or the
// value is empty.
//
// The Exec field can contain:
//   - whitespace-separated args; argv[0] is everything up to the
//     first unquoted whitespace
//   - double-quoted tokens with embedded spaces
//   - %X field codes (deprecated or otherwise)
//
// This implementation is intentionally minimal: split on whitespace,
// strip quotes from argv[0], strip any embedded %X codes. It does
// NOT implement full shell escape handling because the persistence
// site that matters is the binary path, not the arguments.
func extractExec(pd parsedDesktop) string {
	sec := pd.section("Desktop Entry")
	if sec == nil {
		return ""
	}
	raw := strings.TrimSpace(sec.keys["Exec"])
	if raw == "" {
		return ""
	}
	first := firstArg(raw)
	return stripFieldCodes(first)
}

// firstArg returns the first whitespace-delimited token of s, with
// surrounding double quotes stripped. Single quotes are NOT special
// in .desktop Exec values per spec.
func firstArg(s string) string {
	s = strings.TrimLeft(s, " \t")
	if s == "" {
		return ""
	}
	if s[0] == '"' {
		// Quoted: take everything up to the next unescaped '"'.
		end := indexUnescapedQuote(s[1:])
		if end < 0 {
			return strings.Trim(s, `"`)
		}
		return s[1 : 1+end]
	}
	if idx := strings.IndexAny(s, " \t"); idx >= 0 {
		return s[:idx]
	}
	return s
}

// indexUnescapedQuote returns the index of the first '"' in s that is
// not preceded by a backslash. Returns -1 if none.
func indexUnescapedQuote(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			continue
		}
		if s[i] == '"' {
			return i
		}
	}
	return -1
}

// stripFieldCodes removes FreeDesktop %X tokens from s. %% is
// preserved as a literal '%' per spec; everything else of the form
// %<letter> is dropped.
func stripFieldCodes(s string) string {
	if !strings.ContainsRune(s, '%') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' && i+1 < len(s) {
			next := s[i+1]
			if next == '%' {
				b.WriteByte('%')
				i++
				continue
			}
			// %f, %F, %u, %U, %i, %c, %k, %d, %D, %n, %N, %v, %m
			if (next >= 'a' && next <= 'z') || (next >= 'A' && next <= 'Z') {
				i++
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}
