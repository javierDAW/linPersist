// Package sshd normalization and parsing helpers.
//
// sshd_config format per sshd_config(5):
//
//	<Keyword> <value>
//	Match <criterion> <value> [<criterion2> <value2> ...]
//
// Keywords and Match-criterion keywords are case-insensitive; values
// are preserved verbatim. Match blocks scope all subsequent
// directives until the next Match line or end of file (see ADR-0004).
package sshd

import (
	"strings"
)

// lineKind classifies a parsed sshd_config line.
type lineKind int

const (
	lineEmpty lineKind = iota
	lineDirective
	lineMatch
)

// parsedLine is the structured view of one source line.
type parsedLine struct {
	kind     lineKind
	raw      string // line right-trimmed (for content_sha256 input)
	keyword  string // directive keyword (lineDirective) or "Match" (lineMatch)
	value    string // directive value (lineDirective)
	matchRaw string // criteria portion (lineMatch)
}

// isLeadingComment reports whether s begins with '#' after left-trim.
func isLeadingComment(s string) bool {
	t := strings.TrimLeft(s, " \t")
	return strings.HasPrefix(t, "#")
}

// parseLine classifies one source line. Returns lineEmpty for
// blanks and comment lines; the caller skips those.
func parseLine(rawLine string) parsedLine {
	raw := strings.TrimRight(rawLine, " \t\r")
	t := strings.TrimLeft(raw, " \t")
	if t == "" || isLeadingComment(t) {
		return parsedLine{kind: lineEmpty}
	}
	// Split keyword from rest of line.
	i := 0
	for i < len(t) && (isAlnum(t[i]) || t[i] == '_') {
		i++
	}
	if i == 0 {
		return parsedLine{kind: lineEmpty}
	}
	keyword := t[:i]
	rest := strings.TrimLeft(t[i:], " \t")
	if strings.EqualFold(keyword, "Match") {
		return parsedLine{kind: lineMatch, raw: raw, keyword: keyword, matchRaw: rest}
	}
	return parsedLine{kind: lineDirective, raw: raw, keyword: keyword, value: rest}
}

func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9')
}

// normalizeValue collapses internal whitespace of a directive value
// while preserving double-quoted segments. Trims surrounding
// whitespace.
func normalizeValue(s string) string {
	s = strings.TrimSpace(s)
	var out strings.Builder
	out.Grow(len(s))
	inQ := false
	lastWS := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQ = !inQ
			out.WriteByte(c)
			lastWS = false
		case (c == ' ' || c == '\t') && !inQ:
			if !lastWS {
				out.WriteByte(' ')
				lastWS = true
			}
		default:
			out.WriteByte(c)
			lastWS = false
		}
	}
	return out.String()
}

// canonicalMatchLine builds the canonical form of a Match line.
// Lowercases the literal "match" keyword AND every alternating
// criterion keyword (User, Group, Host, ...); preserves criterion
// values (usernames, group names, IPs, ports). Output is the
// canonical line that gets prepended to every directive inside the
// block per ADR-0004.
func canonicalMatchLine(matchArgs string) string {
	args := normalizeValue(matchArgs)
	parts := strings.Fields(args)
	for i, p := range parts {
		if i%2 == 0 {
			parts[i] = strings.ToLower(p) // criterion keyword
		} else {
			parts[i] = p // criterion value
		}
	}
	return "match " + strings.Join(parts, " ")
}

// canonicalDirective builds the canonical form of a directive line.
// Lowercases the keyword; whitespace-normalizes the value; prepends
// the active Match canonical (with " : " separator) when scoped.
func canonicalDirective(keyword, value, currentMatch string) string {
	base := strings.ToLower(keyword) + " " + normalizeValue(value)
	base = strings.TrimRight(base, " ")
	if currentMatch != "" {
		return currentMatch + " : " + base
	}
	return base
}

// snippetDirective builds the human-readable snippet for a
// directive: original keyword case, whitespace-normalized value.
func snippetDirective(keyword, value string) string {
	v := normalizeValue(value)
	if v == "" {
		return keyword
	}
	return keyword + " " + v
}

// snippetMatch builds the human-readable snippet for a Match line:
// original keyword case ("Match") + criteria as written (after
// whitespace normalization).
func snippetMatch(keyword, matchArgs string) string {
	v := normalizeValue(matchArgs)
	if v == "" {
		return keyword
	}
	return keyword + " " + v
}

// directiveExecTarget returns the path-like exec_target value for
// directives that resolve to a runnable binary. AuthorizedKeysCommand
// and ForceCommand are the two; everything else returns "".
//
// Quoting convention: if the whole value is surrounded by double
// quotes, the quoted content IS the full path -- sshd passes the
// quoted string to sh -c verbatim, so spaces inside the quotes are
// part of the path. If the value is NOT quoted, the first
// whitespace-delimited token is the binary and the rest is
// arguments; only the binary is returned as exec_target.
func directiveExecTarget(keyword, value string) string {
	switch strings.ToLower(keyword) {
	case "authorizedkeyscommand", "forcecommand":
		v := strings.TrimSpace(value)
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			return v[1 : len(v)-1]
		}
		if i := strings.IndexAny(v, " \t"); i > 0 {
			v = v[:i]
		}
		return v
	}
	return ""
}

// directiveSignals returns the static signals derivable from
// keyword+value alone.
func directiveSignals(keyword, value string) []string {
	var out []string
	kw := strings.ToLower(keyword)
	val := strings.ToLower(normalizeValue(value))
	if kw == "permitrootlogin" && val == "yes" {
		out = append(out, "sshd_permit_root_login_yes")
	}
	if kw == "authorizedkeyscommand" {
		out = append(out, "sshd_authorized_keys_command")
	}
	return out
}
