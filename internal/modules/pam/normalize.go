// Package pam normalization and parsing helpers.
//
// PAM has two file formats coexisting:
//
//   - /etc/pam.d/<service>: 4 fields per line
//     <type> <control> <module> [args]
//   - /etc/pam.conf       : 5 fields per line (legacy single-file)
//     <service> <type> <control> <module> [args]
//
// The tokenizer respects [bracket=control] syntax (a control like
// [success=ok default=die] is ONE token, not many).
//
// Canonical-form rules (ADR-0002 per-line):
//   - Strip leading and trailing whitespace.
//   - Tokenize respecting brackets.
//   - Lowercase the type keyword (auth/account/password/session).
//   - Rejoin with single spaces.
package pam

import (
	"strings"
)

// tokenizePAM splits a PAM line on whitespace, treating [bracket]
// segments as single tokens.
func tokenizePAM(s string) []string {
	var tokens []string
	var cur strings.Builder
	inBracket := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '[' && !inBracket:
			inBracket = true
			cur.WriteByte(c)
		case c == ']' && inBracket:
			inBracket = false
			cur.WriteByte(c)
		case (c == ' ' || c == '\t') && !inBracket:
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

// pamRule is the parsed shape of one non-comment, non-blank PAM line.
// Format determines which fields are populated:
//   - dotD == true:  service is "", tokens are [type, control, module, args...]
//   - dotD == false: service is set, tokens are [service, type, control, module, args...]
type pamRule struct {
	raw     string
	canon   string
	module  string // third token in pam.d, fourth in pam.conf
	include bool   // true for @include directives
}

// isLeadingComment reports whether the line, after left-trim, begins
// with '#'.
func isLeadingComment(s string) bool {
	t := strings.TrimLeft(s, " \t")
	return strings.HasPrefix(t, "#")
}

// parsePamDLine parses one line of an /etc/pam.d/<service> file.
// Returns ok=false for blanks, comments and unparseable lines.
func parsePamDLine(rawLine string) (pamRule, bool) {
	line := strings.TrimRight(rawLine, " \t\r")
	t := strings.TrimLeft(line, " \t")
	if t == "" || isLeadingComment(line) {
		return pamRule{}, false
	}
	if strings.HasPrefix(t, "@") {
		// @include <target> directive
		parts := strings.Fields(t)
		if len(parts) < 2 {
			return pamRule{}, false
		}
		return pamRule{
			raw:     line,
			canon:   parts[0] + " " + parts[1],
			module:  parts[1],
			include: true,
		}, true
	}
	toks := tokenizePAM(t)
	if len(toks) < 3 {
		return pamRule{}, false
	}
	toks[0] = strings.ToLower(toks[0]) // type keyword
	canon := strings.Join(toks, " ")
	return pamRule{
		raw:    line,
		canon:  canon,
		module: toks[2],
	}, true
}

// parsePamConfLine parses one line of /etc/pam.conf (5-field format).
func parsePamConfLine(rawLine string) (pamRule, bool) {
	line := strings.TrimRight(rawLine, " \t\r")
	t := strings.TrimLeft(line, " \t")
	if t == "" || isLeadingComment(line) {
		return pamRule{}, false
	}
	toks := tokenizePAM(t)
	if len(toks) < 4 {
		return pamRule{}, false
	}
	toks[1] = strings.ToLower(toks[1]) // type keyword (second token in pam.conf)
	canon := strings.Join(toks, " ")
	return pamRule{
		raw:    line,
		canon:  canon,
		module: toks[3],
	}, true
}
