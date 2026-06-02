// Package sudoers normalization and parsing helpers.
//
// Sudoers line kinds (see sudoers(5)):
//
//   - blank / comment (excluding #include / #includedir)
//   - #include <path>
//   - #includedir <path>
//   - <Kind>_Alias NAME = members         (User_Alias, Runas_Alias,
//     Host_Alias, Cmnd_Alias)
//   - Defaults[scope] <param>[=value]
//   - <user> <host>=(<runas>) [<TAGS>] <commands>     (user spec)
//
// Canonical form rules feed content_norm_sha256:
//
//   - Strip leading/trailing whitespace, then quote-aware whitespace
//     collapse + strip-around-equals.
//   - #include / #includedir: drop the leading '#'.
//   - Alias lines: sort members alphabetically; join with ", ".
//   - Defaults and user specs: whitespace-normalized only.
package sudoers

import (
	"sort"
	"strings"
)

// lineKind classifies a parsed sudoers line.
type lineKind int

const (
	lineEmpty lineKind = iota
	lineInclude
	lineAlias
	lineDefaults
	lineUserSpec
)

// parsedLine is the structured view of one non-comment, non-blank line.
type parsedLine struct {
	kind  lineKind
	raw   string // original line after right-trim
	canon string // canonical form (input to content_norm_sha256)
}

// isLeadingComment reports whether the line, after left-trim, begins
// with '#'. Treated as a comment only if it is NOT #include or
// #includedir.
func isLeadingComment(s string) bool {
	t := strings.TrimLeft(s, " \t")
	if !strings.HasPrefix(t, "#") {
		return false
	}
	if strings.HasPrefix(t, "#include ") || strings.HasPrefix(t, "#includedir ") {
		return false
	}
	return true
}

// aliasKeywords are the four alias-introducer tokens recognized by
// sudoers (case-sensitive per sudoers(5)).
var aliasKeywords = []string{
	"User_Alias",
	"Runas_Alias",
	"Host_Alias",
	"Cmnd_Alias",
}

// startsWithAliasKeyword reports whether s begins with a known alias
// keyword followed by whitespace.
func startsWithAliasKeyword(s string) bool {
	for _, k := range aliasKeywords {
		if strings.HasPrefix(s, k+" ") || strings.HasPrefix(s, k+"\t") {
			return true
		}
	}
	return false
}

// normalizeLine performs quote-aware whitespace collapse and
// whitespace-around-equals stripping. Used for every non-empty,
// non-comment line as the first canonicalization step.
func normalizeLine(s string) string {
	s = strings.TrimSpace(s)
	var out strings.Builder
	out.Grow(len(s))
	inQ := false
	i := 0
	n := len(s)
	for i < n {
		c := s[i]
		switch {
		case c == '"':
			inQ = !inQ
			out.WriteByte(c)
			i++
		case (c == ' ' || c == '\t') && !inQ:
			// Run of whitespace: consume.
			for i < n && (s[i] == ' ' || s[i] == '\t') {
				i++
			}
			// Strip around '=': emit nothing if the previous emitted
			// byte was '=' or the next byte is '='.
			lastIsEq := out.Len() > 0 && out.String()[out.Len()-1] == '='
			nextIsEq := i < n && s[i] == '='
			if lastIsEq || nextIsEq {
				continue
			}
			out.WriteByte(' ')
		default:
			out.WriteByte(c)
			i++
		}
	}
	return out.String()
}

// canonicalizeAlias takes an already-whitespace-normalized alias
// line and sorts its members alphabetically. Input is expected to
// match `<Kind>_Alias NAME=member,...` after normalizeLine.
func canonicalizeAlias(norm string) string {
	eq := strings.IndexByte(norm, '=')
	if eq < 0 {
		return norm
	}
	left := norm[:eq+1]
	right := norm[eq+1:]
	members := strings.Split(right, ",")
	for i := range members {
		members[i] = strings.TrimSpace(members[i])
	}
	sort.Strings(members)
	return left + strings.Join(members, ", ")
}

// parseLine classifies and canonicalizes one source line.
// Returns parsedLine with kind=lineEmpty for blanks and non-include
// comments; callers skip those.
func parseLine(rawLine string) parsedLine {
	raw := strings.TrimRight(rawLine, " \t\r")
	t := strings.TrimLeft(raw, " \t")
	if t == "" {
		return parsedLine{kind: lineEmpty}
	}
	if isLeadingComment(t) {
		return parsedLine{kind: lineEmpty}
	}
	if strings.HasPrefix(t, "#include ") || strings.HasPrefix(t, "#includedir ") {
		// Canonical = strip the leading '#'.
		canon := normalizeLine(t[1:])
		return parsedLine{kind: lineInclude, raw: raw, canon: canon}
	}
	norm := normalizeLine(raw)
	if startsWithAliasKeyword(norm) {
		return parsedLine{kind: lineAlias, raw: raw, canon: canonicalizeAlias(norm)}
	}
	if strings.HasPrefix(norm, "Defaults") {
		// Defaults, Defaults:user, Defaults>host, Defaults@!cmd etc.
		return parsedLine{kind: lineDefaults, raw: raw, canon: norm}
	}
	return parsedLine{kind: lineUserSpec, raw: raw, canon: norm}
}

// hasNoPasswd reports whether the canonical line contains the
// literal token "NOPASSWD:" (case-sensitive per sudoers convention).
func hasNoPasswd(canon string) bool {
	return strings.Contains(canon, "NOPASSWD:")
}

// specCommands returns the comma-separated command entries of a user-spec
// line: everything after '=', past the optional (runas) and any leading
// whitespace-separated TAG: tokens. Each returned entry is trimmed and may
// still carry arguments (e.g. "/usr/bin/systemctl restart nginx"). Returns
// nil when the line has no '=' (not a user-spec command list).
func specCommands(canon string) []string {
	eq := strings.IndexByte(canon, '=')
	if eq < 0 {
		return nil
	}
	right := canon[eq+1:]
	// Strip optional (runas).
	if strings.HasPrefix(right, "(") {
		if close := strings.IndexByte(right, ')'); close >= 0 {
			right = right[close+1:]
		}
	}
	right = strings.TrimLeft(right, " \t")
	// Skip TAG: tokens (whitespace-separated tokens ending with ':').
	fields := strings.Fields(right)
	cmdStart := 0
	for i, f := range fields {
		if strings.HasSuffix(f, ":") {
			cmdStart = i + 1
			continue
		}
		break
	}
	var out []string
	for _, c := range strings.Split(strings.Join(fields[cmdStart:], " "), ",") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// hasAllCommands reports whether a user-spec line's command list contains
// the standalone token "ALL".
func hasAllCommands(canon string) bool {
	for _, c := range specCommands(canon) {
		if c == "ALL" {
			return true
		}
	}
	return false
}

// gtfoShellEscape is the curated set of binary basenames whose mere
// presence in a NOPASSWD grant yields a password-less root shell
// (GTFOBins sudo shell-escapes). Deliberately EXCLUDES commonly-scoped
// legitimate admin binaries (systemctl, service, docker, git, package
// managers): those are GTFOBins too, but NOPASSWD grants on them are
// ubiquitous on managed fleets, so they are left to LFA rather than a
// noisy Q7 row. See SignalSudoersNopasswdGtfobin.
var gtfoShellEscape = map[string]bool{
	"vi": true, "vim": true, "view": true, "vimdiff": true, "rvim": true,
	"nano": true, "pico": true, "ed": true, "ex": true,
	"less": true, "more": true, "man": true, "pager": true,
	"awk": true, "gawk": true, "mawk": true, "nawk": true, "sed": true,
	"find": true, "env": true, "xargs": true,
	"tar": true, "zip": true, "cpio": true,
	"python": true, "python2": true, "python3": true,
	"perl": true, "ruby": true, "lua": true, "php": true, "node": true,
	"gdb": true, "nmap": true, "tmux": true, "screen": true,
	"ftp": true, "tclsh": true, "expect": true, "byebug": true,
}

// nopasswdGtfobin reports whether any command in the user-spec's command
// list is a curated shell-escape GTFOBin (by basename of its first
// token). Caller pairs this with hasNoPasswd.
func nopasswdGtfobin(canon string) bool {
	for _, c := range specCommands(canon) {
		bin := c
		if sp := strings.IndexAny(bin, " \t"); sp >= 0 {
			bin = bin[:sp]
		}
		if slash := strings.LastIndexByte(bin, '/'); slash >= 0 {
			bin = bin[slash+1:]
		}
		if gtfoShellEscape[bin] {
			return true
		}
	}
	return false
}
