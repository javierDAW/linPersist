package core

import (
	"bufio"
	"strings"
)

// ExtractExecTarget scans a profile script body for the first command
// that names a concrete absolute-path binary, and returns it. The
// helper exists so the profile.system / profile.user record gets
// populated with the same kind of ExecTarget the cron and systemd
// modules already emit, which in turn lets Q12 (campaign basename
// clustering) consolidate the three arms of a worm that touches all
// three persistence sites into a single row instead of one row per
// module.
//
// Three patterns are recognized, in order of inspection per line:
//
//  1. `. /path/to/payload` or `source /path/to/payload`
//     The script sources an external file at login. The path is the
//     ExecTarget.
//  2. `exec /path/to/payload [args...]`
//     The script replaces itself with the named binary.
//  3. `/path/to/payload [args...]` as the leading token of a line
//     (after trimming whitespace and leading conditionals like
//     `if [ -x ... ]; then`). An absolute path on its own.
//
// Returns "" when no exec target can be inferred. The conservative
// default preserves the pre-v0.4.0 behavior on benign profile files
// where the body is exports, aliases, function definitions, PS1
// tweaks, etc.
//
// Inspection stops at the first match; multi-target scripts surface
// their highest-priority match. This is deliberate: Q12 clusters by
// basename, and a worm whose profile-arm both sources and execs the
// same payload still maps to one cluster.
func ExtractExecTarget(body []byte) string {
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	// 1 MiB is generous; the entries we care about are well under
	// 4 KiB. Bigger lines are not interesting persistence shape.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Strip leading shell control: `if [ ... ]; then` or `&& `
		// are common around worm-arm bodies. Re-trim after each
		// possible prefix and try again.
		trimmed = stripLeadingControl(trimmed)
		if trimmed == "" {
			continue
		}
		if t := extractSource(trimmed); t != "" {
			return t
		}
		if t := extractExec(trimmed); t != "" {
			return t
		}
		if t := extractAbsoluteLead(trimmed); t != "" {
			return t
		}
	}
	return ""
}

// extractSource matches `. /abs` and `source /abs` patterns and
// returns the absolute path argument. Both POSIX-sh `.` and bash
// `source` are supported because attackers in the wild use both.
func extractSource(line string) string {
	switch {
	case strings.HasPrefix(line, ". /"):
		return firstAbsToken(line[2:])
	case strings.HasPrefix(line, "source /"):
		return firstAbsToken(line[len("source "):])
	}
	return ""
}

// extractExec matches `exec /abs ...` and returns the absolute path.
// Bash and POSIX-sh share the syntax. exec without a path argument
// (`exec >&2` redirection) is intentionally NOT matched — there is
// no exec target there.
func extractExec(line string) string {
	if !strings.HasPrefix(line, "exec ") {
		return ""
	}
	rest := strings.TrimLeft(line[len("exec "):], " \t")
	if !strings.HasPrefix(rest, "/") {
		return ""
	}
	return firstAbsToken(rest)
}

// extractAbsoluteLead matches lines whose first whitespace-separated
// token is itself an absolute path: `/usr/local/bin/sync --start`.
// This is the no-frills worm shape — an attacker who just appends
// the payload invocation to the bottom of /etc/profile. Quotes are
// not parsed; the heuristic is intentionally narrow.
func extractAbsoluteLead(line string) string {
	if !strings.HasPrefix(line, "/") {
		return ""
	}
	return firstAbsToken(line)
}

// firstAbsToken returns the first whitespace-separated token of
// `line` if and only if that token starts with `/` and contains no
// shell metacharacters that would invalidate it as a real path
// (>, <, |, &, ;, $, `).
func firstAbsToken(line string) string {
	end := len(line)
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == ' ' || c == '\t' || c == '\n' {
			end = i
			break
		}
		if c == '>' || c == '<' || c == '|' || c == '&' ||
			c == ';' || c == '$' || c == '`' || c == '"' || c == '\'' {
			return ""
		}
	}
	tok := line[:end]
	if !strings.HasPrefix(tok, "/") {
		return ""
	}
	if len(tok) < 2 {
		return ""
	}
	return tok
}

// stripLeadingControl walks the small set of shell-control prefixes
// that show up around a worm-arm invocation and trims them. The list
// is deliberately short to keep the function honest: an attacker
// wrapping the payload in deeply-nested compound commands is not
// caught here, and would surface via the existing Q1 LFA / trap
// scanner instead.
func stripLeadingControl(s string) string {
	prefixes := []string{
		"&& ", "|| ", "; ",
		"then ", "do ", "else ",
	}
	changed := true
	for changed {
		changed = false
		s = strings.TrimLeft(s, " \t")
		for _, p := range prefixes {
			if strings.HasPrefix(s, p) {
				s = s[len(p):]
				changed = true
				break
			}
		}
	}
	return s
}
