package cron

import (
	"bufio"
	"bytes"
	"strings"
)

// lineKind classifies a parsed crontab line.
type lineKind int

const (
	lineEmpty lineKind = iota
	lineVarAssignment
	lineScheduleEntry
	lineMalformed
)

// parsedLine is the structured view of one non-blank, non-comment line.
type parsedLine struct {
	kind     lineKind
	raw      string // original line after right-trim and CRLF strip
	schedule string // five-field schedule or @keyword (lineScheduleEntry)
	user     string // USER column (cron.d, cron.anacron); empty for cron.user
	command  string // command portion (lineScheduleEntry)
	varName  string // identifier (lineVarAssignment)
	varValue string // value after '=' (lineVarAssignment)
	parseErr string // error code when kind == lineMalformed
}

// schedKeywords lists the @-shorthand schedule keywords accepted by
// cron and anacron implementations on Linux. See crontab(5).
var schedKeywords = map[string]struct{}{
	"@reboot":   {},
	"@yearly":   {},
	"@annually": {},
	"@monthly":  {},
	"@weekly":   {},
	"@daily":    {},
	"@midnight": {},
	"@hourly":   {},
}

// stripInlineComment removes trailing whitespace and an optional
// trailing CR. It does NOT remove '#'-prefixed comments here because
// crontab(5) does not honor inline comments; '#' is only a comment
// marker when it is the first non-whitespace character of the line.
func stripInlineComment(s string) string {
	return strings.TrimRight(s, " \t\r")
}

// isLeadingComment reports whether a line, after left-trim, begins
// with '#'. Such lines are crontab comments and are dropped during
// normalization.
func isLeadingComment(s string) bool {
	t := strings.TrimLeft(s, " \t")
	return strings.HasPrefix(t, "#")
}

// splitWS splits on runs of ASCII space/tab. It mirrors what cron does
// when carving a line into fields.
func splitWS(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t'
	})
}

// isIdentifier reports whether s is a valid env-variable identifier:
// [A-Za-z_][A-Za-z0-9_]*. Required for variable-assignment detection.
func isIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_':
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

// tryVarAssignment detects a "NAME = value" or "NAME=value" line as
// produced by cron itself for environment setup. Returns the parsed
// name and value (both trimmed) or ok=false.
func tryVarAssignment(line string) (name, val string, ok bool) {
	idx := strings.IndexByte(line, '=')
	if idx <= 0 {
		return "", "", false
	}
	name = strings.TrimSpace(line[:idx])
	if !isIdentifier(name) {
		return "", "", false
	}
	val = strings.TrimSpace(line[idx+1:])
	return name, val, true
}

// parseCrontabLine takes a line known to be non-empty and non-comment
// and classifies it. hasUser true means the format includes a USER
// column between schedule and command (cron.d, cron.anacron-with-period
// uses a different shape handled separately).
func parseCrontabLine(line string, hasUser bool) parsedLine {
	line = stripInlineComment(line)
	if line == "" {
		return parsedLine{kind: lineEmpty}
	}

	if name, val, ok := tryVarAssignment(line); ok {
		return parsedLine{
			kind:     lineVarAssignment,
			raw:      line,
			varName:  name,
			varValue: val,
		}
	}

	fields := splitWS(line)
	if len(fields) == 0 {
		return parsedLine{kind: lineMalformed, raw: line, parseErr: "PARSE_ERROR"}
	}

	var sched string
	var rest []string

	if strings.HasPrefix(fields[0], "@") {
		if _, ok := schedKeywords[fields[0]]; !ok {
			return parsedLine{kind: lineMalformed, raw: line, parseErr: "PARSE_ERROR"}
		}
		sched = fields[0]
		rest = fields[1:]
	} else {
		if len(fields) < 5 {
			return parsedLine{kind: lineMalformed, raw: line, parseErr: "PARSE_ERROR"}
		}
		sched = strings.Join(fields[:5], " ")
		rest = fields[5:]
	}

	out := parsedLine{
		kind:     lineScheduleEntry,
		raw:      line,
		schedule: sched,
	}

	if hasUser {
		if len(rest) < 2 {
			out.kind = lineMalformed
			out.parseErr = "PARSE_ERROR"
			return out
		}
		out.user = rest[0]
		out.command = strings.Join(rest[1:], " ")
	} else {
		if len(rest) < 1 {
			out.kind = lineMalformed
			out.parseErr = "PARSE_ERROR"
			return out
		}
		out.command = strings.Join(rest, " ")
	}
	return out
}

// canonicalLine produces the deterministic byte representation used to
// compute content_norm_sha256 for one Record. The representation
// preserves semantically-significant content (schedule, user, command,
// or var name + value) but collapses whitespace and strips the line's
// original positional formatting.
//
// Format per kind:
//   - lineVarAssignment: "NAME=VALUE"
//   - lineScheduleEntry (cron.d):   "SCHED USER COMMAND"
//   - lineScheduleEntry (cron.user): "SCHED COMMAND"
//   - lineMalformed: pl.raw (preserved verbatim so downstream sees the
//     exact offending bytes)
func canonicalLine(pl parsedLine) string {
	switch pl.kind {
	case lineVarAssignment:
		return pl.varName + "=" + pl.varValue
	case lineScheduleEntry:
		if pl.user != "" {
			return pl.schedule + " " + pl.user + " " + pl.command
		}
		return pl.schedule + " " + pl.command
	case lineMalformed:
		return pl.raw
	default:
		return ""
	}
}

// Normalize returns the deterministic byte representation of a whole
// crontab-format file. Comments and blank lines are dropped; each
// remaining line is canonicalized via canonicalLine. Output is sorted
// to make whole-file normalization order-insensitive (per ADR-0002,
// individual line records are the stacking key, but the file-level
// Normalize is used by the equivalence test and benefits from being
// order-independent too).
//
// hasUser controls whether the format includes a USER column.
func Normalize(raw []byte, hasUser bool) []byte {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	canon := make([]string, 0, 16)
	for scanner.Scan() {
		line := scanner.Text()
		if isLeadingComment(line) {
			continue
		}
		line = stripInlineComment(line)
		if strings.TrimSpace(line) == "" {
			continue
		}
		pl := parseCrontabLine(line, hasUser)
		if pl.kind == lineEmpty {
			continue
		}
		canon = append(canon, canonicalLine(pl))
	}
	// Sort for order-independence at file level.
	// Per-line content_norm_sha256 used by the agent is computed elsewhere.
	sortStrings(canon)

	var out bytes.Buffer
	for _, c := range canon {
		out.WriteString(c)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

// sortStrings is a tiny insertion sort to avoid pulling in sort just
// for this. Crontab files realistically have < 50 lines.
func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j-1] > a[j]; j-- {
			a[j-1], a[j] = a[j], a[j-1]
		}
	}
}
