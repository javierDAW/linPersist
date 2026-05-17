package kmod

import (
	"bytes"
	"strings"
)

// normalizeLine returns the canonical form of one logical kmod
// directive line. The pipeline:
//
//   - Trim leading and trailing whitespace.
//   - Collapse runs of whitespace inside the line to a single space.
//   - Lowercase the first whitespace-separated token. For modprobe.d
//     directives that token is the directive verb ("install",
//     "alias", "blacklist", ...) which is case-insensitive in
//     modprobe(5); for /etc/modules-style files the first token is a
//     module name (case-sensitive by Linux convention but conventionally
//     lowercase). Lowercasing it across the board collapses the
//     cosmetic variance that would otherwise fragment stacking.
//
// The function is idempotent: normalizeLine(normalizeLine(x)) ==
// normalizeLine(x).
func normalizeLine(line string, _ lineKind) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	var b bytes.Buffer
	b.Grow(len(line))
	inWS := false
	for _, r := range line {
		if r == ' ' || r == '\t' {
			if !inWS {
				b.WriteByte(' ')
				inWS = true
			}
			continue
		}
		inWS = false
		b.WriteRune(r)
	}
	collapsed := b.String()
	// Lowercase first token.
	idx := strings.IndexByte(collapsed, ' ')
	if idx < 0 {
		return strings.ToLower(collapsed)
	}
	return strings.ToLower(collapsed[:idx]) + collapsed[idx:]
}

// Normalize returns the canonical form of an entire kmod file as the
// concatenation of normalized non-comment non-blank lines joined by
// '\n'. Used by tests that want to assert the file-level canonical
// form even though the module emits per-line records.
func Normalize(raw []byte) []byte {
	lines := parseLogicalLines(raw)
	if len(lines) == 0 {
		return nil
	}
	var out bytes.Buffer
	out.Grow(len(raw))
	for _, l := range lines {
		out.WriteString(normalizeLine(l, kindModprobe))
		out.WriteByte('\n')
	}
	return out.Bytes()
}
