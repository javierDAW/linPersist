// Package ldso normalization helpers.
//
// Three site_classes share two parsing routines:
//
//   - ldso.preload                 one record per whitespace-separated
//     path token, after strip + trim.
//   - ldso.conf / ldso.confd       one record per non-comment, non-blank
//     line, classified as either an
//     include directive or a search-path.
//
// The canonical form fed into content_norm_sha256 is the per-record
// representation (one path or one directive), never the whole file.
// File-level Normalize is provided for the equivalence test only.
package ldso

import (
	"bufio"
	"bytes"
	"strings"
)

// confLineKind classifies a parsed ld.so.conf-style line.
type confLineKind int

const (
	confLineEmpty confLineKind = iota
	confLineInclude
	confLineSearchPath
)

// parsedConfLine is the structured view of one non-blank, non-comment
// line from ld.so.conf or /etc/ld.so.conf.d/*.conf.
type parsedConfLine struct {
	kind   confLineKind
	raw    string // line after inline-comment strip and right-trim
	target string // include glob or search-path
}

// stripInlineComment removes everything from the first '#' on the
// line and right-trims whitespace and CR. Unlike crontab(5),
// /etc/ld.so.conf and /etc/ld.so.preload do not document inline
// comment semantics in their man pages, but glibc's ld.so reader
// honors '#' as a comment marker for the rest of the line. Stripping
// inline comments here matches that behavior and avoids a path
// containing '#' (already pathological) breaking the parser.
func stripInlineComment(line string) string {
	if idx := strings.IndexByte(line, '#'); idx >= 0 {
		line = line[:idx]
	}
	return strings.TrimRight(line, " \t\r")
}

// isLeadingComment reports whether a line, after left-trim, begins
// with '#'. Such lines are dropped during normalization.
func isLeadingComment(s string) bool {
	t := strings.TrimLeft(s, " \t")
	return strings.HasPrefix(t, "#")
}

// collapseInternalWhitespace replaces every run of spaces and tabs
// with a single space. Operates on a single line (no newlines
// expected in input).
func collapseInternalWhitespace(s string) string {
	var out strings.Builder
	out.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		switch r {
		case ' ', '\t':
			if !prevSpace {
				out.WriteByte(' ')
				prevSpace = true
			}
		default:
			out.WriteRune(r)
			prevSpace = false
		}
	}
	return out.String()
}

// splitWS returns the whitespace-separated tokens of s. Empty input
// returns nil.
func splitWS(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t'
	})
}

// parsePreloadLine returns the path tokens carried by one
// ld.so.preload line. The returned slice may be empty (line was
// blank or fully commented out) or contain one or more entries.
// Glibc honors the multi-path form even though ld.so(8) documents
// one path per line.
func parsePreloadLine(rawLine string) []string {
	line := stripInlineComment(rawLine)
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	return splitWS(line)
}

// parseConfLine classifies one ld.so.conf-style line. Returns kind
// confLineEmpty for blanks and comment-only lines.
func parseConfLine(rawLine string) parsedConfLine {
	line := stripInlineComment(rawLine)
	line = strings.TrimSpace(line)
	if line == "" {
		return parsedConfLine{kind: confLineEmpty}
	}
	line = collapseInternalWhitespace(line)

	const includePrefix = "include"
	if strings.HasPrefix(line, includePrefix) {
		rest := line[len(includePrefix):]
		// Only honor 'include' when followed by whitespace; reject
		// 'includebogus /path' to keep the directive detection tight.
		if len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t') {
			target := strings.TrimSpace(rest)
			return parsedConfLine{
				kind:   confLineInclude,
				raw:    line,
				target: target,
			}
		}
	}
	return parsedConfLine{
		kind:   confLineSearchPath,
		raw:    line,
		target: line,
	}
}

// canonicalPreload returns the per-record canonical form for one
// ld.so.preload path token: the token itself, unchanged. Trim was
// already applied during tokenization.
func canonicalPreload(token string) string {
	return token
}

// canonicalConf returns the per-record canonical form for one
// ld.so.conf / *.conf line. Inputs are already trimmed and
// whitespace-collapsed by parseConfLine.
func canonicalConf(pl parsedConfLine) string {
	switch pl.kind {
	case confLineInclude:
		return "include " + pl.target
	case confLineSearchPath:
		return pl.target
	default:
		return ""
	}
}

// hasGlobMeta reports whether p contains glob metacharacters that
// would make a literal-existence check meaningless (a glob that
// expands to nothing is normal, not an orphan).
func hasGlobMeta(p string) bool {
	return strings.ContainsAny(p, "*?[")
}

// Normalize returns a deterministic byte representation of a whole
// ld.so.conf-style file: every non-comment, non-blank line is
// canonicalized via canonicalConf and emitted on its own line.
// Output is sorted to make file-level normalization
// order-independent (per-line content_norm_sha256 remains the
// stacking key in production).
func Normalize(raw []byte) []byte {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	canon := make([]string, 0, 16)
	for scanner.Scan() {
		line := scanner.Text()
		if isLeadingComment(line) {
			continue
		}
		pl := parseConfLine(line)
		if pl.kind == confLineEmpty {
			continue
		}
		canon = append(canon, canonicalConf(pl))
	}
	sortStrings(canon)

	var out bytes.Buffer
	for _, c := range canon {
		out.WriteString(c)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

// NormalizePreload returns a deterministic byte representation of an
// /etc/ld.so.preload file: every non-comment path token (after
// multi-path expansion) is emitted on its own line. Output is
// sorted.
func NormalizePreload(raw []byte) []byte {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	canon := make([]string, 0, 16)
	for scanner.Scan() {
		line := scanner.Text()
		if isLeadingComment(line) {
			continue
		}
		for _, tok := range parsePreloadLine(line) {
			canon = append(canon, canonicalPreload(tok))
		}
	}
	sortStrings(canon)

	var out bytes.Buffer
	for _, c := range canon {
		out.WriteString(c)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

// sortStrings is a tiny insertion sort. ld.so.conf files in the wild
// have < 20 entries; this keeps the file dependency-free of "sort".
func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j-1] > a[j]; j-- {
			a[j-1], a[j] = a[j], a[j-1]
		}
	}
}
