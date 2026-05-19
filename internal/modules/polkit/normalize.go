package polkit

import (
	"bufio"
	"bytes"
	"strings"
)

// Normalize returns the canonical form of a polkit JS rules file.
//
// Rules:
//   - Single-line `//` comments and the rest of their line are dropped.
//   - Block `/* ... */` comments are dropped, even across multiple
//     lines.
//   - Blank lines are dropped.
//   - Trailing whitespace per line is stripped.
//   - Comment-recognition is suppressed inside double-quoted and
//     single-quoted string literals (a `//` inside `"http://x"`
//     stays content). Escape sequences (`\\`, `\"`, `\'`) are
//     honored.
//
// Two semantically-equivalent polkit rules files (different comment
// noise, different whitespace) produce identical canonical bytes and
// therefore the same content_norm_sha256.
//
// JavaScript template-literal handling is deliberately minimal: a
// backtick is treated as a literal delimiter but no ${...}
// interpolation parsing is done. Polkit rule files in the wild do
// not use template literals; if a hostile rule used them to evade
// the stripper, the worst case is content_norm_sha256 picking up
// extra cosmetic bytes — still deterministic, just lower stacking
// yield.
func Normalize(raw []byte) []byte {
	stripped := stripJSComments(raw)
	return collapseBlankLines(stripped)
}

// stripJSComments removes // and /* */ comments from JS source while
// respecting string literal boundaries.
func stripJSComments(in []byte) []byte {
	const (
		stNormal = iota
		stLineComment
		stBlockComment
		stStringSingle
		stStringDouble
		stStringBacktick
	)
	state := stNormal
	var out bytes.Buffer
	out.Grow(len(in))
	for i := 0; i < len(in); i++ {
		c := in[i]
		switch state {
		case stNormal:
			if c == '/' && i+1 < len(in) {
				next := in[i+1]
				if next == '/' {
					state = stLineComment
					i++
					continue
				}
				if next == '*' {
					state = stBlockComment
					i++
					continue
				}
			}
			out.WriteByte(c)
			switch c {
			case '\'':
				state = stStringSingle
			case '"':
				state = stStringDouble
			case '`':
				state = stStringBacktick
			}
		case stLineComment:
			if c == '\n' {
				out.WriteByte('\n')
				state = stNormal
			}
		case stBlockComment:
			if c == '*' && i+1 < len(in) && in[i+1] == '/' {
				i++
				state = stNormal
			}
			// Preserve newlines inside block comments so line-based
			// downstream passes still see correct line geometry.
			if c == '\n' {
				out.WriteByte('\n')
			}
		case stStringSingle:
			out.WriteByte(c)
			if c == '\\' && i+1 < len(in) {
				out.WriteByte(in[i+1])
				i++
				continue
			}
			if c == '\'' {
				state = stNormal
			}
		case stStringDouble:
			out.WriteByte(c)
			if c == '\\' && i+1 < len(in) {
				out.WriteByte(in[i+1])
				i++
				continue
			}
			if c == '"' {
				state = stNormal
			}
		case stStringBacktick:
			out.WriteByte(c)
			if c == '\\' && i+1 < len(in) {
				out.WriteByte(in[i+1])
				i++
				continue
			}
			if c == '`' {
				state = stNormal
			}
		}
	}
	return out.Bytes()
}

// collapseBlankLines drops empty/whitespace-only lines and strips
// trailing whitespace per remaining line.
func collapseBlankLines(in []byte) []byte {
	var out bytes.Buffer
	sc := bufio.NewScanner(bytes.NewReader(in))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \t")
		if line == "" {
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

// containsToken returns true if canon contains the literal token at a
// position that is not inside a string literal. Used by the module to
// derive the polkit_admin_rule and polkit_yes_constant signals from
// the canonical form (which already has comments stripped, so
// substring search is sufficient — comments cannot host the token by
// construction).
func containsToken(canon []byte, token string) bool {
	return bytes.Contains(canon, []byte(token))
}
