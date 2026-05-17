package udev

import (
	"bufio"
	"bytes"
	"strings"
)

// parseRules walks the raw bytes of a udev *.rules file and returns
// one logical rule per surviving entry:
//
//   - backslash line continuations are joined (the `\` and `\n` are
//     replaced by a single space, matching udev's own behavior);
//   - lines whose first non-whitespace character is `#` are dropped
//     (full-line comments only -- `#` inside a quoted value is
//     content);
//   - blank lines are dropped.
//
// Each surviving logical line is one rule.
func parseRules(raw []byte) []string {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var physical []string
	for sc.Scan() {
		physical = append(physical, sc.Text())
	}
	var logical []string
	i := 0
	for i < len(physical) {
		text := physical[i]
		for {
			trimmed := strings.TrimRight(text, " \t")
			if !strings.HasSuffix(trimmed, "\\") {
				break
			}
			if i+1 >= len(physical) {
				text = trimmed[:len(trimmed)-1]
				break
			}
			// udev joins continuations with a single space.
			text = trimmed[:len(trimmed)-1] + " "
			i++
			text += strings.TrimLeft(physical[i], " \t")
		}
		t := strings.TrimSpace(text)
		if t == "" || strings.HasPrefix(t, "#") {
			i++
			continue
		}
		logical = append(logical, t)
		i++
	}
	return logical
}

// normalizeRule returns the canonical form of one rule line:
//
//   - leading and trailing whitespace are trimmed;
//   - runs of whitespace OUTSIDE quoted strings are collapsed to a
//     single space;
//   - spacing around `,` outside quoted strings is normalized to
//     `, ` (comma immediately followed by one space);
//   - whitespace INSIDE quoted strings is preserved verbatim;
//   - key-op-value triples retain source order.
//
// The function is idempotent.
func normalizeRule(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(line))

	inQuote := false
	pendingWS := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inQuote {
			b.WriteByte(c)
			if c == '"' && (i == 0 || line[i-1] != '\\') {
				inQuote = false
			}
			continue
		}
		switch {
		case c == '"':
			if pendingWS {
				if b.Len() > 0 && b.String()[b.Len()-1] != ',' && b.String()[b.Len()-1] != ' ' {
					b.WriteByte(' ')
				}
				pendingWS = false
			}
			b.WriteByte(c)
			inQuote = true
		case c == ' ' || c == '\t':
			pendingWS = true
		case c == ',':
			// Drop any pending whitespace before the comma, then
			// emit the comma followed by a single space.
			pendingWS = false
			b.WriteByte(',')
			// If next non-whitespace is not end-of-line, follow with
			// a single space.
			j := i + 1
			for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
				j++
			}
			if j < len(line) {
				b.WriteByte(' ')
			}
			i = j - 1
		default:
			if pendingWS {
				if b.Len() > 0 {
					last := b.String()[b.Len()-1]
					if last != ' ' && last != ',' {
						b.WriteByte(' ')
					}
				}
				pendingWS = false
			}
			b.WriteByte(c)
		}
	}
	return b.String()
}

// extractAssignmentValue scans a canonicalized rule line for the FIRST
// triple whose key matches keyName (case-sensitive against the
// uppercase form) and whose operator is `=`, `+=`, or `:=`. Returns
// the quoted value (with the surrounding `"` stripped) and ok=true on
// a hit. The match is anchored on word boundaries so a key like
// `RUN_FOO` will not match `RUN`.
func extractAssignmentValue(line, keyName string) (string, bool) {
	// We accept the key case-insensitively for robustness.
	upper := strings.ToUpper(line)
	keyUpper := strings.ToUpper(keyName)
	i := 0
	for i < len(upper) {
		idx := strings.Index(upper[i:], keyUpper)
		if idx < 0 {
			return "", false
		}
		pos := i + idx
		// require word-boundary before (start of line, ',', or
		// whitespace).
		if pos > 0 {
			prev := line[pos-1]
			if prev != ' ' && prev != '\t' && prev != ',' {
				i = pos + 1
				continue
			}
		}
		// position after the key
		j := pos + len(keyUpper)
		// allow a curly-brace-qualified form like RUN{program}+=...
		if j < len(line) && line[j] == '{' {
			closeIdx := strings.IndexByte(line[j:], '}')
			if closeIdx < 0 {
				i = pos + 1
				continue
			}
			j += closeIdx + 1
		}
		// expect operator: =, +=, :=
		// optional whitespace
		for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
			j++
		}
		if j >= len(line) {
			return "", false
		}
		switch {
		case line[j] == '=':
			j++
		case (line[j] == '+' || line[j] == ':') && j+1 < len(line) && line[j+1] == '=':
			j += 2
		default:
			i = pos + 1
			continue
		}
		for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
			j++
		}
		if j >= len(line) || line[j] != '"' {
			return "", false
		}
		j++
		// Read until matching unescaped '"'.
		start := j
		for j < len(line) {
			if line[j] == '\\' && j+1 < len(line) {
				j += 2
				continue
			}
			if line[j] == '"' {
				return line[start:j], true
			}
			j++
		}
		return "", false
	}
	return "", false
}

// Normalize returns the canonical form of an entire udev rules file:
// the concatenation of normalized rules (one per logical line) joined
// by '\n'. Used by tests that assert the file-level canonical form
// even though the module emits per-rule records.
func Normalize(raw []byte) []byte {
	rules := parseRules(raw)
	if len(rules) == 0 {
		return nil
	}
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range rules {
		b.WriteString(normalizeRule(r))
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// firstToken returns the first whitespace-separated token of s.
func firstToken(s string) string {
	s = strings.TrimLeft(s, " \t")
	idx := strings.IndexAny(s, " \t")
	if idx < 0 {
		return s
	}
	return s[:idx]
}
