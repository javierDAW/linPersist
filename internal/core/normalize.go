package core

import (
	"bufio"
	"bytes"
	"strings"
)

// Normalization helpers shared across modules. The contract for any
// module-specific Normalize function is documented in
// docs/normalization-rules.md: identical content modulo whitespace,
// comments and (where defined) key ordering MUST hash to the same
// content_norm_sha256 value. These helpers are the bricks; each module
// composes them in the order its file format requires.

// StripLineComments returns b with every line truncated at the first
// occurrence of the given prefix (typically "#" or ";"). Trailing
// whitespace on each resulting line is trimmed. Empty lines are
// dropped. The output always ends with a single trailing newline so
// that concatenations stay round-trippable.
func StripLineComments(b []byte, prefix string) []byte {
	var out bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(b))
	// 1 MiB max line; persistence files larger than that are pathological
	// and the module should bail out before reaching the normalizer.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, prefix); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimRight(line, " \t\r")
		if line == "" {
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

// CollapseWhitespace replaces every run of spaces and tabs with a
// single space. Newlines are preserved. Use this AFTER StripLineComments
// when the file format treats internal whitespace as insignificant
// (e.g. crontab, sudoers).
func CollapseWhitespace(b []byte) []byte {
	var out bytes.Buffer
	out.Grow(len(b))
	prevSpace := false
	for _, r := range string(b) {
		switch r {
		case ' ', '\t':
			if !prevSpace {
				out.WriteByte(' ')
				prevSpace = true
			}
		case '\n':
			out.WriteByte('\n')
			prevSpace = false
		default:
			out.WriteRune(r)
			prevSpace = false
		}
	}
	return out.Bytes()
}
