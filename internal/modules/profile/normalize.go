// Package profile normalization helpers for shell init scripts.
//
// Per-file canonicalization rule for content_norm_sha256:
//
//   - Strip trailing whitespace on every line.
//   - Drop lines starting with '#' after left-trim (any comment,
//     including shebangs since profile files are sourced not
//     executed).
//   - Drop blank lines.
//   - Join remaining lines back with '\n'; the output ends with
//     '\n' iff at least one line survived.
package profile

import (
	"bufio"
	"bytes"
	"strings"
)

// Normalize returns the canonical content of a profile-family file.
// Two inputs that differ only in comments, blank lines, or trailing
// whitespace produce the same canonical output (and therefore the
// same content_norm_sha256).
func Normalize(raw []byte) []byte {
	var out bytes.Buffer
	out.Grow(len(raw))
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \t\r")
		t := strings.TrimLeft(line, " \t")
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}
