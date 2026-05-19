package netdispatch

import (
	"bufio"
	"bytes"
	"strings"
)

// Normalize returns the canonical form of a network dispatcher
// script. Rules mirror the shell-normalizer used by motd, profile,
// sysv, and atjobs:
//
//   - `#` comments (including shebangs) are dropped.
//   - Blank lines are dropped.
//   - Trailing whitespace per line is stripped.
//
// Two scripts that differ only in shebang or comment-noise produce
// the same content_norm_sha256.
func Normalize(raw []byte) []byte {
	var out bytes.Buffer
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \t")
		if line == "" {
			continue
		}
		if strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}
