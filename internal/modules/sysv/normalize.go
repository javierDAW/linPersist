package sysv

import (
	"bufio"
	"bytes"
	"strings"
)

// Normalize returns the canonical content of a sysv-style init
// script. Two inputs that differ only in comments, blank lines, or
// trailing whitespace produce the same canonical output and the same
// content_norm_sha256.
//
// Rules:
//   - Strip trailing whitespace on every line.
//   - Drop lines starting with '#' after left-trim (including the
//     LSB init-info markers `### BEGIN INIT INFO` / `### END INIT
//     INFO` and the metadata between them, which start with '#').
//     The metadata is informational; canonicalizing it away means
//     two scripts that share their executable body but carry
//     different LSB headers collapse to the same content_norm_sha256.
//   - Drop blank lines.
//   - Join surviving lines with '\n'. Output ends with '\n' iff at
//     least one line survived.
//
// The shebang (`#!/bin/sh`, `#!/bin/bash`, ...) is also dropped by
// the comment rule. Init scripts are executed by the kernel as
// scripts, so the shebang is significant -- but for stacking
// purposes the body is what matters, and a malicious script that
// changes its shebang from `#!/bin/sh` to `#!/bin/bash` keeps the
// same canonical hash. If that becomes a real triage gap we can
// revisit and preserve the shebang line.
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
