package motd

import (
	"bufio"
	"bytes"
	"strings"
)

// NormalizeText returns the canonical content of a plain-text motd
// or motd.d/* file. Two inputs that differ only in trailing
// whitespace or blank lines produce the same canonical output.
//
// '#' is NOT treated as a comment character because motd banners are
// arbitrary text and a banner line starting with '#' is content, not
// a directive. The cron / profile shell-style strip rule does NOT
// apply here.
func NormalizeText(raw []byte) []byte {
	var out bytes.Buffer
	out.Grow(len(raw))
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \t\r")
		if strings.TrimLeft(line, " \t") == "" {
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

// NormalizeShell returns the canonical content of an update-motd.d
// shell script. Strips '#' comment lines (including shebangs and LSB
// init-info headers), blank lines, and per-line trailing whitespace.
// Same rules as the `profile` and `sysv` modules.
func NormalizeShell(raw []byte) []byte {
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
