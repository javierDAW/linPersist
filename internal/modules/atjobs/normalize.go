package atjobs

import (
	"bufio"
	"bytes"
	"strings"
)

// shellHeredocPrefix is the line atd writes immediately before the
// real job body, opening a heredoc whose closing tag is a random
// marker on the same line. See man at(1) and the at-spool source.
const shellHeredocPrefix = "${SHELL:-/bin/sh}"

// extractBody returns the heredoc body of an at(1) spool file: the
// lines between the `${SHELL:-/bin/sh} << 'MARKER'` opener and the
// matching closing `MARKER` line. If the file does not follow the
// expected atd layout, the whole raw input is returned with structured
// = false so the caller can pick a fallback hashing strategy.
//
// The header that atd prepends (umask, HOME, PATH, LOGNAME, USER,
// SHELL, TERM, cd ...) is deliberately stripped: it is volatile per
// user and per session and would defeat frequency stacking if hashed
// alongside the actual job content.
func extractBody(raw []byte) (body []byte, structured bool) {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	// Bump buffer for unusually large jobs (the default 64 KiB cap
	// would truncate a multi-megabyte payload; 1 MiB is plenty since
	// the spool file is bounded by Options.MaxFileSize anyway).
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var marker string
	var capturing bool
	var out bytes.Buffer
	for sc.Scan() {
		line := sc.Text()
		if !capturing {
			if m, ok := heredocMarker(line); ok {
				marker = m
				capturing = true
			}
			continue
		}
		// Capturing. Closing marker is the marker on its own line
		// (atd writes it without leading whitespace).
		if line == marker {
			return out.Bytes(), true
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	// Either no heredoc opener was seen (malformed / hand-edited
	// spool file) or the closing marker was missing. Return raw with
	// structured=false; the module falls back to hashing the whole
	// file content sans header guess.
	return raw, false
}

// heredocMarker returns the heredoc marker if line is the opener
// `${SHELL:-/bin/sh} << 'MARKER'` (single or double quotes, with or
// without leading whitespace). The boolean is false when line is
// some other shell construct.
func heredocMarker(line string) (string, bool) {
	trimmed := strings.TrimLeft(line, " \t")
	if !strings.HasPrefix(trimmed, shellHeredocPrefix) {
		return "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(trimmed, shellHeredocPrefix))
	// Expect "<<" optionally followed by '-' (heredoc-tabs form).
	if !strings.HasPrefix(rest, "<<") {
		return "", false
	}
	rest = strings.TrimPrefix(rest, "<<")
	rest = strings.TrimPrefix(rest, "-")
	rest = strings.TrimLeft(rest, " \t")
	if rest == "" {
		return "", false
	}
	// Marker may be quoted with ' or " or unquoted.
	q := rest[0]
	if q == '\'' || q == '"' {
		end := strings.IndexByte(rest[1:], q)
		if end < 0 {
			return "", false
		}
		return rest[1 : 1+end], true
	}
	// Unquoted: marker is the next whitespace-delimited token.
	end := strings.IndexAny(rest, " \t")
	if end < 0 {
		end = len(rest)
	}
	return rest[:end], true
}

// Normalize returns the canonical form of an at(1) spool file. When
// the file follows the expected atd layout the canonical form is the
// heredoc body with comments and blank lines stripped (same rules as
// the profile/sysv/motd-shell normalizer). When the file is
// unstructured, the canonical form is the raw input with the same
// strip pass — best effort, lower stacking yield, but still
// deterministic.
func Normalize(raw []byte) []byte {
	body, _ := extractBody(raw)
	return normalizeShell(body)
}

// normalizeShell strips '#' comments, blank lines, and trailing
// whitespace per line. Mirrors the existing motd/profile/sysv
// normalizer so two at jobs with the same logical content but
// different cosmetic noise produce the same content_norm_sha256.
func normalizeShell(raw []byte) []byte {
	var out bytes.Buffer
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \t")
		if line == "" {
			continue
		}
		ltrim := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(ltrim, "#") {
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}
