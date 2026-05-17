// Package systemd implements the linpersist collector for systemd unit
// and timer persistence on Linux.
//
// Site_classes emitted:
//
//   - systemd.unit   .service, .socket, .path, .mount, .automount,
//     .swap, .target, plus their drop-in *.d/*.conf
//   - systemd.timer  .timer plus *.timer.d/*.conf
//
// Per-file record granularity (one record per unit file, one record per
// drop-in fragment). Canonical form (content_norm_sha256) joins line
// continuations, strips comments, canonicalizes section + key order,
// and sorts whitespace-separated set-semantic key values. See
// ADR-0007 for the binding decisions. MITRE T1543.002 for .unit
// records, T1053.006 for .timer records.
package systemd

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// Section is one [Section] block of a unit file with the key=value
// entries that appeared inside it. Sections appear in source order in
// the returned slice; the Normalize pipeline canonicalizes the order
// downstream.
type Section struct {
	Name    string
	Entries []Entry
}

// Entry is one key=value line inside a [Section]. Key keeps the
// capitalization that appeared on disk; the canonical-form pipeline
// applies any normalization. Value has its surrounding whitespace
// trimmed and any line continuations resolved.
type Entry struct {
	Key   string
	Value string
	// Line is the 1-based source line number of the entry. For
	// continuation-joined entries this is the line of the first
	// physical line of the logical entry.
	Line int
}

// ParseError is a non-fatal parse anomaly. The parser still returns a
// usable section list whenever possible; errors carry the line where
// the anomaly was detected so a caller can surface them via
// Record.Errors[].
type ParseError struct {
	Line int
	Msg  string
}

func (e ParseError) Error() string {
	return fmt.Sprintf("line %d: %s", e.Line, e.Msg)
}

// ParseUnitFile parses a systemd unit/timer/drop-in file.
//
// The parser:
//   - joins backslash line continuations into single logical lines;
//   - drops blank lines and full-line comments (# or ; prefix);
//   - records section headers and key=value entries;
//   - tolerates malformed lines by recording a ParseError and
//     continuing, never panics on bad input.
//
// Inline comments are NOT stripped. systemd does not parse inline
// comments and a '#' inside a value is part of the value.
func ParseUnitFile(raw []byte) ([]Section, []ParseError) {
	logical, lineMap := joinContinuations(raw)
	var (
		sections []Section
		errs     []ParseError
		cur      *Section
	)
	for i, line := range logical {
		srcLine := lineMap[i]
		trimmed := strings.TrimRight(line, " \t\r")
		t := strings.TrimLeft(trimmed, " \t")
		if t == "" {
			continue
		}
		if t[0] == '#' || t[0] == ';' {
			continue
		}
		if t[0] == '[' {
			close := strings.IndexByte(t, ']')
			if close < 2 {
				errs = append(errs, ParseError{Line: srcLine, Msg: "malformed section header"})
				continue
			}
			name := strings.TrimSpace(t[1:close])
			if name == "" {
				errs = append(errs, ParseError{Line: srcLine, Msg: "empty section header"})
				continue
			}
			sections = append(sections, Section{Name: name})
			cur = &sections[len(sections)-1]
			continue
		}
		eq := strings.IndexByte(t, '=')
		if eq <= 0 {
			errs = append(errs, ParseError{Line: srcLine, Msg: "key without '='"})
			continue
		}
		if cur == nil {
			errs = append(errs, ParseError{Line: srcLine, Msg: "key=value outside any section"})
			continue
		}
		key := strings.TrimSpace(t[:eq])
		val := strings.TrimSpace(t[eq+1:])
		if key == "" {
			errs = append(errs, ParseError{Line: srcLine, Msg: "empty key"})
			continue
		}
		cur.Entries = append(cur.Entries, Entry{Key: key, Value: val, Line: srcLine})
	}
	return sections, errs
}

// joinContinuations folds backslash-at-end-of-line continuations into
// a single logical line.
//
// systemd.syntax(5): "If a line ends in a backslash, the backslash is
// dropped and the following line is appended." We tolerate trailing
// whitespace between the backslash and the newline (which is
// technically a syntax error but appears in the wild).
//
// The returned slice carries the joined logical lines. lineMap[i]
// holds the 1-based source line number of the FIRST physical line of
// logical line i (used for error reporting).
func joinContinuations(raw []byte) (logical []string, lineMap []int) {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var physical []string
	for sc.Scan() {
		physical = append(physical, sc.Text())
	}
	// Tolerate a final partial line without trailing newline; the
	// scanner already emits it as the last entry, no special-casing.
	i := 0
	for i < len(physical) {
		start := i + 1 // 1-based source line
		text := physical[i]
		for {
			trimmed := strings.TrimRight(text, " \t")
			if !strings.HasSuffix(trimmed, "\\") {
				break
			}
			if i+1 >= len(physical) {
				// trailing backslash with no next line. drop the
				// backslash so the value does not contain it; the
				// alternative (keep it) would emit a bad ExecStart.
				text = trimmed[:len(trimmed)-1]
				break
			}
			text = trimmed[:len(trimmed)-1]
			i++
			text += physical[i]
		}
		logical = append(logical, text)
		lineMap = append(lineMap, start)
		i++
	}
	return logical, lineMap
}
