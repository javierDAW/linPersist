package main

// Shared TTY / ANSI helpers used by every text renderer in the report
// engine (render_text.go fleet view, render_host_text.go dossier,
// render_diff_text.go diff). Keeping them in one file makes the
// ownership obvious and stops the helpers from drifting per-renderer.

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// ansi wraps strings with SGR escapes when enabled is true; otherwise
// returns the input unchanged.
//
// Each helper resets only the attribute it set, so nested calls
// compose:
//   - bold uses 1m / 22m (sets bold / cancels bold, color untouched)
//   - red uses 31m / 39m (sets color / default color, bold untouched)
//   - orange uses 38;5;208m / 39m (256-color / default color)
//
// This lets `a.bold(a.red("X"))` produce a "bold red X" without the
// inner red's reset prematurely cancelling the outer bold.
type ansi struct{ enabled bool }

func (a *ansi) bold(s string) string {
	if !a.enabled {
		return s
	}
	return "\x1b[1m" + s + "\x1b[22m"
}

func (a *ansi) red(s string) string {
	if !a.enabled {
		return s
	}
	return "\x1b[31m" + s + "\x1b[39m"
}

func (a *ansi) orange(s string) string {
	if !a.enabled {
		return s
	}
	return "\x1b[38;5;208m" + s + "\x1b[39m"
}

// isTTY returns true if f is a character device (terminal). Used to
// gate ANSI escapes.
func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// textSection prints a section title with a dashed underline. ANSI bold
// is applied when enabled; the underline uses the visible length so the
// dashes line up regardless of escape sequences.
func textSection(out io.Writer, a *ansi, title string) {
	fmt.Fprintln(out, a.bold(title))
	fmt.Fprintln(out, strings.Repeat("-", visibleLen(title)))
}

// visibleLen returns the printable rune count of s, stripping ANSI SGR
// escapes (\x1b[...m).
func visibleLen(s string) int {
	n := 0
	inEsc := false
	for _, c := range s {
		if inEsc {
			if c == 'm' {
				inEsc = false
			}
			continue
		}
		if c == '\x1b' {
			inEsc = true
			continue
		}
		n++
	}
	return n
}

// barWidth scales a count to a maximum bar width, ensuring any
// non-zero value renders at least one block so the analyst can see
// it.
func barWidth(count, max, scale int) int {
	if max <= 0 || count <= 0 {
		return 0
	}
	w := count * scale / max
	if w < 1 {
		w = 1
	}
	return w
}

// maybeRed returns s in red when condition is true, plain otherwise.
func maybeRed(a *ansi, s string, condition bool) string {
	if condition {
		return a.red(s)
	}
	return s
}

// severityValue formats an Overview severity count with the right
// ANSI tint (red for critical-with-hits, orange for high-with-hits,
// plain otherwise). Hits == 0 stays plain regardless of severity so
// the overview reads quiet on a quiet fleet.
func severityValue(a *ansi, count int, sev string) string {
	s := strconv.Itoa(count)
	if count == 0 {
		return s
	}
	switch sev {
	case "critical":
		return a.red(s)
	case "high":
		return a.orange(s)
	}
	return s
}

// colorSeverity returns the severity label tinted to match
// severityValue's count colouring. Used for the Q7 row severity cell.
func colorSeverity(a *ansi, sev string) string {
	switch sev {
	case "critical":
		return a.red(sev)
	case "high":
		return a.orange(sev)
	}
	return sev
}

// isControlRune reports whether r is a terminal-control code that must
// never reach a TTY verbatim from untrusted, record-derived data: the
// C0 controls (0x00–0x1F, includes CR, TAB and ESC), DEL (0x7F) and the
// C1 controls (0x80–0x9F). These cover the ESC/CSI/OSC introducers and
// cursor-movement / line-erase sequences a hostile host could use to
// overwrite or hide its own row from the analyst's terminal.
func isControlRune(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f)
}

// safeCell renders an untrusted, record-derived string for display on a
// terminal. Every control rune (see isControlRune) is replaced with a
// visible \xHH escape so a compromised monitored host cannot smuggle
// ANSI cursor-movement, line-erase or OSC sequences through a path,
// content_snippet or exec_target and thereby scrub its own implant row
// out of the report the analyst is reading. The singleton-hunt is the
// tool's whole point; an un-sanitized cell would let the implant edit
// the very view meant to surface it.
//
// Printable runes — including multibyte UTF-8 — pass through unchanged;
// invalid UTF-8 bytes decode to U+FFFD via range-over-string and are
// preserved as that visible replacement character.
//
// safeCell must wrap record-derived cells ONLY. Strings the renderer
// colours itself (the ansi helpers, colorSeverity, the GAP marker)
// legitimately contain ESC and must NOT be passed through safeCell, or
// their colouring would be flattened into literal "\x1b[..m" text.
func safeCell(s string) string {
	if !strings.ContainsFunc(s, isControlRune) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		if isControlRune(r) {
			fmt.Fprintf(&b, `\x%02x`, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// fprintfSafe is fmt.Fprintf with every string argument passed through
// safeCell first. Use it for table rows whose every string cell is
// record-derived (no renderer-applied colour). Rows that interleave a
// coloured cell (a severity tint, a +/- diff mark, a GAP flag) must
// sanitize their untrusted cells with safeCell individually instead, so
// the legitimate ESC in the coloured cell survives.
func fprintfSafe(w io.Writer, format string, args ...any) {
	for i, a := range args {
		if s, ok := a.(string); ok {
			args[i] = safeCell(s)
		}
	}
	fmt.Fprintf(w, format, args...)
}
