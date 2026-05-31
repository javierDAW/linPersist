// trap.go -- line-level detector for shell `trap CMD SIGNAL...` patterns
// in the same shell-init files the profile module already walks. MITRE
// T1546.005 (Event Triggered Execution: Trap).
//
// The detector is intentionally conservative on legitimate no-ops:
//   * `trap`               (alone -- lists current traps)
//   * `trap '' SIGNAL`     (ignore the signal)
//   * `trap - SIGNAL`      (reset to default)
// None of those three patterns emit a record. Comments are skipped
// before parsing. Multi-line continuations (line ending in backslash
// before newline) are joined into a single logical line before scanning.
//
// Author: Jarmi <jarmidaw@gmail.com>

package profile

import (
	"strings"

	"github.com/jarmidaw/linpersist/internal/core"
)

// trapHit describes one persistent trap directive discovered in a shell
// init file. `raw` is the joined logical line (after continuation
// merging) trimmed of leading/trailing whitespace; `cmd` is the trap's
// command argument with surrounding quotes stripped; `signals` is the
// signal-name list following the command.
type trapHit struct {
	raw     string
	cmd     string
	signals []string
}

// scanTraps walks the file content line-by-line (after joining
// backslash-continued lines) and returns one trapHit per real trap
// directive. Order is stable: hits appear in source order.
func scanTraps(content []byte) []trapHit {
	// Merge continued lines first. `\<newline>` becomes a single space.
	// We must do this on the raw text so the quoted block survives
	// intact across a continuation.
	txt := strings.ReplaceAll(string(content), "\\\n", " ")
	var hits []trapHit
	for _, line := range strings.Split(txt, "\n") {
		cmd, sigs, ok := parseTrapLine(line)
		if !ok {
			continue
		}
		hits = append(hits, trapHit{
			raw:     strings.TrimSpace(line),
			cmd:     cmd,
			signals: sigs,
		})
	}
	return hits
}

// parseTrapLine returns (cmd, signals, ok). ok is false for any of:
//   - empty / whitespace-only lines
//   - lines whose first non-blank char is '#'  (comments)
//   - lines that do not start with the literal word `trap` followed by
//     whitespace
//   - `trap` alone (lists current traps, no persistence shape)
//   - `trap ” SIGNAL`, `trap "" SIGNAL` (ignore -- legitimate no-op)
//   - `trap - SIGNAL` (reset to default -- legitimate no-op)
//
// cmd is returned WITHOUT the surrounding quote characters.
func parseTrapLine(line string) (string, []string, bool) {
	s := strings.TrimSpace(line)
	if s == "" || strings.HasPrefix(s, "#") {
		return "", nil, false
	}
	// Must start with `trap` followed by whitespace or end-of-line.
	if !strings.HasPrefix(s, "trap") {
		return "", nil, false
	}
	rest := s[len("trap"):]
	if rest == "" {
		// `trap` alone -- lists current traps.
		return "", nil, false
	}
	if rest[0] != ' ' && rest[0] != '\t' {
		// Not the trap builtin (e.g. `trapeze ...`).
		return "", nil, false
	}
	rest = strings.TrimLeft(rest, " \t")

	cmd, after, ok := extractToken(rest)
	if !ok {
		return "", nil, false
	}
	// Skip no-op patterns.
	if cmd == "" || cmd == "-" {
		return "", nil, false
	}
	after = strings.TrimSpace(after)
	if after == "" {
		// `trap CMD` with no signals would also list -- skip.
		return "", nil, false
	}
	sigs := strings.Fields(after)
	if len(sigs) == 0 {
		return "", nil, false
	}
	return cmd, sigs, true
}

// extractToken returns the next shell token from s, the remaining text,
// and an ok flag. It handles double-quoted "..." and single-quoted '...'
// tokens by stripping the surrounding quotes. Unquoted tokens end at
// the next whitespace. Unterminated quotes return (empty, "", false).
func extractToken(s string) (string, string, bool) {
	s = strings.TrimLeft(s, " \t")
	if s == "" {
		return "", "", false
	}
	first := s[0]
	if first == '"' || first == '\'' {
		// Find the matching close quote. We don't honour backslash
		// escapes inside the quoted region: the shell does, but for
		// our purposes the cmd text is mostly opaque -- we just need
		// the right end position so the signals list survives.
		for i := 1; i < len(s); i++ {
			if s[i] == first {
				return s[1:i], s[i+1:], true
			}
		}
		// Unterminated quote.
		return "", "", false
	}
	// Unquoted: end at whitespace.
	end := len(s)
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			end = i
			break
		}
	}
	return s[:end], s[end:], true
}

// signalsForTrapHit returns the linpersist signal names a trapHit
// contributes. The base file-level signals (recent_mtime_*, world_writable,
// non_root_owner) are added by the caller via baseSignals(); this helper
// only adds trap-specific signals.
func signalsForTrapHit(h trapHit) []string {
	var out []string
	out = append(out, core.SignalTrapCommand)
	for _, sig := range h.signals {
		switch strings.ToUpper(strings.TrimPrefix(sig, "SIG")) {
		case "EXIT", "DEBUG", "RETURN", "ERR":
			out = append(out, core.SignalTrapExitHandler)
		}
	}
	// trap_command_in_tmp fires when the first token of the command
	// resolves under any tmp-class dir. We re-tokenize the command body
	// to find argv[0]; using core.TmpDirs (not a "/tmp/" literal) matches
	// every other module's interpreter_in_tmp heuristic, so a trap into
	// /var/tmp, /dev/shm or /run/shm no longer evades the signal.
	if cmdFirst, _, ok := extractToken(h.cmd); ok {
		for _, d := range core.TmpDirs {
			if strings.HasPrefix(cmdFirst, d) {
				out = append(out, core.SignalTrapCommandInTmp)
				break
			}
		}
	}
	return out
}

// execTargetFromTrap returns the absolute-path argv[0] of the trap's
// command if it looks like one, otherwise "". Used to populate
// Record.ExecTarget for downstream provenance lookup and Q4/Q6/Q11.
func execTargetFromTrap(h trapHit) string {
	tok, _, ok := extractToken(h.cmd)
	if !ok {
		return ""
	}
	if !strings.HasPrefix(tok, "/") {
		// Relative command, function name, or builtin -- not an
		// exec_target we can resolve against package manifests.
		return ""
	}
	return tok
}
