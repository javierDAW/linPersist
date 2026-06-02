package core

import "strings"

// scriptInterpreters is the set of executable basenames that, when they
// appear as a command's first token, mean the real workload is a script
// (or inline code) passed as an argument rather than the binary itself.
// Mirrors the per-module shellInterps sets but lives in core so cron and
// systemd share one source for InterpreterScriptOrphan.
var scriptInterpreters = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ash": true, "ksh": true,
	"python": true, "python2": true, "python3": true,
	"perl": true, "ruby": true, "php": true, "node": true, "lua": true,
	"awk": true, "gawk": true,
}

// InterpreterScriptOrphan reports whether cmd is a known packaged script
// interpreter invoked against a script-file argument that resolves to an
// orphan (package-unowned) path via prov. cmd is the full command token
// slice with the interpreter first (e.g. ["/usr/bin/python3", "/opt/x.py"]).
//
// The point: exec_target captures only cmd[0] (the interpreter), which on
// a "live off the packaged interpreter" implant is owned -- so the orphan
// payload it runs is otherwise invisible. Returns false for:
//   - non-interpreter commands (cmd[0] basename not in scriptInterpreters),
//   - inline `-c <code>` / `-e <code>` forms (no script-path argument),
//   - script arguments that ARE package-owned (the legit vendor case).
//
// The first non-flag absolute-path argument is taken as the script.
func InterpreterScriptOrphan(prov Provenance, cmd []string) bool {
	if prov == nil || len(cmd) < 2 {
		return false
	}
	base := cmd[0]
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	if !scriptInterpreters[base] {
		return false
	}
	for _, arg := range cmd[1:] {
		switch arg {
		case "-c", "-e", "-E", "-eval", "--eval", "--command":
			// Inline-code switch: everything after is shell/interp source,
			// NOT a script-file path. A naive scan would wrongly treat an
			// absolute path INSIDE the inline code (a redirect target, an
			// argument) as "the script" -- the exact false positive that
			// fires on the ubiquitous `ExecStart=/bin/sh -c '...'` vendor
			// unit shape. Inline code is LFA-only by design, so bail.
			return false
		}
		if strings.HasPrefix(arg, "-") {
			continue // other flag (e.g. python3 -u <script>)
		}
		if !strings.HasPrefix(arg, "/") {
			continue // relative / non-path token (awk program text, etc.)
		}
		_, st := prov.LookupPath(arg)
		return st == PkgStatusOrphan
	}
	return false
}
