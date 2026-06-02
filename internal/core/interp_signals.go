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

// InterpreterScriptArg returns the absolute script-file argument a known
// packaged script interpreter is invoked against, or ("", false). cmd is
// the full command token slice with the interpreter first (e.g.
// ["/usr/bin/python3", "/opt/x.py"]). It returns "" for:
//   - non-interpreter commands (cmd[0] basename not in scriptInterpreters),
//   - inline `-c <code>` / `-e <code>` forms (no script-file argument; an
//     absolute path INSIDE inline code is a redirect/arg, not the script,
//     so we bail to avoid the `/bin/sh -c '...< /opt/...'` vendor-unit FP),
//   - commands with no absolute-path argument.
//
// The first non-flag absolute-path argument is taken as the script. This
// is the resolution point both the orphan check (InterpreterScriptOrphan)
// and the integrity check (the sink/module VerifyPath) key on, so a
// packaged interpreter running an orphan OR an owned-but-tampered script
// is no longer invisible behind the owned interpreter exec_target.
func InterpreterScriptArg(cmd []string) (string, bool) {
	if len(cmd) < 2 {
		return "", false
	}
	base := cmd[0]
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	if !scriptInterpreters[base] {
		return "", false
	}
	for _, arg := range cmd[1:] {
		switch arg {
		case "-c", "-e", "-E", "-eval", "--eval", "--command":
			return "", false // inline code; no script file
		}
		if strings.HasPrefix(arg, "-") {
			continue // other flag (e.g. python3 -u <script>)
		}
		if !strings.HasPrefix(arg, "/") {
			continue // relative / non-path token (awk program text, etc.)
		}
		return arg, true
	}
	return "", false
}

// InterpreterScriptOrphan reports whether cmd is a packaged interpreter
// invoked against a script-file argument that resolves to an orphan
// (package-unowned) path via prov. Thin wrapper over InterpreterScriptArg.
func InterpreterScriptOrphan(prov Provenance, cmd []string) bool {
	if prov == nil {
		return false
	}
	arg, ok := InterpreterScriptArg(cmd)
	if !ok {
		return false
	}
	_, st := prov.LookupPath(arg)
	return st == PkgStatusOrphan
}
