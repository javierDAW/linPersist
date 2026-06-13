package core

import "strings"

// behavioral.go implements the Tier-B behavioral grammars (ADR-0017): a
// FROZEN, finite set of execution-control idioms lifted from the
// untruncated logical command line a persistence module collected
// (Record.FullExecLine). It is pure-Go string analysis — no execution, no
// network, no decoding of payload bodies (that is the scope §8.1 inline-
// code boundary, deliberately left to LFA).
//
// Design constraints baked in from the cross-disciplinary consensus:
//   - Match the FULL line, never the 256-byte ContentSnippet (a long
//     dropper's "| sh" tail can sit past the cap = free evasion).
//   - The discriminator is the SYNTACTIC GLUE (fetch/decode | interpreter,
//     socket -> shell), NEVER a bare verb (the bare-curl flood lesson).
//   - Adjacency in ONE command, not co-occurrence in a file: the pipe must
//     actually connect a source stage to an interpreter stage.
//   - Every reverse-shell arm REQUIRES a shell execution sink.
//
// ScanBehavioral is called once centrally from the emit sink; modules only
// populate Record.FullExecLine.

// rawShells is the interpreter set whose presence DOWNSTREAM of a fetch/
// decode pipe is an unconditional rung-1 promoter. Scripting interpreters
// (python/perl/ruby/php/node) are intentionally excluded in v1 — a cron
// `curl … | python3 parse.py` data pipeline is a real benign pattern, so
// that subset is left to a co-indicator + LFA.
var rawShells = map[string]struct{}{
	"sh": {}, "bash": {}, "dash": {}, "ksh": {}, "zsh": {},
}

// pipeWrappers are leading tokens stripped from a pipe stage before reading
// its argv0, so `| env sh`, `| xargs sh -c`, `| sudo bash`, `| busybox sh`
// all resolve to the shell. (Also strips VAR=val env assignments.)
var pipeWrappers = map[string]struct{}{
	"env": {}, "xargs": {}, "sudo": {}, "nohup": {}, "setsid": {},
	"stdbuf": {}, "nice": {}, "timeout": {}, "busybox": {},
}

// ScanBehavioral returns the Tier-B signals present in a lifted persistence
// command line. line MUST be the full, untruncated logical line. An empty
// line (non-exec record) yields nil.
func ScanBehavioral(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	// Scan the line AND the bodies of any `<shell> -c '<body>'` wrapper, so
	// a pipe hidden inside a quoted -c argument (sh -c 'curl … | sh') is
	// still seen. The quotes that hide it from the top-level pipe splitter
	// are exactly the wrapper's own quotes.
	candidates := append([]string{line}, dashCBodies(line)...)
	var out []string
	for _, c := range candidates {
		if fetchPipedToInterpreter(c) {
			out = append(out, SignalFetchPipedToInterpreter)
			break
		}
	}
	for _, c := range candidates {
		if reverseShellSocketIdiom(c) {
			out = append(out, SignalReverseShellSocketIdiom)
			break
		}
	}
	return out
}

// dashCBodies returns the quoted argument bodies of `-c '<body>'` /
// `-c "<body>"` occurrences (one level), where the pipe/socket wiring of a
// `sh -c '…'` wrapper lives.
func dashCBodies(line string) []string {
	var bodies []string
	for {
		p := strings.Index(line, "-c ")
		if p < 0 {
			break
		}
		rest := strings.TrimLeft(line[p+3:], " ")
		if len(rest) > 0 && (rest[0] == '\'' || rest[0] == '"') {
			q := rest[0]
			if end := strings.IndexByte(rest[1:], q); end >= 0 {
				bodies = append(bodies, rest[1:1+end])
			}
		}
		line = line[p+3:]
	}
	return bodies
}

// --- fetch_piped_to_interpreter -----------------------------------------

func fetchPipedToInterpreter(line string) bool {
	// Process-substitution form: `bash <(curl …)`, `. <(wget …)`,
	// `source <(base64 -d …)`. The shell consumes the source's output.
	if procSubFetch(line) {
		return true
	}
	stages := splitTopLevelPipe(line)
	if len(stages) < 2 {
		return false
	}
	// A SOURCE stage upstream of a RAW-SHELL stage. Scan in order: once a
	// source is seen, any later raw-shell stage closes the pattern.
	srcSeen := false
	for _, st := range stages {
		if srcSeen && (stageIsRawShell(st) || stageIsScriptingInterpreterStdin(st)) {
			return true
		}
		if isSourceStage(st) {
			srcSeen = true
		}
	}
	return false
}

// isSourceStage reports whether a pipe stage emits attacker-controlled
// bytes to stdout: a downloader-to-stdout or a decoder. The source verb is
// matched ANYWHERE in the stage (a cron schedule/user prefix or a
// systemd-run/setsid wrapper sits to its left), and the flags are
// evaluated over the whole stage's argv. A downloader that writes to a FILE
// (-o/-O/--output) is NOT a source (it re-enters Tier A via the dropped
// file's tmp/orphan tells).
func isSourceStage(stage string) bool {
	argv := tokenize(stage)
	if len(argv) == 0 {
		return false
	}
	for _, tok := range argv {
		switch base(tok) {
		case "curl", "fetch":
			if !hasOutputToFile(argv) {
				return true
			}
		case "wget":
			if wgetToStdout(argv) {
				return true
			}
		case "base64", "base32":
			if hasAnyFlag(argv, "-d", "--decode", "-D") {
				return true
			}
		case "xxd":
			if hasAnyFlag(argv, "-r") {
				return true
			}
		case "uudecode", "gunzip", "zcat", "bunzip2", "xzcat", "zstdcat":
			return true
		case "gzip":
			if hasAnyFlag(argv, "-d", "-dc", "--decompress") {
				return true
			}
		case "openssl":
			if contains(argv, "enc") && hasAnyFlag(argv, "-d") {
				return true
			}
		}
	}
	return false
}

func stageIsRawShell(stage string) bool {
	argv := stripWrappers(tokenize(stage))
	if len(argv) == 0 {
		return false
	}
	_, ok := rawShells[base(argv[0])]
	return ok
}

// scriptingInterps are language interpreters that, like a raw shell, execute
// a program read from stdin when given NO program source of their own.
var scriptingInterps = map[string]struct{}{
	"python": {}, "python2": {}, "python3": {},
	"perl": {}, "ruby": {}, "php": {}, "node": {}, "nodejs": {},
}

// stageIsScriptingInterpreterStdin reports whether the sink stage is a
// scripting interpreter invoked with NO program source other than stdin — so
// it will EXECUTE the piped (downloaded/decoded) bytes as code. This is the
// `curl … | sh` hazard for interpreters (`curl … | python3`, `… | perl`).
//
// Deliberately narrow to avoid the data-pipeline false positives that kept
// interpreters out of the v1 rawShells set: a script-file argument
// (`… | python3 parse.py`) or an inline-code / module flag
// (`… | python3 -c '…'`, `perl -e`, `php -r`, `python3 -m mod`) means the
// pipe is DATA, not the program — those are EXCLUDED. Only a bare interpreter
// (optionally `-` or innocuous flags like -u) consuming stdin as its program
// fires.
func stageIsScriptingInterpreterStdin(stage string) bool {
	argv := stripWrappers(tokenize(stage))
	if len(argv) == 0 {
		return false
	}
	if _, ok := scriptingInterps[base(argv[0])]; !ok {
		return false
	}
	for _, a := range argv[1:] {
		switch a {
		case "-c", "-e", "-E", "-m", "-r", "--eval", "--exec", "-w":
			return false // program is the flag's argument; stdin is data
		}
		if a != "-" && !strings.HasPrefix(a, "-") {
			return false // positional script-file argument; stdin is data
		}
	}
	return true
}

// procSubFetch matches `<shell> <(<source> …)` and `. <(…)` / `source <(…)`.
func procSubFetch(line string) bool {
	idx := 0
	for {
		p := strings.Index(line[idx:], "<(")
		if p < 0 {
			return false
		}
		at := idx + p
		// command word immediately before "<(": last token before it.
		left := strings.TrimSpace(line[:at])
		lt := tokenize(left)
		if len(lt) > 0 {
			head := base(lt[len(lt)-1])
			_, isShell := rawShells[head]
			if isShell || head == "." || head == "source" {
				// inner first token must be a source.
				inner := line[at+2:]
				if c := strings.IndexByte(inner, ')'); c >= 0 {
					inner = inner[:c]
				}
				if isSourceStage(strings.TrimSpace(inner)) {
					return true
				}
			}
		}
		idx = at + 2
	}
}

// --- reverse_shell_socket_idiom -----------------------------------------

func reverseShellSocketIdiom(line string) bool {
	l := " " + strings.ToLower(line) + " "
	hasDevSock := strings.Contains(l, "/dev/tcp/") || strings.Contains(l, "/dev/udp/")

	// ARM A: /dev/tcp wired to a shell. Require a shell execution sink, not
	// bare presence (excludes `</dev/tcp/host/port` and `echo >/dev/tcp`
	// liveness/wait-for-it probes).
	if hasDevSock {
		interactive := strings.Contains(l, "bash -i") || strings.Contains(l, "sh -i") ||
			strings.Contains(l, "-i >&") || strings.Contains(l, "-i>&")
		redirToSock := strings.Contains(l, ">& /dev/tcp") || strings.Contains(l, ">&/dev/tcp") ||
			strings.Contains(l, "&> /dev/tcp") || strings.Contains(l, "&>/dev/tcp") ||
			strings.Contains(l, ">& /dev/udp") || strings.Contains(l, ">&/dev/udp")
		// exec N<>/dev/tcp … then an fd-shuffle feeding a shell (`<&`,`>&`,`|sh`)
		fdShuffleShell := strings.Contains(l, "<>") &&
			(strings.Contains(l, "|sh") || strings.Contains(l, "| sh") ||
				strings.Contains(l, "|bash") || strings.Contains(l, "| bash") ||
				strings.Contains(l, "0<&") || strings.Contains(l, "<&"))
		if interactive || redirToSock || fdShuffleShell {
			return true
		}
	}

	// ARM B: nc/ncat/netcat with -e/-c/--exec naming a shell; socat
	// EXEC:/SYSTEM: naming a shell. Require the exec operand to BE a shell
	// (excludes `nc -z` port checks and socat relays / non-shell EXEC).
	if hasNCFamily(l) && ncExecsShell(l) {
		return true
	}
	if strings.Contains(l, "socat") && socatExecsShell(l) {
		return true
	}

	// ARM C: mkfifo/mknod back-pipe paired with nc and a shell.
	if (strings.Contains(l, "mkfifo") || (strings.Contains(l, "mknod") && strings.Contains(l, " p"))) &&
		hasNCFamily(l) && namesShell(l) {
		return true
	}
	return false
}

func hasNCFamily(l string) bool {
	// Token-exact scan so "sync"/"func" never match, but "|nc " / ";nc " /
	// "/usr/bin/ncat" all do. Split the lowercased line on shell separators.
	for _, tok := range strings.FieldsFunc(l, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '|' || r == ';' || r == '&' || r == '\n'
	}) {
		switch base(tok) {
		case "nc", "ncat", "netcat":
			return true
		}
	}
	return false
}

// ncExecsShell: nc carries an exec flag (-e/-c/--exec/--sh-exec) whose
// operand names a shell.
func ncExecsShell(l string) bool {
	for _, f := range []string{"-e ", "-c ", "--exec ", "--sh-exec "} {
		p := strings.Index(l, f)
		if p < 0 {
			continue
		}
		if namesShell(l[p:]) {
			return true
		}
	}
	return false
}

// socatExecsShell: socat EXEC:/SYSTEM: whose operand names a shell.
func socatExecsShell(l string) bool {
	for _, kw := range []string{"exec:", "system:"} {
		p := strings.Index(l, kw)
		if p < 0 {
			continue
		}
		// look at the operand window after the keyword.
		end := p + len(kw) + 40
		if end > len(l) {
			end = len(l)
		}
		if namesShell(l[p:end]) {
			return true
		}
	}
	return false
}

// namesShell reports whether s mentions a shell binary/token.
func namesShell(s string) bool {
	for _, sh := range []string{"/bin/sh", "/bin/bash", "/bin/dash", "bash", "/bin/zsh", " sh", "'sh", "\"sh", ":sh", "dash", " -i", "/bin/ash", "busybox"} {
		if strings.Contains(s, sh) {
			return true
		}
	}
	return false
}

// --- small shell-ish tokenizer (deliberately NOT a full shell parser) ---

// splitTopLevelPipe splits on '|' that is outside single/double quotes and
// is not part of '||'. Good enough for lifted persistence command lines;
// it deliberately mis-parses pathological quoting (accepted as a miss).
func splitTopLevelPipe(line string) []string {
	var stages []string
	var b strings.Builder
	var q byte // current quote char, 0 if none
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			}
			b.WriteByte(c)
		case c == '\'' || c == '"':
			q = c
			b.WriteByte(c)
		case c == '|':
			if i+1 < len(line) && line[i+1] == '|' { // '||' logical-or, not a pipe
				b.WriteByte(c)
				b.WriteByte(line[i+1])
				i++
				continue
			}
			stages = append(stages, strings.TrimSpace(b.String()))
			b.Reset()
		default:
			b.WriteByte(c)
		}
	}
	if s := strings.TrimSpace(b.String()); s != "" {
		stages = append(stages, s)
	}
	return stages
}

// tokenize splits a stage on whitespace, respecting quotes loosely.
func tokenize(stage string) []string {
	var toks []string
	var b strings.Builder
	var q byte
	flush := func() {
		if b.Len() > 0 {
			toks = append(toks, b.String())
			b.Reset()
		}
	}
	for i := 0; i < len(stage); i++ {
		c := stage[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			} else {
				b.WriteByte(c)
			}
		case c == '\'' || c == '"':
			q = c
		case c == ' ' || c == '\t' || c == '\n':
			flush()
		default:
			b.WriteByte(c)
		}
	}
	flush()
	return toks
}

// stripWrappers drops leading VAR=val assignments and wrapper commands so
// the returned argv begins at the real argv0. One level of busybox/env/etc
// is enough for the idioms we target (stacked wrappers are an open question
// deliberately left to LFA).
func stripWrappers(argv []string) []string {
	for len(argv) > 0 {
		t := argv[0]
		if strings.Contains(t, "=") && !strings.HasPrefix(t, "-") && !strings.Contains(t, "/") {
			argv = argv[1:] // VAR=val
			continue
		}
		if _, ok := pipeWrappers[base(t)]; ok {
			argv = argv[1:]
			// skip flags that belong to the wrapper (e.g. timeout 5, nice -n 10)
			for len(argv) > 0 && (strings.HasPrefix(argv[0], "-") || isBareNumber(argv[0])) {
				argv = argv[1:]
			}
			continue
		}
		break
	}
	return argv
}

func base(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func contains(argv []string, want string) bool {
	for _, a := range argv {
		if a == want {
			return true
		}
	}
	return false
}

func hasAnyFlag(argv []string, flags ...string) bool {
	for _, a := range argv {
		for _, f := range flags {
			if a == f {
				return true
			}
		}
	}
	return false
}

// hasOutputToFile reports a curl/fetch writing to a file (-o/-O/--output),
// which means it is NOT a downloader-to-stdout source.
func hasOutputToFile(argv []string) bool {
	for _, a := range argv {
		if a == "-o" || a == "-O" || a == "--output" || a == "--remote-name" ||
			strings.HasPrefix(a, "-o") && len(a) > 2 || strings.HasPrefix(a, "--output=") {
			return true
		}
	}
	return false
}

// wgetToStdout reports wget directed to stdout (-O-, -qO-, -O -, --output-document=-).
func wgetToStdout(argv []string) bool {
	for i, a := range argv {
		if a == "-O-" || a == "-qO-" || a == "--output-document=-" {
			return true
		}
		if (a == "-O" || a == "--output-document") && i+1 < len(argv) && argv[i+1] == "-" {
			return true
		}
		// combined short flags like -qO- already caught above; -O- caught above
	}
	return false
}

func isBareNumber(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
