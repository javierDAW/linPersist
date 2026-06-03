package confexec

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/jarmidaw/linpersist/internal/core"
)

// cmdArg0 returns the first token of a command string IF it is a clean
// absolute path, else "". A bare/relative command (systemctl, killall,
// procmail) is a $PATH LOLBin -- provenance cannot classify it and the
// architects agreed those stay LFA-only -- so only an absolute argv0
// (/opt/payload) becomes an exec edge. Surrounding quotes are stripped;
// a token with shell metacharacters is rejected (dynamic path).
func cmdArg0(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	cmd = strings.Trim(cmd, "\"'")
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return ""
	}
	tok := strings.Trim(fields[0], "\"'")
	if !strings.HasPrefix(tok, "/") || len(tok) < 2 {
		return ""
	}
	if strings.ContainsAny(tok, "$`*?<>|&;") {
		return ""
	}
	return tok
}

// scanLines yields each line with leading whitespace trimmed, skipping
// blank lines and # comments.
func eachLine(raw []byte, fn func(line string)) {
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fn(line)
	}
}

// --- mail aliases / .forward ---

// parseAliases lifts the command of a pipe alias `name: |cmd` (or, in a
// ~/.forward file, a bare `|cmd` line). Mailbox/user/include targets are
// inert and yield no edge.
func parseAliases(raw []byte, logical string, _ *Module) []Edge {
	isForward := strings.HasSuffix(logical, ".forward")
	var out []Edge
	eachLine(raw, func(line string) {
		var targets []string
		if isForward {
			targets = []string{line}
		} else {
			i := strings.IndexByte(line, ':')
			if i <= 0 {
				return
			}
			targets = strings.Split(line[i+1:], ",")
		}
		for _, t := range targets {
			t = strings.TrimSpace(t)
			t = strings.Trim(t, "\"'")
			t = strings.TrimSpace(t)
			if !strings.HasPrefix(t, "|") {
				continue
			}
			if arg0 := cmdArg0(strings.TrimPrefix(t, "|")); arg0 != "" {
				out = append(out, Edge{Target: arg0, Snippet: line})
			}
		}
	})
	return out
}

// --- incron ---

// parseIncron parses incrontab lines `<path> <mask> <command...>` and lifts
// the command's argv0.
func parseIncron(raw []byte, _ string, _ *Module) []Edge {
	var out []Edge
	eachLine(raw, func(line string) {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return
		}
		cmd := strings.Join(fields[2:], " ")
		if arg0 := cmdArg0(cmd); arg0 != "" {
			out = append(out, Edge{Target: arg0, Snippet: line})
		}
	})
	return out
}

// --- logrotate ---

var logrotateScriptKeys = map[string]struct{}{
	"prerotate": {}, "postrotate": {}, "firstaction": {},
	"lastaction": {}, "preremove": {},
}

// parseLogrotate collects each (pre|post)rotate/firstaction/... endscript
// shell block and runs it through the shared exec_target extractor, lifting
// the first absolute command. Embedded `systemctl reload` / `killall -HUP`
// (bare commands) yield nothing; a parked /opt|/tmp hook is lifted.
func parseLogrotate(raw []byte, _ string, _ *Module) []Edge {
	var out []Edge
	var inScript bool
	var body []string
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	flush := func() {
		if len(body) == 0 {
			return
		}
		if t := core.ExtractExecTarget([]byte(strings.Join(body, "\n"))); t != "" {
			out = append(out, Edge{Target: t, Snippet: body[0]})
		}
		body = nil
	}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		first := line
		if sp := strings.IndexAny(line, " \t"); sp >= 0 {
			first = line[:sp]
		}
		if _, ok := logrotateScriptKeys[strings.ToLower(first)]; ok {
			inScript = true
			continue
		}
		if strings.EqualFold(first, "endscript") {
			flush()
			inScript = false
			continue
		}
		if inScript {
			body = append(body, line)
		}
	}
	flush()
	return out
}

// --- package-manager hooks ---

// parsePkgmgrHook handles two grammars by locus: apt.conf `*-Invoke {"cmd";}`
// quoted-command lists, and dnf/yum `*.action` files (`match:state:command`).
func parsePkgmgrHook(raw []byte, logical string, _ *Module) []Edge {
	if strings.HasSuffix(logical, ".action") {
		return parseDnfAction(raw)
	}
	return parseAptConf(raw)
}

func parseAptConf(raw []byte) []Edge {
	var out []Edge
	var inInvoke bool
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "-Invoke") {
			inInvoke = true
		}
		if inInvoke {
			for _, q := range quotedStrings(line) {
				if arg0 := cmdArg0(q); arg0 != "" {
					out = append(out, Edge{Target: arg0, Snippet: strings.TrimSpace(line)})
				}
			}
		}
		if strings.Contains(line, "}") {
			inInvoke = false
		}
	}
	return out
}

func parseDnfAction(raw []byte) []Edge {
	var out []Edge
	eachLine(raw, func(line string) {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			return
		}
		if arg0 := cmdArg0(parts[2]); arg0 != "" {
			out = append(out, Edge{Target: arg0, Snippet: line})
		}
	})
	return out
}

// quotedStrings returns the contents of every "..." run on a line.
func quotedStrings(line string) []string {
	var out []string
	for {
		i := strings.IndexByte(line, '"')
		if i < 0 {
			break
		}
		rest := line[i+1:]
		j := strings.IndexByte(rest, '"')
		if j < 0 {
			break
		}
		out = append(out, rest[:j])
		line = rest[j+1:]
	}
	return out
}

// --- sudo.conf plugins ---

// parseSudoConf lifts the .so path of each `Plugin <symbol> <path> [args]`
// line, resolving a relative name against the sudo plugin dir so the stock
// sudoers.so resolves owned.
func parseSudoConf(raw []byte, _ string, m *Module) []Edge {
	var out []Edge
	eachLine(raw, func(line string) {
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.EqualFold(fields[0], "Plugin") {
			return
		}
		p := fields[2]
		if !strings.HasPrefix(p, "/") {
			// Resolve against the platform sudo plugin dir(s).
			for _, dir := range []string{"/usr/libexec/sudo", "/usr/lib/sudo"} {
				cand := filepath.Join(dir, p)
				if _, err := os.Lstat(m.resolve(cand)); err == nil {
					p = cand
					break
				}
			}
			if !strings.HasPrefix(p, "/") {
				p = filepath.Join("/usr/libexec/sudo", p)
			}
		}
		out = append(out, Edge{Target: p, Snippet: line})
	})
	return out
}

// --- NSS ---

// nssVendorTokens is the curated allowlist of well-known glibc NSS service
// names. A `database: ... <token>` whose token is OUTSIDE this set names a
// libnss_<token>.so.2 glibc will dlopen into every process doing that kind
// of lookup -- the Symbiote-class hijack. An allowlist (not a path denylist)
// survives novel basenames. AD/SSSD/LDAP shops ship PACKAGED libnss_sss /
// libnss_ldap / libnss_winbind, so those tokens are allowlisted and their
// resolved .so would be owned anyway.
var nssVendorTokens = map[string]struct{}{
	"files": {}, "compat": {}, "dns": {}, "db": {}, "nis": {}, "nisplus": {},
	"systemd": {}, "sss": {}, "ldap": {}, "winbind": {}, "mymachines": {},
	"myhostname": {}, "resolve": {}, "mdns": {}, "mdns4": {}, "mdns6": {},
	"mdns_minimal": {}, "mdns4_minimal": {}, "mdns6_minimal": {},
	"wins": {}, "gw_name": {}, "docker": {}, "cache": {}, "role": {},
}

// parseNsswitch resolves each non-vendor service token to its
// libnss_<token>.so.2 on the standard library path and emits it as the
// exec edge. Provenance then classifies it: a packaged module stays silent,
// an unowned planted one trips the detection.
func parseNsswitch(raw []byte, _ string, m *Module) []Edge {
	var out []Edge
	seen := map[string]struct{}{}
	eachLine(raw, func(line string) {
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			return
		}
		for _, tok := range strings.Fields(line[i+1:]) {
			// Strip action syntax like [NOTFOUND=return].
			if strings.HasPrefix(tok, "[") {
				continue
			}
			low := strings.ToLower(tok)
			if _, ok := nssVendorTokens[low]; ok {
				continue
			}
			if _, dup := seen[low]; dup {
				continue
			}
			seen[low] = struct{}{}
			soname := "libnss_" + tok + ".so.2"
			if resolved := m.findLib(soname); resolved != "" {
				out = append(out, Edge{Target: resolved, Snippet: line})
			}
		}
	})
	return out
}

// --- systemd environment.d ---

// envHookKeys are the environment.d assignments whose value is a single
// path that turns into a per-session code-exec/dlopen edge. LD_PRELOAD/
// LD_AUDIT name a .so glibc loads into every session process; BASH_ENV/ENV
// name a script the shell sources; PYTHONSTARTUP names a file CPython
// sources in every interactive interpreter. LD_LIBRARY_PATH / PERL5LIB /
// RUBYLIB are search-dir LISTS (the ld.so.conf-shadow shape, not a direct
// target) and are excluded; PERL5OPT=-M / RUBYOPT=-r carry module NAMES
// not paths (inline-code boundary, LFA). NODE_OPTIONS is handled specially
// below (it carries `--require <path>` flags, not a bare path).
var envHookKeys = map[string]struct{}{
	"LD_PRELOAD": {}, "LD_AUDIT": {}, "BASH_ENV": {}, "ENV": {}, "PYTHONSTARTUP": {},
}

// nodeRequireFlags are the NODE_OPTIONS flags that name a module Node
// loads before the entrypoint — `--require <path>` / `--import <path>`
// (and their `=`-joined forms). The argument, when an absolute path, is
// the exec edge.
var nodeRequireFlags = []string{"--require", "--import"}

// nodeRequirePath returns the first absolute path argument of a
// `--require`/`--import` flag inside a NODE_OPTIONS value (space-separated
// or `=`-joined), or "" if none.
func nodeRequirePath(val string) string {
	fields := strings.Fields(val)
	for i, f := range fields {
		for _, flag := range nodeRequireFlags {
			if f == flag && i+1 < len(fields) {
				if p := cmdArg0(fields[i+1]); p != "" {
					return p
				}
			}
			if strings.HasPrefix(f, flag+"=") {
				if p := cmdArg0(strings.TrimPrefix(f, flag+"=")); p != "" {
					return p
				}
			}
		}
	}
	return ""
}

// parsePhpIni lifts the script named by php.ini auto_prepend_file /
// auto_append_file -- a PHP file the engine runs before/after every
// request (web + CLI). extension/zend_extension .so loads are
// search-path-based and left to LFA.
func parsePhpIni(raw []byte, _ string, _ *Module) []Edge {
	var out []Edge
	eachLine(raw, func(line string) {
		if strings.HasPrefix(line, ";") { // php.ini comment marker
			return
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			return
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		if key != "auto_prepend_file" && key != "auto_append_file" {
			return
		}
		val := strings.Trim(strings.TrimSpace(line[eq+1:]), "\"'")
		if arg0 := cmdArg0(val); arg0 != "" {
			out = append(out, Edge{Target: arg0, Snippet: line})
		}
	})
	return out
}

// parseEnvironmentD parses systemd environment.d KEY=VALUE files and lifts
// the absolute path of a code-exec env assignment. environment.d is read by
// systemd's environment generators for every user session -- a third
// env-delivery surface beyond /etc/environment (profile) and ld.so.preload
// (ldso).
func parseEnvironmentD(raw []byte, _ string, _ *Module) []Edge {
	var out []Edge
	eachLine(raw, func(line string) {
		line = strings.TrimPrefix(line, "export ")
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			return
		}
		key := strings.ToUpper(strings.TrimSpace(line[:eq]))
		val := strings.Trim(strings.TrimSpace(line[eq+1:]), "\"'")
		if key == "NODE_OPTIONS" {
			if p := nodeRequirePath(val); p != "" {
				out = append(out, Edge{Target: p, Snippet: line})
			}
			return
		}
		if _, ok := envHookKeys[key]; !ok {
			return
		}
		// LD_PRELOAD may list several .so separated by space/colon; take
		// the first absolute token.
		toks := strings.FieldsFunc(val, func(r rune) bool { return r == ' ' || r == ':' })
		if len(toks) == 0 {
			return
		}
		if arg0 := cmdArg0(toks[0]); arg0 != "" {
			out = append(out, Edge{Target: arg0, Snippet: line})
		}
	})
	return out
}

// --- shell-body sites (X11 session scripts, dpkg maintainer scripts) ---

// parseShellBody runs a shell script body through the shared exec_target
// extractor, lifting the first absolute sourced/exec'd command. Shared by
// the xsession.d (graphical-login scripts) and maintscript.dpkg (dpkg
// maintainer scripts) sites: in both, a clean script execs only packaged
// tools (owned edges -> silent) and a planted payload under /tmp,/opt
// surfaces as the lifted ExecTarget. The script file's OWN path is never
// provenance-checked (only the lifted payload edge is), which is exactly
// what the maintainer-script case needs -- the script is package metadata
// in no .list, so routing its own path through LookupPath would flood
// non_package_path on every script.
func parseShellBody(raw []byte, _ string, _ *Module) []Edge {
	if t := core.ExtractExecTarget(raw); t != "" {
		return []Edge{{Target: t, Snippet: firstCodeLine(raw)}}
	}
	return nil
}

// maintExecPrefixes are the line prefixes that unambiguously run/source a
// named file in a maintainer script. The bare-absolute-lead heuristic that
// ExtractExecTarget uses is too loose for these complex shell bodies (it
// mis-lifts case patterns like `/dev/*)`, update-alternatives path args,
// and conffile references as exec targets, flooding non_package_path), so
// parseMaintscript uses ONLY these explicit exec forms plus a bare lead
// restricted to suspicious dirs.
var maintExecPrefixes = []string{
	". ", "source ", "exec ", "sh ", "bash ", "dash ", "ksh ", "zsh ",
	"/bin/sh ", "/bin/bash ", "/bin/dash ", "/usr/bin/sh ", "/usr/bin/bash ",
}

// parseMaintscript extracts exec edges from a dpkg maintainer-script body,
// lifting ONLY a sourced/exec'd/interpreter-run or bare-lead absolute path
// that lives under a tmp-class or /opt directory — the unambiguous
// dropped-payload shape (`. /tmp/.x`, `exec /opt/.evil`, `/tmp/.x &`).
// A maintainer script legitimately sources/execs MANY absolute paths under
// /usr/share, /etc, /var (debconf confmodule, apache helpers, conffiles,
// optional-dependency files that are absent->orphan, case patterns the
// generic extractor mis-lifts); none of those are a tell, so restricting
// the whole grammar to tmp/opt makes it zero-FP-by-construction (verified
// on a real Debian host: 0 records) while still catching the textbook
// install-time payload. A payload sourced from some other unowned dir is
// left to LFA on the script-body hash (a tampered script is a fleet
// singleton).
func parseMaintscript(raw []byte, _ string, _ *Module) []Edge {
	var out []Edge
	eachLine(raw, func(line string) {
		cand := ""
		for _, p := range maintExecPrefixes {
			if strings.HasPrefix(line, p) {
				cand = cmdArg0(strings.TrimSpace(line[len(p):]))
				break
			}
		}
		if cand == "" {
			cand = cmdArg0(line) // bare-absolute-lead
		}
		if cand != "" && underSuspiciousDir(cand) {
			out = append(out, Edge{Target: cand, Snippet: line})
		}
	})
	return out
}

// underSuspiciousDir reports whether a maintainer-script exec edge is a
// dropped-payload tell. A tmp-class path (/tmp,/var/tmp,/dev/shm,/run/shm)
// always qualifies. /opt is split from tmp: a PRESENT vendor SDK under /opt
// (e.g. `. /opt/vendorsdk/postinst-helper.sh`) is benign and common on
// hosts with commercial agents, so it would flood a non_package verdict on
// every such package (duel-final HIGH). So /opt qualifies ONLY when the
// path carries a HIDDEN segment (a `/.`-prefixed component) — the implant-
// hiding shape (/opt/.x/agent) that a vendor SDK never uses. A non-hidden
// /opt payload is left to LFA on the script-body singleton.
func underSuspiciousDir(p string) bool {
	for _, d := range core.TmpDirs {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return strings.HasPrefix(p, "/opt/") && strings.Contains(p, "/.")
}

func firstCodeLine(raw []byte) string {
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			return line
		}
	}
	return ""
}

// --- shared lib resolution ---

// standardLibDirs is the memoized set of standard library directories
// (base + multiarch subdirs) used to resolve an NSS module to its .so.
func (m *Module) standardLibDirs() []string {
	if m.stdLibDirsSet {
		return m.stdLibDirs
	}
	base := []string{"/lib", "/usr/lib", "/lib64", "/usr/lib64"}
	out := make([]string, 0, len(base)*2)
	for _, d := range base {
		out = append(out, d)
		ents, err := os.ReadDir(m.resolve(d))
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.IsDir() {
				out = append(out, filepath.Join(d, e.Name()))
			}
		}
	}
	m.stdLibDirs = out
	m.stdLibDirsSet = true
	return out
}

// findLib returns the host-absolute logical path of soname under a standard
// library directory, or "" if absent.
func (m *Module) findLib(soname string) string {
	for _, d := range m.standardLibDirs() {
		cand := filepath.Join(d, soname)
		if fi, err := os.Lstat(m.resolve(cand)); err == nil && !fi.IsDir() {
			return cand
		}
	}
	return ""
}
