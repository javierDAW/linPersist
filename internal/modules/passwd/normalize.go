// Package passwd normalization and parsing helpers for the four
// passwd-family files: /etc/passwd, /etc/shadow, /etc/group,
// /etc/gshadow.
//
// Canonical-form rules (ADR-0002 per-line plus ADR-0005 for hash
// handling):
//
//   - passwd.user    canonical == raw line (no transformation).
//     Filter: uid=0 OR shell !∈ {nologin set, false}.
//   - passwd.shadow  hash field replaced by status enum
//     (set/locked/disabled/empty/unknown). content_sha256
//     AND content_norm_sha256 both over the canonical
//     so the raw hash is never an input to any hash.
//   - passwd.group   members sorted alphabetically, comma-joined.
//     content_sha256 over raw line, content_norm_sha256
//     over canonical.
//   - passwd.gshadow same hash policy as shadow; admins and members
//     sorted alphabetically.
package passwd

import (
	"sort"
	"strings"
)

// shadowStatus reduces a /etc/shadow or /etc/gshadow password field
// to an enum value. The raw field never leaves this function.
// See ADR-0005.
func shadowStatus(field string) string {
	if field == "" {
		return "empty"
	}
	switch field[0] {
	case '$':
		return "set"
	case '!':
		return "locked"
	case '*':
		return "disabled"
	default:
		return "unknown"
	}
}

// sortCSV splits a comma-separated list, trims each element, drops
// empties, sorts alphabetically, and rejoins. Used for group members
// and gshadow admins/members canonicalization.
func sortCSV(s string) string {
	if s == "" {
		return ""
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// nologinShells is the set of shells that mark an "uninteresting"
// (non-login) user. Users with these shells are filtered out from
// passwd.user emission UNLESS they have uid=0.
var nologinShells = map[string]struct{}{
	"/usr/sbin/nologin": {},
	"/sbin/nologin":     {},
	"/bin/false":        {},
	"/usr/bin/false":    {},
}

// passwdUser is the parsed view of a /etc/passwd line.
type passwdUser struct {
	raw   string // line right-trimmed; canonical for passwd.user IS the raw line
	user  string
	uid   string
	gid   string
	gecos string
	home  string
	shell string
}

func parsePasswdLine(rawLine string) (passwdUser, bool) {
	line := strings.TrimRight(rawLine, " \t\r")
	if line == "" || strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
		return passwdUser{}, false
	}
	parts := strings.Split(line, ":")
	if len(parts) < 7 {
		return passwdUser{}, false
	}
	return passwdUser{
		raw:   line,
		user:  parts[0],
		uid:   parts[2],
		gid:   parts[3],
		gecos: parts[4],
		home:  parts[5],
		shell: parts[6],
	}, true
}

// shouldEmitUser implements the passwd filter: uid=0 OR shell not in
// the nologin set. Decision documented in the matrix.yaml notes.
func shouldEmitUser(pu passwdUser) bool {
	if pu.uid == "0" {
		return true
	}
	_, isNologin := nologinShells[pu.shell]
	return !isNologin
}

// shadowEntry is the parsed view of a /etc/shadow line. The raw hash
// is observed only to compute the status; it is NOT stored on the
// struct (per ADR-0005).
type shadowEntry struct {
	canon  string // canonical form -- hash replaced by status enum
	user   string
	status string
}

func parseShadowLine(rawLine string) (shadowEntry, bool) {
	line := strings.TrimRight(rawLine, " \t\r")
	if line == "" || strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
		return shadowEntry{}, false
	}
	parts := strings.SplitN(line, ":", 9)
	if len(parts) < 9 {
		return shadowEntry{}, false
	}
	status := shadowStatus(parts[1])
	parts[1] = status // replace hash with status BEFORE any joining
	return shadowEntry{
		canon:  strings.Join(parts, ":"),
		user:   parts[0],
		status: status,
	}, true
}

// groupEntry is the parsed view of a /etc/group line.
type groupEntry struct {
	raw     string // raw line, right-trimmed (input to content_sha256)
	canon   string // canonical: members sorted alphabetically
	name    string
	members string // sorted, comma-joined
}

func parseGroupLine(rawLine string) (groupEntry, bool) {
	line := strings.TrimRight(rawLine, " \t\r")
	if line == "" || strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
		return groupEntry{}, false
	}
	parts := strings.SplitN(line, ":", 4)
	if len(parts) < 4 {
		return groupEntry{}, false
	}
	members := sortCSV(parts[3])
	return groupEntry{
		raw:     line,
		canon:   parts[0] + ":" + parts[1] + ":" + parts[2] + ":" + members,
		name:    parts[0],
		members: members,
	}, true
}

// gshadowEntry is the parsed view of a /etc/gshadow line. As with
// shadowEntry, the raw hash is observed only to derive the status.
type gshadowEntry struct {
	canon   string
	name    string
	status  string
	admins  string
	members string
}

func parseGshadowLine(rawLine string) (gshadowEntry, bool) {
	line := strings.TrimRight(rawLine, " \t\r")
	if line == "" || strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
		return gshadowEntry{}, false
	}
	parts := strings.SplitN(line, ":", 4)
	if len(parts) < 4 {
		return gshadowEntry{}, false
	}
	status := shadowStatus(parts[1])
	admins := sortCSV(parts[2])
	members := sortCSV(parts[3])
	return gshadowEntry{
		canon:   parts[0] + ":" + status + ":" + admins + ":" + members,
		name:    parts[0],
		status:  status,
		admins:  admins,
		members: members,
	}, true
}
