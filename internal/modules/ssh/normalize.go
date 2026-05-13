// Package ssh authorized_keys parsing and normalization helpers.
//
// The format per sshd(8):
//
//	[options] keytype base64-blob [comment]
//
// where options is comma-separated, possibly with double-quoted values
// containing commas or whitespace; keytype is one of a fixed set of
// algorithm identifiers; blob is base64-encoded public-key material;
// comment is free-form rest-of-line.
//
// All parsing happens here; ssh.go composes records from the parsed
// shape. The public-key blob NEVER leaves this package as a string in
// any field other than its decoded sha256 (see ADR-0003).
package ssh

import (
	"encoding/base64"
	"sort"
	"strings"
)

// knownKeytypes is the closed set of authorized_keys algorithm
// identifiers recognized by OpenSSH and therefore by this module.
// Lines whose algorithm slot does not match are rejected as
// malformed.
var knownKeytypes = map[string]struct{}{
	"ssh-rsa":                            {},
	"ssh-dss":                            {},
	"ssh-ed25519":                        {},
	"ecdsa-sha2-nistp256":                {},
	"ecdsa-sha2-nistp384":                {},
	"ecdsa-sha2-nistp521":                {},
	"sk-ssh-ed25519@openssh.com":         {},
	"sk-ecdsa-sha2-nistp256@openssh.com": {},
}

// parsedAuthKey is the structured view of one non-blank,
// non-comment line from an authorized_keys file. The raw blob is
// captured for sha256 computation only; callers MUST NOT include
// the blob in any emitted Record (see ADR-0003).
type parsedAuthKey struct {
	rawOpts   string // options exactly as they appeared
	canonOpts string // options sorted alphabetically, comma-joined
	keytype   string // e.g. "ssh-ed25519"
	blob      string // base64 public-key material (do not emit)
	blobBytes []byte // base64-decoded bytes
	comment   string // free-form text after the blob
	command   string // value of command="..." option when present
}

// isLeadingComment reports whether s, after left-trim, begins with '#'.
func isLeadingComment(s string) bool {
	t := strings.TrimLeft(s, " \t")
	return strings.HasPrefix(t, "#")
}

// splitFirstToken returns the substring up to the first ASCII space
// or tab and the remainder after the separator. If no separator is
// present, token == s and rest == "".
func splitFirstToken(s string) (token, rest string) {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			return s[:i], s[i+1:]
		}
	}
	return s, ""
}

// findEndOfOptions returns the byte index of the first ASCII space
// or tab in s that is NOT inside a double-quoted segment. Returns -1
// if no such position exists (the entire line is one token with no
// keytype following).
func findEndOfOptions(s string) int {
	inQ := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inQ = !inQ
			continue
		}
		if (c == ' ' || c == '\t') && !inQ {
			return i
		}
	}
	return -1
}

// parseAuthKeyLine parses one source line. Returns (parsed, true) on
// a well-formed key line, (zero, false) on blanks, comment-only
// lines, malformed lines, or lines whose blob fails base64 decode.
// Malformed lines are silently dropped by callers in v0.1.0; an
// explicit envelope-with-errors record may be added later.
func parseAuthKeyLine(rawLine string) (parsedAuthKey, bool) {
	line := strings.TrimRight(rawLine, " \t\r")
	if line == "" {
		return parsedAuthKey{}, false
	}
	if isLeadingComment(line) {
		return parsedAuthKey{}, false
	}

	first, rest := splitFirstToken(line)
	if first == "" {
		return parsedAuthKey{}, false
	}

	// Case A: first token is a known keytype -> no options.
	if _, ok := knownKeytypes[first]; ok {
		return finishParse("", first, rest)
	}

	// Case B: first non-quote-whitespace boundary terminates the
	// options string. After that the keytype must follow.
	optsEnd := findEndOfOptions(line)
	if optsEnd <= 0 {
		return parsedAuthKey{}, false
	}
	opts := line[:optsEnd]
	rest = strings.TrimLeft(line[optsEnd:], " \t")
	kt, rest2 := splitFirstToken(rest)
	if _, ok := knownKeytypes[kt]; !ok {
		return parsedAuthKey{}, false
	}
	return finishParse(opts, kt, rest2)
}

// finishParse consumes "<blob> [comment...]" given an already-known
// options string and keytype, returns the parsed result.
func finishParse(rawOpts, keytype, rest string) (parsedAuthKey, bool) {
	rest = strings.TrimLeft(rest, " \t")
	if rest == "" {
		return parsedAuthKey{}, false
	}
	blob, after := splitFirstToken(rest)
	if blob == "" {
		return parsedAuthKey{}, false
	}
	blobBytes, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return parsedAuthKey{}, false
	}
	comment := strings.TrimSpace(after)
	pk := parsedAuthKey{
		rawOpts:   rawOpts,
		canonOpts: canonicalOptions(rawOpts),
		keytype:   keytype,
		blob:      blob,
		blobBytes: blobBytes,
		comment:   comment,
	}
	pk.command = extractForcedCommand(pk.canonOpts)
	return pk, true
}

// canonicalOptions sorts the comma-separated options string while
// respecting double-quoted segments (a comma inside "..." does NOT
// split). Each token is trimmed of leading/trailing whitespace.
// Result is the alphabetically-sorted, comma-joined canonical form
// used for content_norm_sha256.
func canonicalOptions(raw string) string {
	if raw == "" {
		return ""
	}
	tokens := splitOptionsComma(raw)
	sort.Strings(tokens)
	return strings.Join(tokens, ",")
}

// splitOptionsComma splits an options string on commas that are
// NOT inside double-quoted segments, trimming each token.
func splitOptionsComma(s string) []string {
	var tokens []string
	var buf strings.Builder
	inQ := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			buf.WriteByte(c)
			inQ = !inQ
			continue
		}
		if c == ',' && !inQ {
			tokens = append(tokens, strings.TrimSpace(buf.String()))
			buf.Reset()
			continue
		}
		buf.WriteByte(c)
	}
	if buf.Len() > 0 {
		tokens = append(tokens, strings.TrimSpace(buf.String()))
	}
	return tokens
}

// extractForcedCommand scans the (already-canonicalized) options
// string for a command="..." option and returns the dequoted value.
// Returns "" when no command= option is present. Matching is
// case-insensitive on the option key, per SSH's lenient parser.
func extractForcedCommand(canonOpts string) string {
	if canonOpts == "" {
		return ""
	}
	for _, opt := range splitOptionsComma(canonOpts) {
		const key = "command="
		if len(opt) <= len(key) {
			continue
		}
		if !strings.EqualFold(opt[:len(key)], key) {
			continue
		}
		val := opt[len(key):]
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}
		return val
	}
	return ""
}

// reconstructLine builds the privacy-preserving line representation
// used as the input to content_sha256 and content_norm_sha256
// hashing, and to content_snippet. The blob is substituted by its
// 12-char sha256 prefix wrapped in <sha256:...> so the raw blob
// never appears.
//
// Components are joined by single spaces. Empty components are
// skipped (no leading/trailing spaces, no double spaces).
func reconstructLine(opts, keytype, prefix12, comment string) string {
	parts := make([]string, 0, 4)
	if opts != "" {
		parts = append(parts, opts)
	}
	parts = append(parts, keytype)
	parts = append(parts, "<sha256:"+prefix12+">")
	if comment != "" {
		parts = append(parts, comment)
	}
	return strings.Join(parts, " ")
}
