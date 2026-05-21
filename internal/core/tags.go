package core

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ADR-0015 governs the host-tag contract. This file is the single
// source of truth for parsing, validation, and canonicalization.

// MaxTagKeyLen is the maximum length of a tag key in bytes.
// K8s label keys cap at 63; we mirror that.
const MaxTagKeyLen = 63

// MaxTagValueLen is the maximum length of a tag value in bytes.
// Slimmer than K8s (253) because tag values are operator-supplied
// peer-group labels, not opaque blobs.
const MaxTagValueLen = 63

// tagKeyRE matches a syntactically valid tag key.
//
// Grammar: lowercase letter followed by 0..62 of lowercase
// alphanumerics, underscore, or hyphen. Total length 1..63.
//
// Rationale: lowercase-only forbids ambient OS hostname casing
// from sneaking into peer-group keys. Underscore + hyphen are the
// only delimiters typical operators reach for; allowing dots would
// risk colliding with the DNS-label conventions ADR-0006 reserves
// for hostname_hash representations.
var tagKeyRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)

// tagValueRE matches a syntactically valid tag value.
//
// Grammar: empty, OR a single lowercase alphanumeric, OR a
// lowercase alphanumeric followed by 0..61 of lowercase
// alphanumeric / dot / underscore / hyphen, ending in a lowercase
// alphanumeric. Total length 0..63.
//
// Rationale: K8s label values without the colon (which has no
// meaning in our flat string serialization). Trailing punctuation
// is forbidden so `role=build,` cannot pass; that catches the
// common typo where a comma-separator-from-some-other-system
// leaks through the shell.
var tagValueRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9_.-]{0,61}[a-z0-9])?)?$`)

// reservedTagKeys are keys forbidden because the agent already
// emits them as top-level fields in HostMeta. Accepting them as
// tags would split the same logical attribute across two paths in
// the JSON record.
var reservedTagKeys = map[string]string{
	"hostname":      "use --include-hostname to emit host_meta.hostname",
	"hostname_hash": "host_meta.hostname_hash is always emitted; --tag rejected",
	"os_id":         "host_meta.os_id is auto-detected from /etc/os-release",
	"os_version":    "host_meta.os_version is auto-detected from /etc/os-release",
	"kernel":        "host_meta.kernel is auto-detected from uname",
	"arch":          "host_meta.arch is auto-detected from runtime",
	"boot_id":       "host_meta.boot_id is auto-detected from /proc/sys/kernel/random/boot_id",
	"host_id":       "host_id is derived from /etc/machine-id; --tag rejected",
}

// ErrTagFormat is returned for any malformed tag string. Callers
// can wrap or test for it; the message carries the specific
// failure detail.
var ErrTagFormat = errors.New("invalid tag format")

// ParseTag validates a single `key=value` tag string and returns
// the canonical wire form (`"key=value"`) on success.
//
// The function does NOT split into a struct because tags travel as
// strings inside `host_meta.tags []string`. Returning the canonical
// form (lower-cased and trimmed of nothing else; the regex already
// enforces lowercase) gives callers a single representation to
// store and compare.
func ParseTag(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("%w: empty tag", ErrTagFormat)
	}
	// Exactly one '=' separator.
	idx := strings.Index(raw, "=")
	if idx < 0 {
		return "", fmt.Errorf("%w: missing '=' in %q (expected key=value)", ErrTagFormat, raw)
	}
	if strings.IndexByte(raw[idx+1:], '=') >= 0 {
		return "", fmt.Errorf("%w: multiple '=' in %q (expected key=value)", ErrTagFormat, raw)
	}
	key := raw[:idx]
	value := raw[idx+1:]

	if err := ValidateTagKey(key); err != nil {
		return "", err
	}
	if err := ValidateTagValue(value); err != nil {
		return "", err
	}
	return key + "=" + value, nil
}

// ValidateTagKey returns nil iff key matches the tag-key grammar
// AND is not a reserved name.
func ValidateTagKey(key string) error {
	if key == "" {
		return fmt.Errorf("%w: empty key", ErrTagFormat)
	}
	if len(key) > MaxTagKeyLen {
		return fmt.Errorf("%w: key %q exceeds max length %d", ErrTagFormat, key, MaxTagKeyLen)
	}
	if !tagKeyRE.MatchString(key) {
		return fmt.Errorf("%w: key %q must match [a-z][a-z0-9_-]{0,62}", ErrTagFormat, key)
	}
	if reason, reserved := reservedTagKeys[key]; reserved {
		return fmt.Errorf("%w: key %q is reserved (%s)", ErrTagFormat, key, reason)
	}
	return nil
}

// ValidateTagValue returns nil iff value matches the tag-value
// grammar. The empty value is permitted (encodes presence-only
// boolean tags such as `has_cuda=`).
func ValidateTagValue(value string) error {
	if len(value) > MaxTagValueLen {
		return fmt.Errorf("%w: value %q exceeds max length %d", ErrTagFormat, value, MaxTagValueLen)
	}
	if !tagValueRE.MatchString(value) {
		return fmt.Errorf("%w: value %q must match [a-z0-9]([a-z0-9_.-]{0,61}[a-z0-9])? or be empty", ErrTagFormat, value)
	}
	return nil
}

// CanonicalizeTags returns a sorted, deduplicated copy of the
// input slice. Inputs are assumed to be pre-validated canonical
// `key=value` strings (i.e. the output of ParseTag); this function
// does not re-validate, so a caller that bypasses ParseTag is
// responsible for the contract.
//
// Sort order: byte-lexicographic on the full `key=value` string.
// This places `env=prod` before `role=build` and is stable across
// hosts. The canonical tag set used as the Q3 peer-group key is
// the comma-joined form of the slice this function returns.
func CanonicalizeTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}
	out := make([]string, 0, len(tags))
	seen := make(map[string]struct{}, len(tags))
	for _, t := range tags {
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// CanonicalTagKey returns the canonical, comma-joined tag-set
// string used as the Q3 peer-group key. CanonicalizeTags is
// applied first so input order does not matter.
//
// An empty tag slice returns the empty string -- the canonical
// key for the "untagged" peer-group.
func CanonicalTagKey(tags []string) string {
	canon := CanonicalizeTags(tags)
	if len(canon) == 0 {
		return ""
	}
	return strings.Join(canon, ",")
}
