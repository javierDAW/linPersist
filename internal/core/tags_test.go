package core

import (
	"errors"
	"strings"
	"testing"
)

// TestParseTag_ValidCases exercises the happy path: every input
// here must parse without error and return the input unchanged
// (canonical form == input, the grammar is lowercase-only).
func TestParseTag_ValidCases(t *testing.T) {
	cases := []string{
		"role=build",
		"env=prod",
		"tier=edge-1",
		"region=eu-west-1",
		"k=v",
		"has_cuda=",         // empty value: presence-only
		"a=0",               // single-char alphanumeric
		"role-secondary=ci", // hyphen in key
		"build_id=ci-2026",  // dot-less but with hyphen
		"team=dfir.lab",     // dot in value
	}
	for _, c := range cases {
		got, err := ParseTag(c)
		if err != nil {
			t.Errorf("ParseTag(%q): unexpected error: %v", c, err)
			continue
		}
		if got != c {
			t.Errorf("ParseTag(%q): canonical = %q, want %q", c, got, c)
		}
	}
}

// TestParseTag_RejectsMalformed gathers every grammatically
// invalid input shape. Each must return ErrTagFormat with a
// message specific enough that the operator sees WHY it failed.
func TestParseTag_RejectsMalformed(t *testing.T) {
	cases := []struct {
		raw      string
		mustHave string
	}{
		{"", "empty tag"},
		{"role", "missing '='"},
		{"role=build=ci", "multiple '='"},
		{"=value", "empty key"},
		{"Role=build", "must match"},   // uppercase forbidden
		{"role=Build", "must match"},   // uppercase forbidden in value
		{"role=build server", "value"}, // space in value
		{"role =build", "key"},         // space in key
		{"role=build,", "value"},       // trailing comma forbidden
		{"role=-build", "value"},       // leading hyphen in value
		{"role=build-", "value"},       // trailing hyphen in value
		{"-role=build", "key"},         // leading hyphen in key
		{"1role=build", "key"},         // leading digit in key
		// Length boundary: 64-char key (over the 63 limit).
		{strings.Repeat("a", 64) + "=v", "max length"},
		// Length boundary: 64-char value.
		{"k=" + strings.Repeat("a", 64), "max length"},
	}
	for _, tc := range cases {
		_, err := ParseTag(tc.raw)
		if err == nil {
			t.Errorf("ParseTag(%q): want error, got nil", tc.raw)
			continue
		}
		if !errors.Is(err, ErrTagFormat) {
			t.Errorf("ParseTag(%q): err = %v, want wrapping ErrTagFormat", tc.raw, err)
		}
		if !strings.Contains(err.Error(), tc.mustHave) {
			t.Errorf("ParseTag(%q): message %q must contain %q", tc.raw, err.Error(), tc.mustHave)
		}
	}
}

// TestParseTag_RejectsReservedKeys verifies every reserved key
// trips the rejection path AND carries a hint pointing at the
// proper HostMeta field. Operators should not have to read source
// to understand the rejection.
func TestParseTag_RejectsReservedKeys(t *testing.T) {
	for _, key := range []string{
		"hostname", "hostname_hash", "os_id", "os_version",
		"kernel", "arch", "boot_id", "host_id",
	} {
		_, err := ParseTag(key + "=anything")
		if err == nil {
			t.Errorf("reserved key %q: want error, got nil", key)
			continue
		}
		if !errors.Is(err, ErrTagFormat) {
			t.Errorf("reserved key %q: err = %v, want wrapping ErrTagFormat", key, err)
		}
		if !strings.Contains(err.Error(), "reserved") {
			t.Errorf("reserved key %q: message %q must mention 'reserved'", key, err.Error())
		}
	}
}

// TestCanonicalizeTags_Determinism is the LFA grouping guarantee
// in the small: regardless of input order, the canonical form is
// byte-identical. The Q3 peer-group key derives from this slice.
func TestCanonicalizeTags_Determinism(t *testing.T) {
	a := []string{"role=build", "env=prod", "tier=ci"}
	b := []string{"tier=ci", "role=build", "env=prod"}
	c := []string{"env=prod", "tier=ci", "role=build"}
	ca, cb, cc := CanonicalizeTags(a), CanonicalizeTags(b), CanonicalizeTags(c)
	if join(ca) != join(cb) || join(cb) != join(cc) {
		t.Fatalf("input order leaks through canonicalization:\n  a=%v -> %v\n  b=%v -> %v\n  c=%v -> %v",
			a, ca, b, cb, c, cc)
	}
}

// TestCanonicalizeTags_DedupExactDuplicates exercises the dedup
// guarantee: the same literal `key=value` pair twice collapses to
// one entry. Distinct values for the same key (multi-value) do
// NOT collapse.
func TestCanonicalizeTags_DedupExactDuplicates(t *testing.T) {
	in := []string{"role=build", "role=build", "role=ci"}
	got := CanonicalizeTags(in)
	want := []string{"role=build", "role=ci"}
	if join(got) != join(want) {
		t.Fatalf("dedup: got %v, want %v", got, want)
	}
}

// TestCanonicalizeTags_NilOnEmpty defends against the empty case;
// downstream consumers rely on len-zero for the untagged
// peer-group branch.
func TestCanonicalizeTags_NilOnEmpty(t *testing.T) {
	if got := CanonicalizeTags(nil); got != nil {
		t.Errorf("nil input: got %v, want nil", got)
	}
	if got := CanonicalizeTags([]string{}); got != nil {
		t.Errorf("empty input: got %v, want nil", got)
	}
}

// TestCanonicalTagKey_UntaggedIsEmpty pins the "untagged
// peer-group key is the empty string" invariant. Q3 keys on it.
func TestCanonicalTagKey_UntaggedIsEmpty(t *testing.T) {
	if got := CanonicalTagKey(nil); got != "" {
		t.Errorf("nil tags: peer-group key = %q, want empty", got)
	}
	if got := CanonicalTagKey([]string{}); got != "" {
		t.Errorf("empty tags: peer-group key = %q, want empty", got)
	}
}

// TestCanonicalTagKey_StableJoin verifies the comma-joined form is
// what Q3 actually receives. A change in the join character would
// silently break peer-group identity across Go/SQL parity.
func TestCanonicalTagKey_StableJoin(t *testing.T) {
	in := []string{"role=build", "env=prod"}
	got := CanonicalTagKey(in)
	want := "env=prod,role=build"
	if got != want {
		t.Fatalf("CanonicalTagKey: got %q, want %q", got, want)
	}
}

func join(s []string) string { return strings.Join(s, "|") }
