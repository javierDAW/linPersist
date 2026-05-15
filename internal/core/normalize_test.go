package core

import (
	"bytes"
	"testing"
)

// --- StripLineComments -------------------------------------------------

func TestStripLineComments_HashPrefix(t *testing.T) {
	in := []byte("# header\n" +
		"MAILTO=root\n" +
		"\n" +
		"# trailing comment line\n" +
		"0 3 * * * /opt/job.sh\n")
	got := StripLineComments(in, "#")
	want := []byte("MAILTO=root\n0 3 * * * /opt/job.sh\n")
	if !bytes.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestStripLineComments_SemicolonPrefix(t *testing.T) {
	in := []byte("; ini-style comment\n" +
		"key=value ; inline gone\n" +
		"plain=data\n")
	got := StripLineComments(in, ";")
	want := []byte("key=value\nplain=data\n")
	if !bytes.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestStripLineComments_InlineCommentStripped(t *testing.T) {
	// The prefix is matched anywhere in the line, not just at column 0.
	// Modules that need column-0-only semantics (e.g. crontab, which
	// does NOT honor inline #) must filter upstream of this helper.
	in := []byte("value1 # comment after value\n" +
		"value2\n" +
		"value3#nospace\n")
	got := StripLineComments(in, "#")
	want := []byte("value1\nvalue2\nvalue3\n")
	if !bytes.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestStripLineComments_TrimsTrailingWhitespace(t *testing.T) {
	in := []byte("data   \t  \n" +
		"more\t\t\n")
	got := StripLineComments(in, "#")
	want := []byte("data\nmore\n")
	if !bytes.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestStripLineComments_StripsCR(t *testing.T) {
	// CRLF line endings (sometimes seen on configs edited from Windows).
	// Trailing CR must be stripped so the digest matches LF-equivalent
	// content.
	crlf := []byte("alpha\r\nbeta\r\n")
	lf := []byte("alpha\nbeta\n")
	if !bytes.Equal(StripLineComments(crlf, "#"), StripLineComments(lf, "#")) {
		t.Errorf("CRLF and LF inputs produced different normalized output")
	}
}

func TestStripLineComments_DropsBlankLines(t *testing.T) {
	in := []byte("\n\n  \nalpha\n\nbeta\n\n\n")
	got := StripLineComments(in, "#")
	want := []byte("alpha\nbeta\n")
	if !bytes.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestStripLineComments_SingleTrailingNewline(t *testing.T) {
	// Whether the input had a trailing newline or not, the output must
	// end with exactly one '\n'. This is what makes the helper
	// composable with sort and concatenation.
	cases := [][]byte{
		[]byte("one\n"),
		[]byte("one"),
		[]byte("one\n\n"),
		[]byte("one\n\n\n"),
	}
	for _, in := range cases {
		got := StripLineComments(in, "#")
		if len(got) == 0 || got[len(got)-1] != '\n' {
			t.Errorf("output does not end with newline: %q", got)
		}
		// And exactly one trailing newline.
		if len(got) >= 2 && got[len(got)-2] == '\n' {
			t.Errorf("output ends with multiple newlines: %q", got)
		}
	}
}

func TestStripLineComments_Idempotent(t *testing.T) {
	inputs := [][]byte{
		[]byte(""),
		[]byte("# just comments\n# really\n"),
		[]byte("MAILTO=root\n# inline\n0 3 * * * /opt/job.sh # tail\n"),
		[]byte("alpha\r\nbeta   \r\n# gone\r\n"),
	}
	for _, in := range inputs {
		once := StripLineComments(in, "#")
		twice := StripLineComments(once, "#")
		if !bytes.Equal(once, twice) {
			t.Errorf("not idempotent for %q\n  once:  %q\n  twice: %q",
				in, once, twice)
		}
	}
}

func TestStripLineComments_Empty(t *testing.T) {
	if got := StripLineComments(nil, "#"); len(got) != 0 {
		t.Errorf("nil input -> %q; want empty", got)
	}
	if got := StripLineComments([]byte{}, "#"); len(got) != 0 {
		t.Errorf("empty input -> %q; want empty", got)
	}
}

func TestStripLineComments_AllCommentsYieldsEmpty(t *testing.T) {
	in := []byte("# only\n# comments\n# here\n")
	got := StripLineComments(in, "#")
	if len(got) != 0 {
		t.Errorf("all-comment input -> %q; want empty", got)
	}
}

// --- CollapseWhitespace ------------------------------------------------

func TestCollapseWhitespace_BasicSpaces(t *testing.T) {
	in := []byte("alpha     beta")
	want := []byte("alpha beta")
	if got := CollapseWhitespace(in); !bytes.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestCollapseWhitespace_TabsToSpace(t *testing.T) {
	in := []byte("alpha\tbeta")
	want := []byte("alpha beta")
	if got := CollapseWhitespace(in); !bytes.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestCollapseWhitespace_MixedTabsAndSpaces(t *testing.T) {
	// Any contiguous run of spaces and/or tabs collapses to ONE space.
	in := []byte("a \t  \t b   \t\tc")
	want := []byte("a b c")
	if got := CollapseWhitespace(in); !bytes.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestCollapseWhitespace_PreservesNewlines(t *testing.T) {
	in := []byte("a\nb\nc\n")
	want := []byte("a\nb\nc\n")
	if got := CollapseWhitespace(in); !bytes.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestCollapseWhitespace_NewlineBoundary(t *testing.T) {
	// Whitespace adjacent to a newline does not "leak" through it: the
	// space run terminates at the newline.
	in := []byte("alpha \nbeta")
	want := []byte("alpha \nbeta")
	if got := CollapseWhitespace(in); !bytes.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestCollapseWhitespace_NoWhitespaceUnchanged(t *testing.T) {
	in := []byte("no-whitespace-here")
	if got := CollapseWhitespace(in); !bytes.Equal(got, in) {
		t.Errorf("got %q; want %q (unchanged)", got, in)
	}
}

func TestCollapseWhitespace_Empty(t *testing.T) {
	if got := CollapseWhitespace(nil); len(got) != 0 {
		t.Errorf("nil -> %q; want empty", got)
	}
	if got := CollapseWhitespace([]byte{}); len(got) != 0 {
		t.Errorf("empty -> %q; want empty", got)
	}
}

func TestCollapseWhitespace_UTF8Preserved(t *testing.T) {
	// Non-ASCII codepoints survive collapse: the function operates on
	// runes, not bytes, so a multibyte character is not split.
	in := []byte("álvaro    pérez\tcrear archivo")
	want := []byte("álvaro pérez crear archivo")
	if got := CollapseWhitespace(in); !bytes.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestCollapseWhitespace_Idempotent(t *testing.T) {
	inputs := [][]byte{
		[]byte(""),
		[]byte("already canonical"),
		[]byte("messy \t \t whitespace"),
		[]byte("multi\nline\ttext   with\tboth"),
	}
	for _, in := range inputs {
		once := CollapseWhitespace(in)
		twice := CollapseWhitespace(once)
		if !bytes.Equal(once, twice) {
			t.Errorf("not idempotent for %q\n  once:  %q\n  twice: %q",
				in, once, twice)
		}
	}
}

// --- Composition contract ----------------------------------------------

// The two helpers are designed to be stacked. CollapseWhitespace AFTER
// StripLineComments is the canonical pipeline for crontab/sudoers.
// This test pins that order: applying it to an inflated input produces
// the same digest input as a hand-crafted canonical form.
func TestStripThenCollapse_NormalizesCosmeticVariants(t *testing.T) {
	variants := [][]byte{
		[]byte("MAILTO=root\n0   3 * * *   /opt/job.sh\n"),
		[]byte("# header\nMAILTO=root\n0\t3\t*\t*\t*\t/opt/job.sh\n"),
		[]byte("MAILTO=root  \n0 3 * * * /opt/job.sh   # tail\n# trailing\n"),
		[]byte("MAILTO=root\r\n0 3 * * * /opt/job.sh\r\n"),
	}
	canonical := CollapseWhitespace(StripLineComments(variants[0], "#"))
	for i, v := range variants[1:] {
		got := CollapseWhitespace(StripLineComments(v, "#"))
		if !bytes.Equal(got, canonical) {
			t.Errorf("variant %d does not match canonical:\n  canonical: %q\n  variant:   %q",
				i+1, canonical, got)
		}
	}
}
