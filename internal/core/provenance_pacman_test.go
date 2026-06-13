package core

import (
	"context"
	"testing"
)

// Validates the pacman mtree parser against a REAL Arch package mtree
// (licenses-20240728-1, committed under testdata/) — not a synthetic file,
// so a wrong understanding of the gzipped mtree v2.0 format would fail here.
func TestBuildPacmanDigestsRealMtree(t *testing.T) {
	r := &Resolver{root: "testdata/pacman"}
	dig, err := r.buildPacmanDigests(context.Background())
	if err != nil {
		t.Fatalf("buildPacmanDigests: %v", err)
	}
	// Path -> sha256 cross-checked independently via `zcat | grep`.
	const path = "/usr/share/licenses/known_spdx_license_exceptions.txt"
	const want = "72fff1f78950764982efbef634772bafb89b87344de00560f3ec35a99a66e9af"
	if got := dig[path]; got != want {
		t.Errorf("digest[%s] = %q, want %q", path, got, want)
	}
	if len(dig) < 2 {
		t.Errorf("expected several file digests from the real mtree, got %d", len(dig))
	}
	// Directories carry no sha256digest -> must not appear.
	if _, ok := dig["/usr/share/licenses"]; ok {
		t.Error("a directory entry leaked into fileDigests")
	}
}

func TestMtreeUnescape(t *testing.T) {
	cases := map[string]string{
		"/usr/bin/x":          "/usr/bin/x",
		"/usr/share/a\\040b":  "/usr/share/a b",  // \040 octal = space
		"/x\\\\y":             "/x\\y",            // \\ = backslash
	}
	for in, want := range cases {
		if got := mtreeUnescape(in); got != want {
			t.Errorf("mtreeUnescape(%q) = %q, want %q", in, got, want)
		}
	}
}
