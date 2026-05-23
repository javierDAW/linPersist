package modset

import (
	"sort"
	"testing"
)

// TestAll_Count pins the number of modules so accidentally dropping a
// constructor line from All() fails a test instead of silently shipping
// a smaller binary.
func TestAll_Count(t *testing.T) {
	t.Parallel()
	const want = 22
	if got := len(All(nil, nil)); got != want {
		t.Fatalf("All() returned %d modules, want %d", got, want)
	}
}

// TestAll_AlphabeticalByName asserts modules are returned in
// alphabetical order of Name(). The order is load-bearing for
// determinism in matrix-audit's drift messages and for predictable
// startup logs — preserve it.
func TestAll_AlphabeticalByName(t *testing.T) {
	t.Parallel()
	mods := All(nil, nil)
	names := make([]string, len(mods))
	for i, m := range mods {
		names[i] = m.Name()
	}
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	for i := range names {
		if names[i] != sorted[i] {
			t.Fatalf("All() not alphabetical at index %d: got %q, want %q (full=%v)",
				i, names[i], sorted[i], names)
		}
	}
}

// TestAll_UniqueNames guards against two modules accidentally claiming
// the same Name() — a class of bug that would break matrix-audit's
// (module, site_class) pair uniqueness invariant.
func TestAll_UniqueNames(t *testing.T) {
	t.Parallel()
	seen := map[string]struct{}{}
	for _, m := range All(nil, nil) {
		if _, dup := seen[m.Name()]; dup {
			t.Fatalf("duplicate module name %q in modset.All()", m.Name())
		}
		seen[m.Name()] = struct{}{}
	}
}

// TestAll_NilDepsAccepted asserts that passing nil for both deps is a
// valid call (matrix-audit relies on this). The constructors must
// substitute noop implementations rather than panic on a nil interface.
func TestAll_NilDepsAccepted(t *testing.T) {
	t.Parallel()
	mods := All(nil, nil)
	if len(mods) == 0 {
		t.Fatal("All(nil, nil) returned empty slice")
	}
	for _, m := range mods {
		if m.Name() == "" {
			t.Fatalf("module has empty Name()")
		}
		if len(m.SiteClasses()) == 0 {
			t.Fatalf("module %q has no SiteClasses()", m.Name())
		}
	}
}
