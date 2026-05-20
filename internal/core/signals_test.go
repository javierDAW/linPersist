// Internal-consistency tests for the signals catalog.
//
// These tests run on the Signals slice itself and verify properties
// the catalog must satisfy without looking at the rest of the source
// tree. The cross-source audit (modules and core helpers actually
// referencing every catalog name and vice-versa) lives in
// signals_emission_test.go because it has to scan the filesystem.

package core

import (
	"strings"
	"testing"
)

// TestSignalCatalogNoDuplicates: every Signals[i].Name must be unique.
// A duplicate would shadow itself in signalsByName and quietly mask
// the second entry's metadata at runtime.
func TestSignalCatalogNoDuplicates(t *testing.T) {
	seen := make(map[string]int, len(Signals))
	for i, s := range Signals {
		if prev, ok := seen[s.Name]; ok {
			t.Errorf("duplicate signal name %q at index %d (first seen at index %d)",
				s.Name, i, prev)
			continue
		}
		seen[s.Name] = i
	}
}

// TestSignalCatalogDescriptionShape: every entry must have a
// non-trivial Description. The shape rules are deliberately loose:
//
//   - Non-empty (catches blank entries from copy-paste).
//   - At least 20 characters (catches stubs like "todo").
//   - At most 200 characters (one-liner contract; if you need more,
//     the full rationale belongs in the const docstring in signals.go,
//     not here).
//   - No trailing period (consistency with the surrounding catalog).
func TestSignalCatalogDescriptionShape(t *testing.T) {
	for _, s := range Signals {
		switch {
		case s.Description == "":
			t.Errorf("signal %q has empty Description", s.Name)
		case len(s.Description) < 20:
			t.Errorf("signal %q Description too short (%d chars): %q",
				s.Name, len(s.Description), s.Description)
		case len(s.Description) > 200:
			t.Errorf("signal %q Description too long (%d chars): %q",
				s.Name, len(s.Description), s.Description)
		case strings.HasSuffix(s.Description, "."):
			t.Errorf("signal %q Description ends with a period: %q",
				s.Name, s.Description)
		}
	}
}

// TestSignalCatalogEmittedByNonEmpty: every entry must declare at
// least one emitter. A signal nobody emits is documentation noise and
// would confuse downstream consumers expecting it in the wild.
func TestSignalCatalogEmittedByNonEmpty(t *testing.T) {
	for _, s := range Signals {
		if len(s.EmittedBy) == 0 {
			t.Errorf("signal %q declares no emitter", s.Name)
		}
	}
}

// TestSignalCatalogEmittedByTokenShape: each EmittedBy token must be
// either a bare module name (lowercase, no separators) or a
// core-helper path of the form "core/<file>". Other shapes catch
// typos and unintended formats.
func TestSignalCatalogEmittedByTokenShape(t *testing.T) {
	for _, s := range Signals {
		for _, token := range s.EmittedBy {
			if token == "" {
				t.Errorf("signal %q has empty EmittedBy token", s.Name)
				continue
			}
			if strings.HasPrefix(token, "core/") {
				rest := strings.TrimPrefix(token, "core/")
				if rest == "" || strings.ContainsAny(rest, "/ \t") {
					t.Errorf("signal %q EmittedBy %q: expected core/<file>",
						s.Name, token)
				}
				continue
			}
			if strings.ContainsAny(token, "/ \t") || strings.ToLower(token) != token {
				t.Errorf("signal %q EmittedBy %q: expected bare lowercase module name",
					s.Name, token)
			}
		}
	}
}

// TestSignalCatalogLookup: SignalByName, KnownSignal and
// KnownSignalSet must agree on the universe.
func TestSignalCatalogLookup(t *testing.T) {
	if got, want := len(KnownSignalSet()), len(Signals); got != want {
		t.Fatalf("KnownSignalSet size = %d, want %d", got, want)
	}
	for _, s := range Signals {
		got, ok := SignalByName(s.Name)
		if !ok {
			t.Errorf("SignalByName(%q): not found", s.Name)
			continue
		}
		if got.Name != s.Name {
			t.Errorf("SignalByName(%q) returned %q", s.Name, got.Name)
		}
		if !KnownSignal(s.Name) {
			t.Errorf("KnownSignal(%q) = false", s.Name)
		}
	}
	if _, ok := SignalByName("definitely_not_a_signal_v0xdeadbeef"); ok {
		t.Error("SignalByName on bogus name returned ok=true")
	}
	if KnownSignal("definitely_not_a_signal_v0xdeadbeef") {
		t.Error("KnownSignal on bogus name returned true")
	}
}
