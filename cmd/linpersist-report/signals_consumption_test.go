package main

import (
	"testing"

	"github.com/jarmidaw/linpersist/internal/core"
)

// TestWarningSignals_KeysExistInCatalog asserts that every key in the
// warningSignals map is a real signal declared in core.Signals. This
// closes the consumption-side drift channel: signals_emission_test.go in
// the core package audits modules that EMIT signals, but never sees who
// CONSUMES them. Without this test, a rename or removal in
// internal/core/signals.go could silently demote a warning pill in the
// HTML report back to "accent informational" without any test failing.
func TestWarningSignals_KeysExistInCatalog(t *testing.T) {
	t.Parallel()
	known := make(map[string]struct{}, len(core.Signals))
	for _, def := range core.Signals {
		known[def.Name] = struct{}{}
	}
	for key := range warningSignals {
		if _, ok := known[key]; !ok {
			t.Errorf("warningSignals key %q is not declared in core.Signals — typo or removed signal?", key)
		}
	}
}
