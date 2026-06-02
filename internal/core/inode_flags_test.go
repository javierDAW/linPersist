package core

import (
	"os"
	"path/filepath"
	"testing"
)

// TestInodeFlagSignals_PlainFile: a freshly created file has no chattr
// flags, so InodeFlagSignals returns nil. (Setting +i needs root, so the
// positive path is exercised end-to-end in the nspawn lab; here we pin
// the no-flag and error paths that must never emit a phantom signal.)
func TestInodeFlagSignals_PlainFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if sigs := InodeFlagSignals(f); sigs != nil {
		t.Errorf("plain file InodeFlagSignals = %v; want nil", sigs)
	}
}

func TestInodeFlagSignals_Missing(t *testing.T) {
	if sigs := InodeFlagSignals(filepath.Join(t.TempDir(), "nope")); sigs != nil {
		t.Errorf("missing path InodeFlagSignals = %v; want nil", sigs)
	}
}
