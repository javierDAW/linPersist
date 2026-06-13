package systemd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jarmidaw/linpersist/internal/core"
)

// The external-unit-symlink anomaly signal must be gated on the target unit
// being NON-package: a vendor package that ships a unit under /opt and
// symlinks it into a .wants dir (legit) stays silent; an attacker's symlink
// to a non-package unit fires.
func TestExternalSymlinkProvenanceGate(t *testing.T) {
	root := t.TempDir()
	write := func(p, c string) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	unit := "[Service]\nExecStart=/usr/bin/true\n"
	write("opt/vendor/legit.service", unit)   // OWNED vendor external unit
	write("opt/evil/payload.service", unit)   // non-package attacker unit
	wants := filepath.Join(root, "etc/systemd/system/multi-user.target.wants")
	if err := os.MkdirAll(wants, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/opt/vendor/legit.service", filepath.Join(wants, "legit.service")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/opt/evil/payload.service", filepath.Join(wants, "payload.service")); err != nil {
		t.Fatal(err)
	}

	m := New(Options{
		Root: root,
		Provenance: auxProvStub{
			owned:  map[string]bool{"/opt/vendor/legit.service": true},
			orphan: map[string]bool{},
		},
	})
	var recs []core.Record
	if err := m.Collect(context.Background(), func(r core.Record) { recs = append(recs, r) }); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	sig := func(locusSub string) (bool, bool) {
		for _, r := range recs {
			if filepath.Base(r.Locus) == locusSub || (len(r.Locus) > 0 && contains(r.Locus, locusSub)) {
				for _, s := range r.Signals {
					if s == core.SignalSystemdExternalUnitSymlink {
						return true, true
					}
				}
				return false, true
			}
		}
		return false, false
	}
	legitFired, legitSeen := sig("legit.service")
	evilFired, evilSeen := sig("payload.service")
	if !legitSeen || !evilSeen {
		t.Fatalf("records not collected (legit=%v evil=%v); got %d records", legitSeen, evilSeen, len(recs))
	}
	if legitFired {
		t.Error("OWNED vendor external unit fired systemd_external_unit_symlink (false positive)")
	}
	if !evilFired {
		t.Error("non-package external unit did NOT fire systemd_external_unit_symlink (missed)")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
