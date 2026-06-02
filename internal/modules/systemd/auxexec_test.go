package systemd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jarmidaw/linpersist/internal/core"
)

type auxProvStub struct {
	orphan map[string]bool
	owned  map[string]bool
}

func (auxProvStub) Warmup(context.Context) {}
func (s auxProvStub) LookupPath(p string) (string, core.PkgStatus) {
	switch {
	case s.orphan[p]:
		return "", core.PkgStatusOrphan
	case s.owned[p]:
		return "pkg", core.PkgStatusOwned
	}
	return "", core.PkgStatusUnknown
}

// TestAuxExecUnmanaged pins the ExecStartPre behavior-injection detector:
// it must fire only on an aux-exec target that EXISTS and is package-
// unowned (a parked payload), not on a vendor unit's reference to an
// owned or absent optional binary (the emergency.service flood the lab
// surfaced).
func TestAuxExecUnmanaged(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "opt/payload"), "x")
	mustWrite(t, filepath.Join(root, "usr/bin/legit"), "x")
	m := New(Options{
		Root: root,
		Provenance: auxProvStub{
			orphan: map[string]bool{"/opt/payload": true},
			owned:  map[string]bool{"/usr/bin/legit": true},
		},
	})
	mk := func(val string) []Section {
		return []Section{{Entries: []Entry{{Key: "ExecStartPre", Value: val}}}}
	}
	cases := []struct {
		name string
		val  string
		want bool
	}{
		{"present + package-unowned -> fire", "/opt/payload", true},
		{"present + owned vendor binary -> no fire", "/usr/bin/legit", false},
		{"absent target (optional vendor binary) -> no fire", "/opt/missing", false},
		{"tmp-class target -> fire", "/tmp/.x/run", true},
		{"bare relative command -> no fire", "true", false},
	}
	for _, tc := range cases {
		if got := m.auxExecUnmanaged(mk(tc.val)); got != tc.want {
			t.Errorf("%s: auxExecUnmanaged(%q) = %v; want %v", tc.name, tc.val, got, tc.want)
		}
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
}
