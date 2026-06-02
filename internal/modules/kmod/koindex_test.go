package kmod

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jarmidaw/linpersist/internal/core"
)

type koProvStub struct{ orphan map[string]bool }

func (koProvStub) Warmup(context.Context) {}
func (s koProvStub) LookupPath(p string) (string, core.PkgStatus) {
	if s.orphan[p] {
		return "", core.PkgStatusOrphan
	}
	return "kmod-pkg", core.PkgStatusOwned
}

// TestModuleKOResolution: a modules.dep entry resolves a module name to
// its .ko, and an autoload directive for a package-unowned .ko (planted
// LKM rootkit) surfaces via exec_target + non_package_path; a packaged
// module does not.
func TestModuleKOResolution(t *testing.T) {
	root := t.TempDir()
	kver := "6.1.0-lab"
	dep := "kernel/drivers/evil/diamorphine.ko: \nkernel/net/legit/nf_tables.ko: \n"
	mustWriteK(t, filepath.Join(root, "lib/modules", kver, "modules.dep"), dep)
	mustWriteK(t, filepath.Join(root, "lib/modules", kver, "kernel/drivers/evil/diamorphine.ko"), "\x7fELF")
	mustWriteK(t, filepath.Join(root, "lib/modules", kver, "kernel/net/legit/nf_tables.ko"), "\x7fELF")
	// /etc/modules autoloads both: the rootkit (unowned) + a packaged one.
	mustWriteK(t, filepath.Join(root, "etc/modules"), "diamorphine\nnf_tables\n")

	evilKO := "/lib/modules/" + kver + "/kernel/drivers/evil/diamorphine.ko"
	m := New(Options{
		Root:       root,
		Provenance: koProvStub{orphan: map[string]bool{evilKO: true}},
	})

	if got := m.moduleKOPath("diamorphine"); got != evilKO {
		t.Fatalf("moduleKOPath(diamorphine) = %q; want %q", got, evilKO)
	}

	var recs []core.Record
	if err := m.Collect(context.Background(), func(r core.Record) { recs = append(recs, r) }); err != nil {
		t.Fatalf("collect: %v", err)
	}
	var evil, legit *core.Record
	for i := range recs {
		switch recs[i].ContentSnippet {
		case "diamorphine":
			evil = &recs[i]
		case "nf_tables":
			legit = &recs[i]
		}
	}
	if evil == nil || legit == nil {
		t.Fatalf("missing records: evil=%v legit=%v", evil != nil, legit != nil)
	}
	if !contains(evil.Signals, core.SignalKmodAutoload) || !contains(evil.Signals, core.SignalNonPackagePath) {
		t.Errorf("planted module signals = %v; want kmod_autoload + non_package_path", evil.Signals)
	}
	if evil.ExecTarget != evilKO {
		t.Errorf("planted exec_target = %q; want %q", evil.ExecTarget, evilKO)
	}
	if contains(legit.Signals, core.SignalNonPackagePath) {
		t.Errorf("packaged module wrongly flagged non_package_path: %v", legit.Signals)
	}
	if !contains(legit.Signals, core.SignalKmodAutoload) {
		t.Errorf("packaged autoload module missing kmod_autoload: %v", legit.Signals)
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func mustWriteK(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}
