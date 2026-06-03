package core

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// pacman fixture: a local-db package dir with a `files` index.
func pacmanFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "etc/os-release"), "ID=arch\n")
	// linux-firmware-20240101-1 proves the version-strip keeps hyphenated names.
	writeFile(t, filepath.Join(root, "var/lib/pacman/local/linux-firmware-20240101-1/files"),
		"%FILES%\nusr/\nusr/lib/\nusr/lib/firmware/x.bin\n\n%BACKUP%\netc/fw.conf\tabc123\n")
	writeFile(t, filepath.Join(root, "var/lib/pacman/local/coreutils-9.5-1/files"),
		"%FILES%\nusr/\nusr/bin/\nusr/bin/ls\nusr/bin/cat\n")
	return root
}

func TestResolver_PacmanOwnership(t *testing.T) {
	root := pacmanFixture(t)
	r := NewResolver(nullLogger(), WithProvenanceRoot(root))
	r.Warmup(context.Background())
	if r.PackageManager() != PkgMgrPacman {
		t.Fatalf("PackageManager = %v; want PkgMgrPacman", r.PackageManager())
	}
	pkg, status := r.LookupPath("/usr/bin/ls")
	if status != PkgStatusOwned || pkg != "coreutils" {
		t.Errorf("LookupPath(/usr/bin/ls) = (%q,%q); want (coreutils, owned)", pkg, status)
	}
	if pkg, _ := r.LookupPath("/usr/lib/firmware/x.bin"); pkg != "linux-firmware" {
		t.Errorf("hyphenated pkg name wrong: got %q want linux-firmware", pkg)
	}
	// A directory entry (trailing slash) must NOT be owned, and an orphan path is orphan.
	if _, status := r.LookupPath("/usr/bin"); status == PkgStatusOwned {
		t.Errorf("directory entry should not be owned")
	}
	if _, status := r.LookupPath("/opt/.evil/payload"); status != PkgStatusOrphan {
		t.Errorf("planted /opt path = %q; want orphan", status)
	}
}

// portage fixture: a CONTENTS file under /var/db/pkg/<cat>/<pkgver>/.
func portageFixture(t *testing.T, lsContent string) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "etc/os-release"), "ID=gentoo\n")
	sum := md5.Sum([]byte(lsContent))
	lsMD5 := hex.EncodeToString(sum[:])
	writeFile(t, filepath.Join(root, "usr/bin/ls"), lsContent)
	writeFile(t, filepath.Join(root, "var/db/pkg/sys-apps/coreutils-9.5/CONTENTS"),
		"dir /usr/bin\n"+
			"obj /usr/bin/ls "+lsMD5+" 1700000000\n"+
			"sym /usr/bin/dir -> /usr/bin/ls 1700000000\n")
	return root
}

func TestResolver_PortageOwnership(t *testing.T) {
	root := portageFixture(t, "ELF-ls\n")
	r := NewResolver(nullLogger(), WithProvenanceRoot(root))
	r.Warmup(context.Background())
	if r.PackageManager() != PkgMgrPortage {
		t.Fatalf("PackageManager = %v; want PkgMgrPortage", r.PackageManager())
	}
	pkg, status := r.LookupPath("/usr/bin/ls")
	if status != PkgStatusOwned || pkg != "sys-apps/coreutils-9.5" {
		t.Errorf("LookupPath(/usr/bin/ls) = (%q,%q); want (sys-apps/coreutils-9.5, owned)", pkg, status)
	}
	if _, status := r.LookupPath("/usr/bin/dir"); status != PkgStatusOwned {
		t.Errorf("sym CONTENTS entry should be owned")
	}
	if _, status := r.LookupPath("/opt/.evil/x"); status != PkgStatusOrphan {
		t.Errorf("orphan path = %q; want orphan", status)
	}
}

func TestResolver_PortageVerifyPath(t *testing.T) {
	// Clean: on-disk content matches the CONTENTS md5 (a fresh resolver).
	cleanRoot := portageFixture(t, "ELF-ls-clean\n")
	rc := NewResolver(nullLogger(), WithProvenanceRoot(cleanRoot))
	rc.Warmup(context.Background())
	if got := rc.VerifyPath("/usr/bin/ls"); got != PkgVerifyMatched {
		t.Fatalf("clean portage file VerifyPath = %q; want matched", got)
	}

	// Tampered: CONTENTS records md5("clean") but the on-disk file already
	// differs at warmup (a separate resolver, so no cached verdict).
	tamperRoot := portageFixture(t, "ELF-ls-clean\n")
	if err := os.WriteFile(filepath.Join(tamperRoot, "usr/bin/ls"), []byte("TAMPERED\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rt := NewResolver(nullLogger(), WithProvenanceRoot(tamperRoot))
	rt.Warmup(context.Background())
	if got := rt.VerifyPath("/usr/bin/ls"); got != PkgVerifyMismatched {
		t.Errorf("tampered portage file VerifyPath = %q; want mismatched", got)
	}
}

func TestDetectPackageManager_ArchGentoo(t *testing.T) {
	cases := []struct {
		name     string
		osID     string
		mkPkgDir string
		want     PackageManager
	}{
		{"arch", "ID=arch\n", "var/lib/pacman/local", PkgMgrPacman},
		{"manjaro", "ID=manjaro\nID_LIKE=arch\n", "var/lib/pacman/local", PkgMgrPacman},
		{"gentoo", "ID=gentoo\n", "var/db/pkg", PkgMgrPortage},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, filepath.Join(root, "etc/os-release"), tc.osID)
			if err := os.MkdirAll(filepath.Join(root, tc.mkPkgDir), 0o755); err != nil {
				t.Fatal(err)
			}
			r := NewResolver(nullLogger(), WithProvenanceRoot(root))
			if got := r.detectPackageManager(); got != tc.want {
				t.Errorf("detectPackageManager() = %v; want %v", got, tc.want)
			}
		})
	}
}
