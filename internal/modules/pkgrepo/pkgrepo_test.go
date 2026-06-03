package pkgrepo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

var fixedNow = time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)

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

func collect(t *testing.T, root string) []core.Record {
	t.Helper()
	m := New(Options{Root: root, Now: func() time.Time { return fixedNow }})
	var recs []core.Record
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := m.Collect(ctx, func(r core.Record) { recs = append(recs, r) }); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return recs
}

func sig(recs []core.Record, sc, want string) bool {
	for _, r := range recs {
		if r.SiteClass != sc {
			continue
		}
		for _, s := range r.Signals {
			if s == want {
				return true
			}
		}
	}
	return false
}

func TestAptTrustedAndOrigin(t *testing.T) {
	root := t.TempDir()
	// trusted=yes (gpgcheck disabled) + a non-canonical host (origin).
	write(t, root, "etc/apt/sources.list.d/evil.list", "deb [trusted=yes] http://apt.evil.example/repo stable main\n")
	// canonical, signed -> NO record.
	write(t, root, "etc/apt/sources.list", "deb http://deb.debian.org/debian bookworm main\n")
	recs := collect(t, root)
	if !sig(recs, "pkgrepo.apt", core.SignalRepoGpgcheckDisabled) {
		t.Errorf("trusted=yes should raise repo_gpgcheck_disabled; recs=%v", recs)
	}
	if !sig(recs, "pkgrepo.apt", core.SignalRepoOriginAdded) {
		t.Errorf("non-canonical host should raise repo_origin_added")
	}
	// the canonical signed repo must NOT produce a record
	for _, r := range recs {
		if r.SiteClass == "pkgrepo.apt" && r.ContentSnippet != "" && containsHost(r.ContentSnippet, "deb.debian.org") {
			t.Errorf("canonical signed repo must not produce a record: %q", r.ContentSnippet)
		}
	}
}

func containsHost(s, h string) bool {
	return len(s) > 0 && (len(h) == 0 || (func() bool { return indexOf(s, h) >= 0 })())
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestYumGpgcheck(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/yum.repos.d/evil.repo", "[evil]\nname=evil\nbaseurl=http://yum.evil.example/x\nenabled=1\ngpgcheck=0\n")
	write(t, root, "etc/yum.repos.d/base.repo", "[base]\nname=base\nbaseurl=http://dl.rockylinux.org/pub/rocky/9/x\nenabled=1\ngpgcheck=1\n")
	write(t, root, "etc/yum.repos.d/disabled.repo", "[old]\nbaseurl=http://yum.evil.example/y\nenabled=0\ngpgcheck=0\n")
	recs := collect(t, root)
	if !sig(recs, "pkgrepo.yum", core.SignalRepoGpgcheckDisabled) {
		t.Errorf("gpgcheck=0 should raise repo_gpgcheck_disabled; recs=%v", recs)
	}
	// disabled section + canonical signed section -> only the evil one emits
	n := 0
	for _, r := range recs {
		if r.SiteClass == "pkgrepo.yum" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("expected exactly 1 yum record (the evil enabled gpgcheck=0); got %d: %v", n, recs)
	}
}

func TestCleanReposYieldNothing(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/apt/sources.list", "deb http://deb.debian.org/debian bookworm main\ndeb http://security.debian.org/debian-security bookworm-security main\n")
	write(t, root, "etc/yum.repos.d/base.repo", "[base]\nbaseurl=http://dl.rockylinux.org/x\nenabled=1\ngpgcheck=1\n")
	if recs := collect(t, root); len(recs) != 0 {
		t.Errorf("clean signed+canonical repos must yield nothing; got %v", recs)
	}
}
