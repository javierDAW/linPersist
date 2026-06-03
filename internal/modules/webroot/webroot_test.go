package webroot

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

func collect(t *testing.T, root string) map[string]core.Record {
	t.Helper()
	m := New(Options{Root: root, Now: func() time.Time { return fixedNow }})
	out := map[string]core.Record{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := m.Collect(ctx, func(r core.Record) { out[r.Locus] = r }); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return out
}

func TestWebrootCollectsScriptsNotAssets(t *testing.T) {
	root := t.TempDir()
	write(t, root, "var/www/html/index.php", "<?php phpinfo();")
	write(t, root, "var/www/html/uploads/shell.phtml", "<?php system($_GET['c']);")
	write(t, root, "var/www/html/style.css", "body{}") // not a script
	write(t, root, "var/www/html/logo.png", "PNGDATA") // not a script
	write(t, root, "srv/www/app.jsp", "<% out.print(1); %>")
	recs := collect(t, root)
	for _, want := range []string{"/var/www/html/index.php", "/var/www/html/uploads/shell.phtml", "/srv/www/app.jsp"} {
		r, ok := recs[want]
		if !ok {
			t.Errorf("missing webroot record for %s", want)
			continue
		}
		if r.SiteClass != siteClass || r.ContentSHA256 == "" {
			t.Errorf("bad record for %s: site=%q sha=%q", want, r.SiteClass, r.ContentSHA256)
		}
		if r.ExecTarget != "" {
			t.Errorf("webroot must not set exec_target (no provenance), got %q", r.ExecTarget)
		}
	}
	if _, ok := recs["/var/www/html/style.css"]; ok {
		t.Error(".css must not be collected")
	}
	if _, ok := recs["/var/www/html/logo.png"]; ok {
		t.Error(".png must not be collected")
	}
}

func TestWebrootNoNonRootOwnerSignal(t *testing.T) {
	root := t.TempDir()
	write(t, root, "var/www/html/x.php", "<?php")
	r := collect(t, root)["/var/www/html/x.php"]
	for _, s := range r.Signals {
		if s == core.SignalNonRootOwner {
			t.Error("webroot must NOT emit non_root_owner (www-data ownership is the norm -> would flood)")
		}
	}
}

func TestWebrootMaxRecordsCap(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 50; i++ {
		write(t, root, filepath.Join("var/www/html", "f"+string(rune('a'+i%26))+string(rune('0'+i/26))+".php"), "<?php")
	}
	m := New(Options{Root: root, Now: func() time.Time { return fixedNow }, MaxRecords: 10})
	n := 0
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = m.Collect(ctx, func(core.Record) { n++ })
	if n > 10 {
		t.Errorf("MaxRecords cap not honored: emitted %d, want <= 10", n)
	}
}
