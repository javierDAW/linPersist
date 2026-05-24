package dbus

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

// writeService stages a .service file under <root>/<loci>/<name>
// and returns the absolute path. Mirrors the staging helper pattern
// in other module tests.
func writeService(t *testing.T, root, loci, name, body string) string {
	t.Helper()
	dir := filepath.Join(root, loci)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	full := filepath.Join(dir, name)
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", full, err)
	}
	return full
}

func collect(t *testing.T, m *Module) []core.Record {
	t.Helper()
	var out []core.Record
	if err := m.Collect(context.Background(), func(r core.Record) { out = append(out, r) }); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Locus < out[j].Locus })
	return out
}

func signalSet(sigs []string) map[string]struct{} {
	m := make(map[string]struct{}, len(sigs))
	for _, s := range sigs {
		m[s] = struct{}{}
	}
	return m
}

// TestCollect_SystemServiceWithTmpExec is the canonical implant
// case: a system-bus .service whose Exec points under /tmp.
func TestCollect_SystemServiceWithTmpExec(t *testing.T) {
	root := t.TempDir()
	writeService(t, root, "/usr/share/dbus-1/system-services", "org.attacker.helper.service",
		"[D-BUS Service]\nName=org.attacker.helper\nExec=/tmp/.x/agent --serve\nUser=root\n")
	m := New(Options{Root: root})
	recs := collect(t, m)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	r := recs[0]
	if r.SiteClass != siteClassSystem {
		t.Errorf("site_class: got %q want %q", r.SiteClass, siteClassSystem)
	}
	if r.ExecTarget != "/tmp/.x/agent" {
		t.Errorf("exec_target: got %q want /tmp/.x/agent", r.ExecTarget)
	}
	sigs := signalSet(r.Signals)
	if _, ok := sigs[core.SignalInterpreterInTmp]; !ok {
		t.Errorf("missing interpreter_in_tmp (got %v)", r.Signals)
	}
	if _, ok := sigs[core.SignalExecTargetOrphan]; !ok {
		t.Errorf("missing exec_target_orphan for nonexistent payload (got %v)", r.Signals)
	}
}

// TestCollect_SessionServiceClassified validates the session-bus
// classification and that the Exec= is extracted.
func TestCollect_SessionServiceClassified(t *testing.T) {
	root := t.TempDir()
	writeService(t, root, "/usr/share/dbus-1/services", "org.example.app.service",
		"[D-BUS Service]\nName=org.example.app\nExec=/usr/bin/example-app\n")
	m := New(Options{Root: root})
	recs := collect(t, m)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	if recs[0].SiteClass != siteClassSession {
		t.Errorf("site_class: got %q want %q", recs[0].SiteClass, siteClassSession)
	}
	if recs[0].ExecTarget != "/usr/bin/example-app" {
		t.Errorf("exec_target: got %q", recs[0].ExecTarget)
	}
}

// TestCollect_EtcOverrideAlsoWalked: operator-side overrides under
// /etc must surface too.
func TestCollect_EtcOverrideAlsoWalked(t *testing.T) {
	root := t.TempDir()
	writeService(t, root, "/etc/dbus-1/system-services", "org.local.override.service",
		"[D-BUS Service]\nName=org.local.override\nExec=/opt/vendor/bin/run\n")
	m := New(Options{Root: root})
	recs := collect(t, m)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	if recs[0].SiteClass != siteClassSystem {
		t.Errorf("etc/ override should land in dbus.system, got %q", recs[0].SiteClass)
	}
}

// TestCollect_NonServiceFilesIgnored: only *.service files emit.
func TestCollect_NonServiceFilesIgnored(t *testing.T) {
	root := t.TempDir()
	writeService(t, root, "/usr/share/dbus-1/system-services", "README", "ignore me\n")
	writeService(t, root, "/usr/share/dbus-1/system-services", "backup.service~", "old\n")
	writeService(t, root, "/usr/share/dbus-1/system-services", ".hidden.service", "[D-BUS Service]\nExec=/bin/true\n")
	writeService(t, root, "/usr/share/dbus-1/system-services", "real.service",
		"[D-BUS Service]\nExec=/bin/true\n")
	m := New(Options{Root: root})
	recs := collect(t, m)
	if len(recs) != 1 {
		t.Fatalf("want 1 record (only real.service), got %d: %+v", len(recs), recs)
	}
}

// TestCollect_NoExecLine: a .service with no Exec= still emits a
// record (the analyst should see the orphan service definition)
// but with empty exec_target.
func TestCollect_NoExecLine(t *testing.T) {
	root := t.TempDir()
	writeService(t, root, "/usr/share/dbus-1/system-services", "org.nooop.service",
		"[D-BUS Service]\nName=org.nooop\nSystemdService=nooop.service\n")
	m := New(Options{Root: root})
	recs := collect(t, m)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	if recs[0].ExecTarget != "" {
		t.Errorf("exec_target should be empty without Exec= line, got %q", recs[0].ExecTarget)
	}
}

// TestParseService_QuotedExec covers the quote-stripping in
// firstToken via stripOuterQuotes — dbus accepts quoted Exec
// values just like .desktop files.
func TestParseService_QuotedExec(t *testing.T) {
	root := t.TempDir()
	writeService(t, root, "/usr/share/dbus-1/system-services", "q.service",
		"[D-BUS Service]\nExec=\"/usr/local/bin/wrap me\" --flag\n")
	m := New(Options{Root: root})
	recs := collect(t, m)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	// argv[0] of a freedesktop Exec= line is the content of the
	// outer quote pair; a path with spaces is legal. The agent
	// surfaces it verbatim so an attacker dropping a binary at a
	// pathological filename does not slip through.
	if recs[0].ExecTarget != "/usr/local/bin/wrap me" {
		t.Errorf("exec_target with quoted Exec: got %q", recs[0].ExecTarget)
	}
}

// TestCanonical_StableAcrossKeyOrder pins the content_norm_sha256
// determinism: the parsed map iteration order must not leak into
// the canonical form.
func TestCanonical_StableAcrossKeyOrder(t *testing.T) {
	a := canonical(map[string]string{"Name": "n", "Exec": "/e", "User": "u"})
	b := canonical(map[string]string{"User": "u", "Exec": "/e", "Name": "n"})
	if a != b {
		t.Errorf("canonical not stable: %q vs %q", a, b)
	}
}

// TestCollect_RecentMtimeSignal: a freshly-written .service fires
// recent_mtime_7d when the clock is anchored just after.
func TestCollect_RecentMtimeSignal(t *testing.T) {
	root := t.TempDir()
	writeService(t, root, "/usr/share/dbus-1/system-services", "fresh.service",
		"[D-BUS Service]\nExec=/bin/true\n")
	m := New(Options{
		Root: root,
		Now:  func() time.Time { return time.Now().Add(time.Minute).UTC() },
	})
	recs := collect(t, m)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	sigs := signalSet(recs[0].Signals)
	if _, ok := sigs[core.SignalRecentMtime7d]; !ok {
		t.Errorf("missing recent_mtime_7d on fresh file (got %v)", recs[0].Signals)
	}
}
