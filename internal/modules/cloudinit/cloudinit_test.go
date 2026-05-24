package cloudinit

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"testing"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

func writeFile(t *testing.T, root, loci, name string, mode uint32, body string) string {
	t.Helper()
	dir := filepath.Join(root, loci)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	full := filepath.Join(dir, name)
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", full, err)
	}
	if mode != 0 {
		if err := syscall.Chmod(full, mode); err != nil {
			t.Fatalf("chmod %s: %v", full, err)
		}
	}
	return full
}

func collect(t *testing.T, m *Module) []core.Record {
	t.Helper()
	var out []core.Record
	if err := m.Collect(context.Background(), func(r core.Record) { out = append(out, r) }); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SiteClass != out[j].SiteClass {
			return out[i].SiteClass < out[j].SiteClass
		}
		return out[i].Locus < out[j].Locus
	})
	return out
}

// TestCollect_CloudCfgD_DropinClassified covers the most common
// case: an operator-pushed drop-in under /etc/cloud/cloud.cfg.d/.
func TestCollect_CloudCfgD_DropinClassified(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/etc/cloud/cloud.cfg.d", "90-custom.cfg", 0o644,
		"#cloud-config\nruncmd:\n  - touch /tmp/marker\n")
	m := New(Options{Root: root})
	recs := collect(t, m)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	r := recs[0]
	if r.SiteClass != siteClassConfig {
		t.Errorf("site_class: got %q want %q", r.SiteClass, siteClassConfig)
	}
	if len(r.MITRE) != 2 || r.MITRE[0] != mitreCreateProcess || r.MITRE[1] != mitreAutostart {
		t.Errorf("mitre: got %v want [%s %s]", r.MITRE, mitreCreateProcess, mitreAutostart)
	}
	if r.ExecTarget != "" {
		t.Errorf("config records should not populate exec_target (got %q)", r.ExecTarget)
	}
}

// TestCollect_NonCfgFilesIgnored: cloud-init only loads *.cfg files
// from cloud.cfg.d/; READMEs and backups are skipped.
func TestCollect_NonCfgFilesIgnored(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/etc/cloud/cloud.cfg.d", "README", 0o644, "docs\n")
	writeFile(t, root, "/etc/cloud/cloud.cfg.d", "10-real.cfg", 0o644, "#cloud-config\n")
	writeFile(t, root, "/etc/cloud/cloud.cfg.d", "50-backup.cfg~", 0o644, "old\n")
	m := New(Options{Root: root})
	recs := collect(t, m)
	if len(recs) != 1 {
		t.Fatalf("want 1 record (10-real.cfg only), got %d", len(recs))
	}
}

// TestCollect_PerBootScriptIsExecTarget verifies that a script
// under /var/lib/cloud/scripts/per-boot/ surfaces as
// cloudinit.script with ExecTarget == locus.
func TestCollect_PerBootScriptIsExecTarget(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/var/lib/cloud/scripts/per-boot", "10-rotate-keys", 0o755,
		"#!/bin/sh\necho hi >> /var/log/rotate-keys.log\n")
	m := New(Options{Root: root})
	recs := collect(t, m)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	r := recs[0]
	if r.SiteClass != siteClassScript {
		t.Errorf("site_class: got %q want %q", r.SiteClass, siteClassScript)
	}
	if r.ExecTarget != "/var/lib/cloud/scripts/per-boot/10-rotate-keys" {
		t.Errorf("exec_target: got %q", r.ExecTarget)
	}
	if r.ExecTargetSHA256 == "" {
		t.Errorf("exec_target_sha256 should equal content_sha256 for self-exec scripts")
	}
	if r.ExecTargetSHA256 != r.ContentSHA256 {
		t.Errorf("exec_target_sha256 should equal content_sha256: %q vs %q",
			r.ExecTargetSHA256, r.ContentSHA256)
	}
}

// TestCollect_NonExecScript_RecordsError: cloud-init silently skips
// non-x scripts; the agent emits the record with a NOT_EXECUTABLE
// error envelope so the analyst sees the dead drop.
func TestCollect_NonExecScript_RecordsError(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/var/lib/cloud/scripts/per-boot", "10-quiet", 0o644,
		"#!/bin/sh\necho hi\n")
	m := New(Options{Root: root})
	recs := collect(t, m)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	found := false
	for _, e := range recs[0].Errors {
		if e.Code == "NOT_EXECUTABLE" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected NOT_EXECUTABLE error envelope, got %+v", recs[0].Errors)
	}
}

// TestCollect_AllThreePhasesSurface: per-boot, per-instance and
// per-once each have their own dir; one script in each must
// produce three records.
func TestCollect_AllThreePhasesSurface(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/var/lib/cloud/scripts/per-boot", "10-boot", 0o755, "#!/bin/sh\n")
	writeFile(t, root, "/var/lib/cloud/scripts/per-instance", "10-instance", 0o755, "#!/bin/sh\n")
	writeFile(t, root, "/var/lib/cloud/scripts/per-once", "10-once", 0o755, "#!/bin/sh\n")
	m := New(Options{Root: root})
	recs := collect(t, m)
	if len(recs) != 3 {
		t.Fatalf("want 3 records, got %d", len(recs))
	}
	wantLoci := []string{
		"/var/lib/cloud/scripts/per-boot/10-boot",
		"/var/lib/cloud/scripts/per-instance/10-instance",
		"/var/lib/cloud/scripts/per-once/10-once",
	}
	for i, r := range recs {
		if r.SiteClass != siteClassScript {
			t.Errorf("rec[%d].SiteClass: got %q", i, r.SiteClass)
		}
		if r.Locus != wantLoci[i] {
			t.Errorf("rec[%d].Locus: got %q want %q", i, r.Locus, wantLoci[i])
		}
	}
}

// TestCollect_MainCloudCfgClassified: the main /etc/cloud/cloud.cfg
// file is read as a single-file config (not via a dir walk).
func TestCollect_MainCloudCfgClassified(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/etc/cloud", "cloud.cfg", 0o644,
		"#cloud-config\nuser: ubuntu\n")
	m := New(Options{Root: root})
	recs := collect(t, m)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	if recs[0].Locus != "/etc/cloud/cloud.cfg" {
		t.Errorf("locus: got %q", recs[0].Locus)
	}
	if recs[0].SiteClass != siteClassConfig {
		t.Errorf("site_class: got %q want %q", recs[0].SiteClass, siteClassConfig)
	}
}

// TestCollect_NoCloudInit_NoRecords: a host without cloud-init
// installed produces zero records, no error.
func TestCollect_NoCloudInit_NoRecords(t *testing.T) {
	root := t.TempDir()
	m := New(Options{Root: root})
	recs := collect(t, m)
	if len(recs) != 0 {
		t.Fatalf("want 0 records on bare host, got %d", len(recs))
	}
}

// TestCollect_RecentMtime_FiresOnFreshFile: per-boot script written
// "just now" emits recent_mtime_7d.
func TestCollect_RecentMtime_FiresOnFreshFile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/var/lib/cloud/scripts/per-boot", "10-fresh", 0o755, "#!/bin/sh\n")
	m := New(Options{
		Root: root,
		Now:  func() time.Time { return time.Now().Add(time.Minute).UTC() },
	})
	recs := collect(t, m)
	found := false
	for _, s := range recs[0].Signals {
		if s == core.SignalRecentMtime7d {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected recent_mtime_7d, got %v", recs[0].Signals)
	}
}
