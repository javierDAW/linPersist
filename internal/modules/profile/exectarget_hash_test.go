package profile

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

// orphanProvenance reports a single (logical) target path as non-package
// (orphan) and everything else as unknown.
type orphanProvenance struct{ target string }

func (orphanProvenance) Warmup(context.Context) {}

func (o orphanProvenance) LookupPath(p string) (string, core.PkgStatus) {
	if p == o.target {
		return "", core.PkgStatusOrphan
	}
	return "", core.PkgStatusUnknown
}

// writePayloadInRoot drops a payload at the ROOT-resolved location of a
// logical path and returns (logicalPath, bytes). The exec_target in the
// config is the logical path; the file lives under root, so a --root
// collection must resolve through root to hash it (regression guard for
// the root-resolution bug the re-audit found in the first fix).
func writePayloadInRoot(t *testing.T, root, logical string) (string, []byte) {
	t.Helper()
	real := filepath.Join(root, filepath.FromSlash(logical))
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		t.Fatal(err)
	}
	b := []byte("#!/bin/sh\necho inert-worm\n")
	if err := os.WriteFile(real, b, 0o755); err != nil {
		t.Fatal(err)
	}
	return logical, b
}

func collectProfile(t *testing.T, opts Options) []core.Record {
	t.Helper()
	var recs []core.Record
	if err := New(opts).Collect(context.Background(), func(r core.Record) { recs = append(recs, r) }); err != nil {
		t.Fatal(err)
	}
	return recs
}

// TestExecTargetHashedAndProvenancePreserved guards the profile.system
// fix: the arm gets exec_target_sha256 (so Q6 can stack a worm) and keeps
// non_package_path (which the old code clobbered by rebuilding rec.Signals
// after annotating). The payload lives under root, so this also guards the
// root-resolution fix.
func TestExecTargetHashedAndProvenancePreserved(t *testing.T) {
	root := t.TempDir()
	target, payload := writePayloadInRoot(t, root, "/usr/local/sbin/sync-agent")

	dropin := filepath.Join(root, "etc", "profile.d", "deploy-sync.sh")
	if err := os.MkdirAll(filepath.Dir(dropin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dropin, []byte(target+" &\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	recs := collectProfile(t, Options{
		Root:       root,
		Now:        func() time.Time { return time.Now().UTC() },
		Provenance: orphanProvenance{target: target},
	})

	hit := findRec(recs, "profile.system", target)
	if hit == nil {
		t.Fatalf("no profile.system record with exec_target %s among %d records", target, len(recs))
	}
	if want := core.HashHex(payload); hit.ExecTargetSHA256 != want {
		t.Errorf("exec_target_sha256 = %q, want %q (Q6 needs the payload hash)", hit.ExecTargetSHA256, want)
	}
	if !hasSignal(hit.Signals, "non_package_path") {
		t.Errorf("non_package_path missing from %v (signal-clobber regression)", hit.Signals)
	}
}

// TestTrapArmExecTargetHashed guards the trap-path fix (GAP-2): the trap
// emit path now hashes its exec_target (root-resolved) and annotates
// provenance, so a trap worm arm carries exec_target_sha256 +
// non_package_path and can stack in Q6.
func TestTrapArmExecTargetHashed(t *testing.T) {
	root := t.TempDir()
	target, payload := writePayloadInRoot(t, root, "/usr/local/sbin/cleanup")

	dropin := filepath.Join(root, "etc", "profile.d", "zz-trap.sh")
	if err := os.MkdirAll(filepath.Dir(dropin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dropin, []byte("trap '"+target+"' EXIT\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	recs := collectProfile(t, Options{
		Root:       root,
		Now:        func() time.Time { return time.Now().UTC() },
		Provenance: orphanProvenance{target: target},
	})

	hit := findRec(recs, "profile.trap.system", target)
	if hit == nil {
		t.Fatalf("no trap record with exec_target %s among %d", target, len(recs))
	}
	if want := core.HashHex(payload); hit.ExecTargetSHA256 != want {
		t.Errorf("trap exec_target_sha256 = %q, want %q (Q6 needs it)", hit.ExecTargetSHA256, want)
	}
	if !hasSignal(hit.Signals, "non_package_path") {
		t.Errorf("non_package_path missing from trap record %v", hit.Signals)
	}
}

// TestTrapCommandInTmpUsesTmpDirs guards the trap.go fix: a trap into a
// tmp-class dir OTHER than /tmp (here /var/tmp) must still fire
// trap_command_in_tmp. The old code used a literal "/tmp/" prefix.
func TestTrapCommandInTmpUsesTmpDirs(t *testing.T) {
	root := t.TempDir()
	dropin := filepath.Join(root, "etc", "profile.d", "zz-trap.sh")
	if err := os.MkdirAll(filepath.Dir(dropin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dropin, []byte("trap '/var/tmp/.x/agent' EXIT\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	recs := collectProfile(t, Options{Root: root, Now: func() time.Time { return time.Now().UTC() }})
	hit := findRec(recs, "profile.trap.system", "/var/tmp/.x/agent")
	if hit == nil {
		// exec_target may differ; fall back to any trap record.
		for i := range recs {
			if recs[i].SiteClass == "profile.trap.system" {
				hit = &recs[i]
				break
			}
		}
	}
	if hit == nil {
		t.Fatalf("no profile.trap.system record among %d", len(recs))
	}
	if !hasSignal(hit.Signals, "trap_command_in_tmp") {
		t.Fatalf("trap into /var/tmp did not fire trap_command_in_tmp: %v", hit.Signals)
	}
}

func findRec(recs []core.Record, siteClass, execTarget string) *core.Record {
	for i := range recs {
		if recs[i].SiteClass == siteClass && recs[i].ExecTarget == execTarget {
			return &recs[i]
		}
	}
	return nil
}

func hasSignal(sigs []string, want string) bool {
	for _, s := range sigs {
		if s == want {
			return true
		}
	}
	return false
}
