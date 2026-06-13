package core

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPayloadExecSignals(t *testing.T) {
	root := t.TempDir()
	resolve := func(p string) string { return filepath.Join(root, p) }
	now := time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)

	// A present, freshly-modified non-tmp payload.
	present := filepath.Join(root, "usr", "local", "bin", "helper")
	if err := os.MkdirAll(filepath.Dir(present), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(present, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(present, now.Add(-time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		target string
		want   []string
		absent []string
	}{
		{"tmp_dangling", "/tmp/.sysv/agent",
			[]string{SignalInterpreterInTmp, SignalExecTargetOrphan}, nil},
		{"var_tmp_dangling", "/var/tmp/.x",
			[]string{SignalInterpreterInTmp, SignalExecTargetOrphan}, nil},
		{"non_tmp_orphan", "/usr/local/bin/missing",
			[]string{SignalExecTargetOrphan}, []string{SignalInterpreterInTmp}},
		{"non_tmp_present_recent", "/usr/local/bin/helper",
			[]string{SignalRecentTargetMtime7d}, []string{SignalInterpreterInTmp, SignalExecTargetOrphan}},
		{"relative", "agent", nil, []string{SignalInterpreterInTmp, SignalExecTargetOrphan}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := PayloadExecSignals(tc.target, resolve, now)
			for _, w := range tc.want {
				if !hasSig(got, w) {
					t.Errorf("target %q: want signal %q, got %v", tc.target, w, got)
				}
			}
			for _, a := range tc.absent {
				if hasSig(got, a) {
					t.Errorf("target %q: signal %q should be absent, got %v", tc.target, a, got)
				}
			}
		})
	}
}

func TestAnnotatePayloadExec(t *testing.T) {
	root := t.TempDir()
	resolve := func(p string) string { return filepath.Join(root, p) }
	now := time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)

	// A benign init script sourcing a packaged helper that exists: must NOT
	// promote (ExecTarget stays the file, no signals added).
	pkgHelper := filepath.Join(root, "lib", "lsb", "init-functions")
	if err := os.MkdirAll(filepath.Dir(pkgHelper), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pkgHelper, []byte("# lsb\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("tmp_payload_promotes", func(t *testing.T) {
		rec := &Record{ExecTarget: "/etc/init.d/ops-cache", Signals: []string{"non_package_path"}}
		body := []byte("#!/bin/sh\n/tmp/.sysv/agent &\n")
		if !AnnotatePayloadExec(rec, body, resolve, now, 1<<20) {
			t.Fatal("expected promotion for a /tmp payload")
		}
		if rec.ExecTarget != "/tmp/.sysv/agent" {
			t.Errorf("ExecTarget: got %q, want /tmp/.sysv/agent", rec.ExecTarget)
		}
		if !hasSig(rec.Signals, SignalInterpreterInTmp) || !hasSig(rec.Signals, SignalExecTargetOrphan) {
			t.Errorf("want interpreter_in_tmp + exec_target_orphan, got %v", rec.Signals)
		}
		if !hasSig(rec.Signals, "non_package_path") {
			t.Errorf("pre-existing signal dropped: %v", rec.Signals)
		}
	})

	t.Run("benign_source_does_not_promote", func(t *testing.T) {
		rec := &Record{ExecTarget: "/etc/init.d/skeleton", Signals: []string{"recent_mtime_7d"}}
		body := []byte("#!/bin/sh\n. /lib/lsb/init-functions\nstart() { :; }\n")
		if AnnotatePayloadExec(rec, body, resolve, now, 1<<20) {
			t.Fatal("benign packaged source must not promote")
		}
		if rec.ExecTarget != "/etc/init.d/skeleton" {
			t.Errorf("ExecTarget changed on benign script: %q", rec.ExecTarget)
		}
		if hasSig(rec.Signals, SignalInterpreterInTmp) || hasSig(rec.Signals, SignalExecTargetOrphan) {
			t.Errorf("benign script gained exec-target signals: %v", rec.Signals)
		}
	})

	t.Run("non_tmp_orphan_does_not_promote", func(t *testing.T) {
		rec := &Record{ExecTarget: "/var/spool/at/job", Signals: nil}
		body := []byte("/usr/local/bin/check-mail --once\n")
		if AnnotatePayloadExec(rec, body, resolve, now, 1<<20) {
			t.Fatal("non-tmp orphan must not promote (FP economics)")
		}
		if rec.ExecTarget != "/var/spool/at/job" {
			t.Errorf("ExecTarget changed on non-tmp orphan: %q", rec.ExecTarget)
		}
	})
}
