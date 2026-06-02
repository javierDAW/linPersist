package main

import (
	"testing"

	"github.com/jarmidaw/linpersist/internal/core"
)

// TestComputeQ6ExcludesPackageBaseline guards the q6Suspicious filter:
// a packaged exec_target shared across hosts (baseline) must NOT surface
// in Q6, while a non-package payload shared across hosts (worm) must.
// Reverting q6Suspicious to `return true` floods Q6 with baseline and
// fails this test.
func TestComputeQ6ExcludesPackageBaseline(t *testing.T) {
	r := func(host, sha string, sigs ...string) core.Record {
		return core.Record{HostID: host, Module: "cron", ExecTargetSHA256: sha, Signals: sigs}
	}
	recs := []core.Record{
		r("h1", "pkgsha"), r("h2", "pkgsha"), // packaged, no anomaly signal -> baseline, excluded
		r("h1", "wormsha", core.SignalNonPackagePath),
		r("h2", "wormsha", core.SignalNonPackagePath), // non-package worm -> included
	}
	got := computeQ6(recs)
	if len(got) != 1 {
		t.Fatalf("Q6 rows = %d, want 1 (only the non-package worm); rows=%v", len(got), got)
	}
	if got[0].ExecTargetSHA256 != shortHash("wormsha") {
		t.Errorf("Q6 surfaced %q, want the worm sha", got[0].ExecTargetSHA256)
	}

	if q6Suspicious(nil) || q6Suspicious([]string{core.SignalRecentMtime7d}) {
		t.Error("baseline signals must not be q6Suspicious")
	}
	if !q6Suspicious([]string{core.SignalExecTargetOrphan}) {
		t.Error("exec_target_orphan must be q6Suspicious")
	}
}

// TestComputeQ12ExcludesBaselineCluster guards the q12Suspicious filter:
// a basename shared across modules/hosts with NO anomaly signal (package
// baseline like bash) must NOT surface; one with an anomaly arm (campaign)
// must. Reverting q12Suspicious to `return true` resurfaces the baseline
// wall and fails this test.
func TestComputeQ12ExcludesBaselineCluster(t *testing.T) {
	mk := func(host, mod, exec string, sigs ...string) core.Record {
		return core.Record{HostID: host, Module: mod, ExecTarget: exec, Signals: sigs}
	}
	recs := []core.Record{
		// baseline "bash": 2 modules, 2 hosts, no anomaly -> excluded
		mk("h1", "passwd", "/bin/bash"), mk("h2", "passwd", "/bin/bash"),
		mk("h1", "systemd", "/bin/bash"), mk("h2", "systemd", "/bin/bash"),
		// campaign "payload": 2 modules, 2 hosts, one arm non-package -> included
		mk("h1", "cron", "/x/payload", core.SignalNonPackagePath),
		mk("h2", "cron", "/x/payload"),
		mk("h1", "profile", "/x/payload"), mk("h2", "profile", "/x/payload"),
	}
	got := computeQ12(recs)
	if len(got) != 1 || got[0].Basename != "payload" {
		t.Fatalf("Q12 = %v, want exactly the [payload] campaign (bash baseline excluded)", got)
	}

	if q12Suspicious(nil) || q12Suspicious([]string{core.SignalRecentMtime7d}) {
		t.Error("baseline signals must not be q12Suspicious")
	}
	if !q12Suspicious([]string{core.SignalInterpreterInTmp}) {
		t.Error("interpreter_in_tmp must be q12Suspicious")
	}
}
