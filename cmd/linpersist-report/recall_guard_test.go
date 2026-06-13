package main

import "testing"

// Recall regression guard, reproducible from the shipped tree (the nspawn
// lab lives off-main). A committed fixture carries the canonical implant
// signal-sets; this asserts the report's Q7 pipeline still fires the
// expected detection on each. Pairs with the module unit tests (which guard
// that the collectors EMIT these signals) to cover the full recall path —
// e.g. the Class-A escalation (sysv/motd/netdispatch/atjobs /tmp payload ->
// payload_under_tmp_via_persistence) cannot silently regress without one of
// these gates failing.
func TestRecallGuardQ7(t *testing.T) {
	res, err := load("testdata/recall_fleet.ndjson")
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	report := build(res.Records, res.Files, res.Skipped, "test", 3)
	fired := map[string]bool{}
	maxSev := map[string]string{}
	for _, row := range report.Q7ImplantRollCall {
		for _, d := range row.MatchedDetections {
			fired[d] = true
			maxSev[d] = row.MaxSeverity
		}
	}
	want := []string{
		"payload_under_tmp_via_persistence", // Class-A escalation
		"suid_binary_outside_package_path",
		"reverse_shell_in_persistence",
		"second_uid_zero_account",
		"trap_handler_payload_in_tmp",
		"persistence_fetch_piped_to_shell",
		"sudoers_nopasswd_all_recent", // critical freshness escalation (re-gate)
	}
	for _, w := range want {
		if !fired[w] {
			t.Errorf("RECALL REGRESSION: rule %q did not fire in Q7", w)
		}
	}
	// The fresh sudoers grant must escalate to critical (the re-gate design).
	if s := maxSev["sudoers_nopasswd_all_recent"]; s != "critical" {
		t.Errorf("sudoers_nopasswd_all_recent severity = %q, want critical", s)
	}
}
