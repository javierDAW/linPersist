package main

import (
	"reflect"
	"testing"

	"github.com/jarmidaw/linpersist/internal/core"
)

// diffRec builds a Record minimal enough for the diff to consume.
// host_id, module, site_class, locus form the identity tuple;
// content_norm distinguishes Δ from =. Other fields are zero.
func diffRec(hostID, module, locus, contentNorm string) core.Record {
	return core.Record{
		HostID:            hostID,
		Module:            module,
		SiteClass:         module + ".d",
		Locus:             locus,
		ContentNormSHA256: contentNorm,
	}
}

// TestComputeDiff_NoChanges is the smoke baseline: prev byte-equal
// to curr -> zero diff entries, UnchangedCount equals the number of
// distinct identities.
func TestComputeDiff_NoChanges(t *testing.T) {
	records := []core.Record{
		diffRec("h1", "cron", "/etc/cron.d/a", "hash-a"),
		diffRec("h2", "cron", "/etc/cron.d/a", "hash-a"),
		diffRec("h1", "pam", "/etc/pam.d/sshd", "hash-pam"),
	}
	ds := ComputeDiff(records, records)
	if len(ds.Added) != 0 || len(ds.Removed) != 0 || len(ds.Changed) != 0 {
		t.Fatalf("expected zero changes, got +%d -%d Δ%d",
			len(ds.Added), len(ds.Removed), len(ds.Changed))
	}
	if ds.UnchangedCount != 3 {
		t.Errorf("UnchangedCount: got %d, want 3", ds.UnchangedCount)
	}
	if len(ds.HostsAppeared) != 0 || len(ds.HostsDisappeared) != 0 {
		t.Errorf("host churn must be empty for identical inputs")
	}
}

// TestComputeDiff_RecordAdded exercises the + classification: a
// record exists in curr at an identity the prev set never had.
func TestComputeDiff_RecordAdded(t *testing.T) {
	prev := []core.Record{
		diffRec("h1", "cron", "/etc/cron.d/a", "hash-a"),
	}
	curr := []core.Record{
		diffRec("h1", "cron", "/etc/cron.d/a", "hash-a"),
		diffRec("h1", "cron", "/etc/cron.d/b", "hash-b"), // new
	}
	ds := ComputeDiff(prev, curr)
	if len(ds.Added) != 1 {
		t.Fatalf("Added: got %d, want 1: %+v", len(ds.Added), ds.Added)
	}
	if ds.Added[0].Locus != "/etc/cron.d/b" {
		t.Errorf("Added[0].Locus: got %q, want /etc/cron.d/b", ds.Added[0].Locus)
	}
	if len(ds.Removed) != 0 || len(ds.Changed) != 0 {
		t.Errorf("only Added expected, got -%d Δ%d", len(ds.Removed), len(ds.Changed))
	}
}

// TestComputeDiff_RecordRemoved exercises the - classification.
func TestComputeDiff_RecordRemoved(t *testing.T) {
	prev := []core.Record{
		diffRec("h1", "cron", "/etc/cron.d/a", "hash-a"),
		diffRec("h1", "cron", "/etc/cron.d/b", "hash-b"), // will vanish
	}
	curr := []core.Record{
		diffRec("h1", "cron", "/etc/cron.d/a", "hash-a"),
	}
	ds := ComputeDiff(prev, curr)
	if len(ds.Removed) != 1 {
		t.Fatalf("Removed: got %d, want 1: %+v", len(ds.Removed), ds.Removed)
	}
	if ds.Removed[0].Locus != "/etc/cron.d/b" {
		t.Errorf("Removed[0].Locus: got %q, want /etc/cron.d/b", ds.Removed[0].Locus)
	}
	if len(ds.Added) != 0 || len(ds.Changed) != 0 {
		t.Errorf("only Removed expected, got +%d Δ%d", len(ds.Added), len(ds.Changed))
	}
}

// TestComputeDiff_RecordChanged exercises Δ: same identity, distinct
// content_norm.
func TestComputeDiff_RecordChanged(t *testing.T) {
	prev := []core.Record{
		diffRec("h1", "cron", "/etc/cron.d/a", "hash-old"),
	}
	curr := []core.Record{
		diffRec("h1", "cron", "/etc/cron.d/a", "hash-new"),
	}
	ds := ComputeDiff(prev, curr)
	if len(ds.Changed) != 1 {
		t.Fatalf("Changed: got %d, want 1: %+v", len(ds.Changed), ds.Changed)
	}
	pair := ds.Changed[0]
	if pair.Prev.ContentNormSHA256 != "hash-old" || pair.Curr.ContentNormSHA256 != "hash-new" {
		t.Errorf("Changed pair hashes: prev=%q curr=%q",
			pair.Prev.ContentNormSHA256, pair.Curr.ContentNormSHA256)
	}
	if len(ds.Added) != 0 || len(ds.Removed) != 0 {
		t.Errorf("only Changed expected, got +%d -%d", len(ds.Added), len(ds.Removed))
	}
}

// TestComputeDiff_HostDisappeared verifies the host-level row
// suppresses individual `-` entries when the entire host vanishes.
func TestComputeDiff_HostDisappeared(t *testing.T) {
	prev := []core.Record{
		diffRec("h1", "cron", "/etc/cron.d/a", "hash-a"),
		diffRec("h2", "cron", "/etc/cron.d/a", "hash-a"),
		diffRec("h2", "pam", "/etc/pam.d/sshd", "hash-pam"),
		diffRec("h2", "ssh", "/etc/ssh/sshd_config", "hash-ssh"),
	}
	// h2 entirely absent in curr.
	curr := []core.Record{
		diffRec("h1", "cron", "/etc/cron.d/a", "hash-a"),
	}
	ds := ComputeDiff(prev, curr)

	if len(ds.HostsDisappeared) != 1 {
		t.Fatalf("HostsDisappeared: got %d, want 1: %+v", len(ds.HostsDisappeared), ds.HostsDisappeared)
	}
	hc := ds.HostsDisappeared[0]
	if hc.HostID != "h2" {
		t.Errorf("HostsDisappeared[0].HostID: got %q, want h2", hc.HostID)
	}
	if hc.RecordCount != 3 {
		t.Errorf("HostsDisappeared[0].RecordCount: got %d, want 3", hc.RecordCount)
	}
	if len(ds.Removed) != 0 {
		t.Errorf("per-record Removed must be empty (suppressed): got %+v", ds.Removed)
	}
}

// TestComputeDiff_HostAppeared mirrors the host-level case for
// new hosts.
func TestComputeDiff_HostAppeared(t *testing.T) {
	prev := []core.Record{
		diffRec("h1", "cron", "/etc/cron.d/a", "hash-a"),
	}
	curr := []core.Record{
		diffRec("h1", "cron", "/etc/cron.d/a", "hash-a"),
		diffRec("h-new", "cron", "/etc/cron.d/a", "hash-a"),
		diffRec("h-new", "pam", "/etc/pam.d/sshd", "hash-pam"),
	}
	ds := ComputeDiff(prev, curr)

	if len(ds.HostsAppeared) != 1 {
		t.Fatalf("HostsAppeared: got %d, want 1: %+v", len(ds.HostsAppeared), ds.HostsAppeared)
	}
	hc := ds.HostsAppeared[0]
	if hc.HostID != "h-new" {
		t.Errorf("HostsAppeared[0].HostID: got %q, want h-new", hc.HostID)
	}
	if hc.RecordCount != 2 {
		t.Errorf("HostsAppeared[0].RecordCount: got %d, want 2", hc.RecordCount)
	}
	if len(ds.Added) != 0 {
		t.Errorf("per-record Added must be empty (suppressed): got %+v", ds.Added)
	}
}

// TestComputeDiff_PrevEmpty: prev is the empty set, curr has hosts.
// Every host should land in HostsAppeared, no individual + entries.
func TestComputeDiff_PrevEmpty(t *testing.T) {
	curr := []core.Record{
		diffRec("h1", "cron", "/etc/cron.d/a", "hash-a"),
		diffRec("h2", "pam", "/etc/pam.d/sshd", "hash-pam"),
	}
	ds := ComputeDiff(nil, curr)

	if len(ds.HostsAppeared) != 2 {
		t.Fatalf("HostsAppeared: got %d, want 2 (h1, h2): %+v",
			len(ds.HostsAppeared), ds.HostsAppeared)
	}
	if len(ds.Added) != 0 {
		t.Errorf("Added must be empty (all suppressed via host-level): %+v", ds.Added)
	}
}

// TestComputeDiff_CurrEmpty: the symmetrical case.
func TestComputeDiff_CurrEmpty(t *testing.T) {
	prev := []core.Record{
		diffRec("h1", "cron", "/etc/cron.d/a", "hash-a"),
		diffRec("h2", "pam", "/etc/pam.d/sshd", "hash-pam"),
	}
	ds := ComputeDiff(prev, nil)

	if len(ds.HostsDisappeared) != 2 {
		t.Fatalf("HostsDisappeared: got %d, want 2 (h1, h2): %+v",
			len(ds.HostsDisappeared), ds.HostsDisappeared)
	}
	if len(ds.Removed) != 0 {
		t.Errorf("Removed must be empty: %+v", ds.Removed)
	}
}

// TestComputeDiff_Determinism runs the same inputs twice and
// requires byte-identical DiffSets. Critical for downstream tools
// that diff the diff output (e.g. cron jobs that alert on changes
// across two consecutive comparisons).
func TestComputeDiff_Determinism(t *testing.T) {
	prev := []core.Record{
		diffRec("h2", "pam", "/etc/pam.d/sshd", "hash-pam"),
		diffRec("h1", "cron", "/etc/cron.d/a", "hash-a"),
		diffRec("h1", "cron", "/etc/cron.d/b", "hash-b-old"),
	}
	curr := []core.Record{
		diffRec("h1", "cron", "/etc/cron.d/b", "hash-b-new"),
		diffRec("h2", "pam", "/etc/pam.d/sshd", "hash-pam"),
		diffRec("h1", "cron", "/etc/cron.d/c", "hash-c"),
	}
	ds1 := ComputeDiff(prev, curr)
	ds2 := ComputeDiff(prev, curr)
	if !reflect.DeepEqual(ds1, ds2) {
		t.Fatalf("non-deterministic diff:\n  ds1=%+v\n  ds2=%+v", ds1, ds2)
	}
}

// TestComputeDiff_MixedScenario combines all classifications in
// one set. Belt-and-braces for the interaction of host-level and
// per-record paths.
func TestComputeDiff_MixedScenario(t *testing.T) {
	prev := []core.Record{
		// h1: kept, one record changes hash.
		diffRec("h1", "cron", "/etc/cron.d/a", "hash-a"),
		diffRec("h1", "cron", "/etc/cron.d/b", "hash-b-old"),
		// h2: disappears entirely.
		diffRec("h2", "pam", "/etc/pam.d/sshd", "hash-pam"),
		diffRec("h2", "ssh", "/etc/ssh/sshd_config", "hash-ssh"),
	}
	curr := []core.Record{
		// h1: a kept, b changed, c new.
		diffRec("h1", "cron", "/etc/cron.d/a", "hash-a"),
		diffRec("h1", "cron", "/etc/cron.d/b", "hash-b-new"),
		diffRec("h1", "cron", "/etc/cron.d/c", "hash-c"),
		// h3: new host entirely.
		diffRec("h3", "cron", "/etc/cron.d/a", "hash-a"),
	}
	ds := ComputeDiff(prev, curr)

	if len(ds.Added) != 1 || ds.Added[0].Locus != "/etc/cron.d/c" {
		t.Errorf("Added: want 1 entry for /etc/cron.d/c, got %+v", ds.Added)
	}
	if len(ds.Removed) != 0 {
		t.Errorf("Removed: want 0 (h2 records suppressed by host-level), got %+v", ds.Removed)
	}
	if len(ds.Changed) != 1 {
		t.Errorf("Changed: want 1 for /etc/cron.d/b, got %+v", ds.Changed)
	}
	if len(ds.HostsDisappeared) != 1 || ds.HostsDisappeared[0].HostID != "h2" {
		t.Errorf("HostsDisappeared: want [h2], got %+v", ds.HostsDisappeared)
	}
	if len(ds.HostsAppeared) != 1 || ds.HostsAppeared[0].HostID != "h3" {
		t.Errorf("HostsAppeared: want [h3], got %+v", ds.HostsAppeared)
	}
	if ds.UnchangedCount != 1 {
		t.Errorf("UnchangedCount: want 1 (h1's /etc/cron.d/a), got %d", ds.UnchangedCount)
	}
}
