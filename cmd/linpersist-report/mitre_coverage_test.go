package main

import (
	"testing"

	"github.com/jarmidaw/linpersist/internal/core"
)

// TestMITRECoverage_EmptyDataset confirms the zero-input contract: no
// records means every technique is dormant_module_silent (no module
// emitted anything, so the site_class does not apply at all).
func TestMITRECoverage_EmptyDataset(t *testing.T) {
	got := computeMITRECoverage(nil)
	if got.TotalTechniques == 0 {
		t.Fatal("expected TotalTechniques > 0 (matrix.yaml should embed)")
	}
	if got.SurfacingTechniques != 0 {
		t.Errorf("SurfacingTechniques: got %d, want 0", got.SurfacingTechniques)
	}
	if got.DormantTechniques != got.TotalTechniques {
		t.Errorf("DormantTechniques (%d) should equal TotalTechniques (%d) with no records",
			got.DormantTechniques, got.TotalTechniques)
	}
	if got.DormantModuleSilent != got.DormantTechniques {
		t.Errorf("with no records, every dormant should be module_silent, got %d/%d module_silent",
			got.DormantModuleSilent, got.DormantTechniques)
	}
	if got.DormantCoverageGap != 0 {
		t.Errorf("DormantCoverageGap: got %d, want 0 (no module is active)", got.DormantCoverageGap)
	}
	// Every row must carry the module_silent status.
	for _, r := range got.Rows {
		if r.Status != statusDormantModuleSilent {
			t.Errorf("row %s: status %q, want %q", r.TechniqueID, r.Status, statusDormantModuleSilent)
		}
	}
}

// TestMITRECoverage_CoverageGapVsModuleSilent activates one module
// (cron) WITHOUT any of its MITRE IDs on the record. Cron's matrix
// techniques (T1053.003 / T1053.006) should become coverage_gap (the
// module is active, but no record carries the technique ID). All other
// modules remain silent, so their techniques stay module_silent.
func TestMITRECoverage_CoverageGapVsModuleSilent(t *testing.T) {
	// One synthetic cron record without MITRE — enough to mark the
	// cron module "active" for the panel's purposes.
	records := []core.Record{
		{
			HostID:    "h1",
			Module:    "cron",
			SiteClass: "cron.d",
			Locus:     "/etc/cron.d/test",
			// Empty MITRE: simulates a record where the module ran
			// but the technique tagging is missing — exactly the
			// coverage_gap diagnostic case.
		},
	}
	got := computeMITRECoverage(records)
	if got.SurfacingTechniques != 0 {
		t.Errorf("SurfacingTechniques: got %d, want 0", got.SurfacingTechniques)
	}
	if got.DormantCoverageGap == 0 {
		t.Error("DormantCoverageGap: got 0, want >= 1 (cron is active but emits no T1053.* records)")
	}

	// T1053.003 is covered by the `cron` module (cron.d / cron.user / etc.)
	// — with a cron record present it must flip to coverage_gap.
	// T1053.006, despite the sibling MITRE ID, is covered by `systemd`
	// (systemd.timer). With NO systemd record in the dataset it must stay
	// module_silent — that asymmetry is precisely the panel signal the
	// sub-categorization is meant to surface.
	foundT1053003 := false
	for _, r := range got.Rows {
		if r.TechniqueID == "T1053.003" {
			foundT1053003 = true
			if r.Status != statusDormantCoverageGap {
				t.Errorf("T1053.003 (cron) should be coverage_gap, got %q (modules=%v)",
					r.Status, r.Modules)
			}
		}
		if r.TechniqueID == "T1053.006" {
			if r.Status != statusDormantModuleSilent {
				t.Errorf("T1053.006 (systemd.timer) should be module_silent when no systemd records present, got %q (modules=%v)",
					r.Status, r.Modules)
			}
		}
	}
	if !foundT1053003 {
		t.Fatal("matrix.yaml should declare T1053.003 under cron")
	}

	// Spot-check: a technique whose module is NOT in records remains
	// module_silent. xdg is reliably absent from the synthetic dataset.
	for _, r := range got.Rows {
		if r.TechniqueID == "T1547.013" {
			if r.Status != statusDormantModuleSilent {
				t.Errorf("T1547.013 should be module_silent (no xdg records present), got %q", r.Status)
			}
		}
	}
}

// TestMITRECoverage_SurfacingRecord confirms a record carrying a MITRE
// ID promotes the technique to surfacing and credits the host count.
func TestMITRECoverage_SurfacingRecord(t *testing.T) {
	records := []core.Record{
		{
			HostID:    "h1",
			Module:    "cron",
			SiteClass: "cron.d",
			Locus:     "/etc/cron.d/test",
			MITRE:     []string{"T1053.003"},
		},
		{
			HostID:    "h2",
			Module:    "cron",
			SiteClass: "cron.d",
			Locus:     "/etc/cron.d/test",
			MITRE:     []string{"T1053.003"},
		},
	}
	got := computeMITRECoverage(records)
	if got.SurfacingTechniques == 0 {
		t.Fatal("SurfacingTechniques: got 0, want >= 1")
	}
	var found *MITRECoverageRow
	for i := range got.Rows {
		if got.Rows[i].TechniqueID == "T1053.003" {
			found = &got.Rows[i]
			break
		}
	}
	if found == nil {
		t.Fatal("T1053.003 row not found")
	}
	if found.Status != statusSurfacing {
		t.Errorf("status: got %q, want %q", found.Status, statusSurfacing)
	}
	if found.Records != 2 {
		t.Errorf("Records: got %d, want 2", found.Records)
	}
	if found.Hosts != 2 {
		t.Errorf("Hosts: got %d, want 2", found.Hosts)
	}
}

// TestMITRECoverageSummary_Format checks the one-line summary string
// produced for the Overview block. With dormants present the format
// must include the gap/silent breakdown.
func TestMITRECoverageSummary_Format(t *testing.T) {
	s := MITRECoverageSection{
		TotalTechniques:     18,
		SurfacingTechniques: 15,
		DormantTechniques:   3,
		DormantCoverageGap:  1,
		DormantModuleSilent: 2,
	}
	got := mitreCoverageSummary(s)
	want := "15/18 surfacing, 3 dormant (1 gap, 2 silent)"
	if got != want {
		t.Errorf("summary: got %q, want %q", got, want)
	}

	// All-surfacing case skips the dormant clause.
	s2 := MITRECoverageSection{
		TotalTechniques:     5,
		SurfacingTechniques: 5,
	}
	got2 := mitreCoverageSummary(s2)
	want2 := "5/5 surfacing"
	if got2 != want2 {
		t.Errorf("summary all-surfacing: got %q, want %q", got2, want2)
	}

	// Empty matrix case.
	got3 := mitreCoverageSummary(MITRECoverageSection{})
	want3 := "(matrix.yaml unavailable)"
	if got3 != want3 {
		t.Errorf("summary empty: got %q, want %q", got3, want3)
	}
}
