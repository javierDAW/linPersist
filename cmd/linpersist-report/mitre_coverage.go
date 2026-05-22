package main

import (
	_ "embed"
	"fmt"
	"sort"
	"strings"

	"github.com/jarmidaw/linpersist/internal/core"
	"gopkg.in/yaml.v3"
)

// matrix.yaml is the source of truth for MITRE ATT&CK Linux
// persistence coverage. The reporter embeds a copy so the panel
// is available even when the binary is run far from the repo
// (operator deployments). The `make all` target validates that
// the embedded copy matches the canonical matrix.yaml in the
// repo root.
//
//go:embed assets/matrix.yaml
var embeddedMatrixYAML []byte

// matrixEntryYAML mirrors the matrix.yaml entry shape that this
// panel cares about. matrix-audit reads `module`, `site_class`,
// `status`; the panel additionally reads `mitre` (the list of
// ATT&CK IDs declared as covered).
type matrixEntryYAML struct {
	SiteClass string   `yaml:"site_class"`
	Module    string   `yaml:"module"`
	Status    string   `yaml:"status"`
	MITRE     []string `yaml:"mitre"`
}

type matrixFileYAML struct {
	SiteClasses []matrixEntryYAML `yaml:"site_classes"`
}

// MITRE panel row status constants. surfacing means the technique
// has at least one live record; the two dormant variants subdivide
// "no records observed":
//   - dormantModuleSilent: none of the modules covering the technique
//     emitted ANY record in the dataset, so the site_class simply
//     does not apply to this fleet shape (e.g. grub/xdg in container
//     fleets). This is dormant-by-environment, not a coverage gap.
//   - dormantCoverageGap: at least one covering module is active
//     elsewhere in the dataset, yet no record carries this MITRE ID.
//     This is the operationally interesting case — module pulls
//     records, but the specific persistence vector this technique
//     describes is not being exercised. Either the fleet truly has
//     no such artifact, or the module's MITRE tagging needs review.
const (
	statusSurfacing           = "surfacing"
	statusDormantModuleSilent = "dormant_module_silent"
	statusDormantCoverageGap  = "dormant_coverage_gap"
)

// MITRECoverageRow is one row of the coverage panel. One row per
// distinct technique ID declared in matrix.yaml.
type MITRECoverageRow struct {
	TechniqueID string   // canonical ATT&CK ID, e.g. T1053.003
	SiteClasses []string // matrix.yaml site_classes that claim coverage
	Modules     []string // distinct modules covering the technique (deduped from SiteClasses)
	Hosts       int      // distinct hosts that emitted at least one record with this MITRE ID
	Records     int      // total records with this MITRE ID
	Status      string   // surfacing | dormant_module_silent | dormant_coverage_gap
}

// MITRECoverageSection holds the whole panel. Sortable summary at
// the head; full table in Rows.
type MITRECoverageSection struct {
	TotalTechniques     int // distinct MITRE IDs declared in matrix.yaml
	SurfacingTechniques int // techniques with at least one record in the dataset
	DormantTechniques   int // sum of the two dormant variants (kept for back-compat / brevity)
	DormantModuleSilent int // covering modules emitted nothing fleet-wide
	DormantCoverageGap  int // covering modules active, but no record carries this technique ID
	Rows                []MITRECoverageRow
}

// computeMITRECoverage parses the embedded matrix.yaml, indexes
// the records by MITRE technique ID, and produces the panel
// data. The function tolerates a missing or malformed
// matrix.yaml by returning an empty MITRECoverageSection with
// no error -- the panel will simply render an empty header in
// that case rather than crashing the rest of the report.
func computeMITRECoverage(records []core.Record) MITRECoverageSection {
	var mf matrixFileYAML
	if err := yaml.Unmarshal(embeddedMatrixYAML, &mf); err != nil {
		return MITRECoverageSection{}
	}

	// Build technique -> site_classes and technique -> modules indexes
	// from matrix.yaml. Modules dedup across multiple site_classes that
	// share the same technique ID (e.g. T1542.003 is covered by both
	// kernel.grub and kernel.grub.dropin under the same `grub` module).
	techSites := map[string]map[string]struct{}{}
	techMods := map[string]map[string]struct{}{}
	for _, e := range mf.SiteClasses {
		for _, id := range e.MITRE {
			id = strings.TrimSpace(id)
			if id == "" || id == "TBD" {
				continue
			}
			if techSites[id] == nil {
				techSites[id] = map[string]struct{}{}
			}
			techSites[id][e.SiteClass] = struct{}{}
			if techMods[id] == nil {
				techMods[id] = map[string]struct{}{}
			}
			if e.Module != "" {
				techMods[id][e.Module] = struct{}{}
			}
		}
	}

	// Build technique -> hosts/records index from live records.
	techHosts := map[string]map[string]struct{}{}
	techRecords := map[string]int{}
	// activeModules is the set of modules with at least one live record
	// in the dataset. Used to distinguish dormant_module_silent (the
	// covering module emitted nothing fleet-wide) from
	// dormant_coverage_gap (covering module active elsewhere but no
	// record carries the technique ID).
	activeModules := map[string]struct{}{}
	for _, r := range records {
		if r.Module != "" {
			activeModules[r.Module] = struct{}{}
		}
		for _, id := range r.MITRE {
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			if techHosts[id] == nil {
				techHosts[id] = map[string]struct{}{}
			}
			techHosts[id][r.HostID] = struct{}{}
			techRecords[id]++
		}
	}

	out := MITRECoverageSection{}
	for tech, sites := range techSites {
		sc := make([]string, 0, len(sites))
		for s := range sites {
			sc = append(sc, s)
		}
		sort.Strings(sc)

		mods := make([]string, 0, len(techMods[tech]))
		for m := range techMods[tech] {
			mods = append(mods, m)
		}
		sort.Strings(mods)

		hosts := len(techHosts[tech])
		recs := techRecords[tech]
		var status string
		switch {
		case recs > 0:
			status = statusSurfacing
			out.SurfacingTechniques++
		default:
			// Dormant. Distinguish module-silent from coverage-gap by
			// asking whether ANY covering module emitted records.
			anyActive := false
			for m := range techMods[tech] {
				if _, ok := activeModules[m]; ok {
					anyActive = true
					break
				}
			}
			if anyActive {
				status = statusDormantCoverageGap
				out.DormantCoverageGap++
			} else {
				status = statusDormantModuleSilent
				out.DormantModuleSilent++
			}
			out.DormantTechniques++
		}
		out.Rows = append(out.Rows, MITRECoverageRow{
			TechniqueID: tech,
			SiteClasses: sc,
			Modules:     mods,
			Hosts:       hosts,
			Records:     recs,
			Status:      status,
		})
	}
	out.TotalTechniques = len(out.Rows)

	// Sort: surfacing first (descending records), then dormant. Within
	// dormant: coverage_gap before module_silent (gaps are operationally
	// more interesting). Stable secondary sort by technique ID for
	// determinism.
	sort.Slice(out.Rows, func(i, j int) bool {
		ri, rj := out.Rows[i], out.Rows[j]
		if ri.Status != rj.Status {
			return statusRank(ri.Status) < statusRank(rj.Status)
		}
		if ri.Status == statusSurfacing {
			if ri.Records != rj.Records {
				return ri.Records > rj.Records
			}
		}
		return ri.TechniqueID < rj.TechniqueID
	})

	return out
}

// statusRank assigns an order to status values for sorting:
// surfacing (0) < dormant_coverage_gap (1) < dormant_module_silent (2).
// Unknown values sort last.
func statusRank(s string) int {
	switch s {
	case statusSurfacing:
		return 0
	case statusDormantCoverageGap:
		return 1
	case statusDormantModuleSilent:
		return 2
	default:
		return 3
	}
}

// mitreCoverageSummary returns the one-line summary used in the
// Overview block header. Example:
//
//	"15/18 surfacing, 3 dormant (1 gap, 2 silent)"
//
// Or, if no dormant subdivision is present, falls back to the
// concise form.
func mitreCoverageSummary(s MITRECoverageSection) string {
	if s.TotalTechniques == 0 {
		return "(matrix.yaml unavailable)"
	}
	if s.DormantTechniques == 0 {
		return fmt.Sprintf("%d/%d surfacing", s.SurfacingTechniques, s.TotalTechniques)
	}
	return fmt.Sprintf("%d/%d surfacing, %d dormant (%d gap, %d silent)",
		s.SurfacingTechniques, s.TotalTechniques,
		s.DormantTechniques, s.DormantCoverageGap, s.DormantModuleSilent)
}
