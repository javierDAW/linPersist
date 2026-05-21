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

// MITRECoverageRow is one row of the coverage panel. One row per
// distinct technique ID declared in matrix.yaml.
type MITRECoverageRow struct {
	TechniqueID string   // canonical ATT&CK ID, e.g. T1053.003
	SiteClasses []string // matrix.yaml site_classes that claim coverage
	Hosts       int      // distinct hosts that emitted at least one record with this MITRE ID
	Records     int      // total records with this MITRE ID
	Status      string   // "surfacing" (records present) or "dormant" (no records yet)
}

// MITRECoverageSection holds the whole panel. Sortable summary at
// the head; full table in Rows.
type MITRECoverageSection struct {
	TotalTechniques     int // distinct MITRE IDs declared in matrix.yaml
	SurfacingTechniques int // techniques with at least one record in the dataset
	DormantTechniques   int // declared but not yet observed
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

	// Build technique -> site_classes index from matrix.yaml.
	techSites := map[string]map[string]struct{}{}
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
		}
	}

	// Build technique -> hosts/records index from live records.
	techHosts := map[string]map[string]struct{}{}
	techRecords := map[string]int{}
	for _, r := range records {
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
		hosts := len(techHosts[tech])
		recs := techRecords[tech]
		status := "dormant"
		if recs > 0 {
			status = "surfacing"
			out.SurfacingTechniques++
		} else {
			out.DormantTechniques++
		}
		out.Rows = append(out.Rows, MITRECoverageRow{
			TechniqueID: tech,
			SiteClasses: sc,
			Hosts:       hosts,
			Records:     recs,
			Status:      status,
		})
	}
	out.TotalTechniques = len(out.Rows)

	// Sort: surfacing first (descending records), then dormant.
	// Stable secondary sort by technique ID for determinism.
	sort.Slice(out.Rows, func(i, j int) bool {
		ri, rj := out.Rows[i], out.Rows[j]
		if ri.Status != rj.Status {
			return ri.Status == "surfacing" // surfacing before dormant
		}
		if ri.Status == "surfacing" {
			if ri.Records != rj.Records {
				return ri.Records > rj.Records
			}
		}
		return ri.TechniqueID < rj.TechniqueID
	})

	return out
}

// mitreCoverageSummary returns the one-line summary used in the
// Overview block header. Example: "covered 14/22 techniques
// (8 dormant)".
func mitreCoverageSummary(s MITRECoverageSection) string {
	if s.TotalTechniques == 0 {
		return "(matrix.yaml unavailable)"
	}
	return fmt.Sprintf("%d/%d surfacing, %d dormant",
		s.SurfacingTechniques, s.TotalTechniques, s.DormantTechniques)
}
