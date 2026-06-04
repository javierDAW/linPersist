package main

import (
	"sort"
	"strings"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
	"github.com/jarmidaw/linpersist/internal/detections"
)

// detectionRules is the parsed rule set, loaded once at init() so a
// malformed detections.yaml fails the binary at startup rather than
// at first Q7 row. The YAML itself is embedded in the detections
// package; see ADR-0013 for the schema and the release-gate
// mechanics that keep this file in sync with tools/stack_demo.sql.
var detectionRules = detections.MustLoadEmbedded()

// Report is the top-level data passed to the HTML template.
type Report struct {
	Generated    time.Time
	AgentVersion string
	Sources      []string
	SkippedLines int

	Overview Overview

	Q1Singletons          []SingletonRow
	Q2LocusSingletons     []LocusSingletonRow
	Q3PeerGroupSingletons []PeerGroupRow
	// Q4 (orphan+tmp implant fingerprint) is folded out of the HTML tabs
	// (it is a strict subset of the Q7 payload_under_tmp_via_persistence
	// detection — count survives as Overview.OrphanTmpCount, orphan view as
	// the Q9 IsOrphan column). It is RETAINED in the text report and the
	// dossier, and as the Go side of the SQL Q4 equivalence mirror.
	Q4ImplantFingerprint  []ImplantRow
	Q5SignalDistribution  []SignalRow // HTML: an Overview drill-down, not a tab; text: the Q5 section
	Q6ExecTargetStacking  []ExecTargetRow
	Q7ImplantRollCall     []RollCallRow
	Q8MtimeConcentration  []MtimeConcRow
	Q9ExecInTmp           []ExecInTmpRow
	Q10HostCoverage       []HostCoverageRow
	Q11OrphanOutsideTmp   []OrphanOutsideTmpRow
	Q12BasenameClustering []BasenameClusterRow

	// Peer-group (Q3) context surfaced in the report so an empty Q3 reads
	// as "suppressed below floor", not "clean", and so an analyst sees the
	// effective floor.
	PeerFloor            int  // effective --peer-floor
	SuppressedPeerGroups int  // (os_id, tag_set) cohorts below the floor
	QualifyingPeerGroups int  // cohorts at/above the floor (Q3 has material)
	LFATriageOnly        bool // N=1 OR no cohort reaches the floor -> cross-host LFA is triage-only

	MITRECoverage MITRECoverageSection

	// HistogramBuckets is the per-bucket count of (module,
	// content_norm_sha256) groups by how many hosts share them.
	// Buckets: 1 (singleton), 2-4 (rare), 5-9 (uncommon), 10-49,
	// 50-99, >=100. The buckets are emitted as inline SVG.
	HistogramBuckets []HistogramBucket
}

type Overview struct {
	TotalRecords     int
	TotalHosts       int
	TotalModules     int
	TotalSiteClasses int
	ByModule         []NamedCount
	BySiteClass      []NamedCount
	ByOSID           []NamedCount
	BySignal         []NamedCount
	// SeverityCounts is a Q7-scoped tally of records by worst-severity
	// of the detections they matched. Keyed by the canonical severity
	// strings (info / low / medium / high / critical) plus the empty
	// string for records whose matched detections declared no
	// severity. Populated after Q7 is computed (see build()).
	SeverityCounts map[string]int
	// OrphanTmpCount is the Q4 fingerprint count (records with both
	// exec_target_orphan and interpreter_in_tmp) — folded out of its own tab
	// into Q7, kept here as an Overview badge.
	OrphanTmpCount int
	// DegradedHosts lists hosts whose provenance pipeline could not run
	// because no package manager was detected (host_meta.pkg_mgr=="none"
	// or empty) — distroless/from-scratch/appliance images. On these
	// hosts the non_package_path / package_file_tampered gate is BLIND,
	// so every provenance-gated detection is silently weaker. The report
	// surfaces this as a banner so an analyst does not read "0 findings"
	// as "clean" when it actually means "could not verify ownership"
	// (duel-final coherence fix: honest degradation, no silent blind spot).
	DegradedHosts []DegradedHost
}

// DegradedHost names a host with no package-manager provenance.
type DegradedHost struct {
	Host string
	OSID string
}

type NamedCount struct {
	Name    string
	Records int
	Hosts   int
}

type SingletonRow struct {
	Module        string
	SiteClass     string
	ContentNorm   string // shortened to 12 chars for display
	SampleHost    string
	SampleLocus   string
	SampleSnippet string
	// CoIndicators counts the STRONG structural tells on the sample record
	// (non_package_path, package_file_tampered, exec_target_orphan,
	// interpreter_in_tmp, world_writable, immutable/append-only,
	// mount_shadows_path). These are population- AND provisioning-
	// independent, so >0 puts the row in the rung-1 Actionable partition
	// (ADR-0017). recent_mtime/recent_ctime are DELIBERATELY excluded:
	// on a freshly-imaged/provisioned host (WSL, containers, golden
	// images) they fire on nearly every file — the live smoke saw
	// recent_ctime on 64% of records — so promoting on recency would
	// re-create the very flood the ladder exists to prevent.
	CoIndicators int
	// Recency is a SECONDARY rank: the count of recent_{mtime,ctime}_*
	// tells. It never promotes a row to Actionable (see above), but within
	// the Informational partition a freshly-changed unique file is the
	// likelier implant, so recency floats it up — a per-record temporal
	// hint that needs no history store.
	Recency int
	// Disc is the ADR-0017 discriminator label for the row's site_class,
	// rendered in the rung-4 informational partition: "novelty-only"
	// (provenance structurally inapplicable — no tell was ever possible)
	// or "no-tell" (a structural tell could have fired and did not).
	Disc string
}

type LocusSingletonRow struct {
	Module        string
	SiteClass     string
	Locus         string
	ContentNorm   string
	SampleHost    string
	SampleSnippet string
}

type PeerGroupRow struct {
	OSID          string
	TagKey        string // ADR-0015: canonical tag set, "" for untagged peer-group.
	Module        string
	SiteClass     string
	ContentNorm   string
	HostsInOS     int // hosts in the peer-group (os_id + tagKey).
	PeerSize      int
	SampleHost    string
	SampleLocus   string
	SampleSnippet string
}

type ImplantRow struct {
	Host       string
	Module     string
	SiteClass  string
	Locus      string
	ExecTarget string
	Signals    []string
	Snippet    string
}

type SignalRow struct {
	Module  string
	Signal  string
	Hosts   int
	Records int
}

type ExecTargetRow struct {
	ExecTargetSHA256 string
	Hosts            int
	Records          int
	Modules          int
	SiteClasses      int
	SampleTarget     string
	SpreadModules    []string
}

// RollCallRow is one row of Q7: implant roll-call. The detection
// clauses are loaded from detections.yaml; MatchedDetections lists
// every detection id that fired on this record so the analyst can
// map the row to the rule without re-deriving it from triage_signals.
// MaxSeverity is the worst severity across the matched detections
// (ordering: critical > high > medium > low > info > unspecified),
// used to drive the row pill in HTML and the row prefix in text.
type RollCallRow struct {
	Host              string
	Module            string
	SiteClass         string
	Locus             string
	ExecTarget        string
	TriageSignals     []string
	MatchedDetections []string
	MaxSeverity       string
	Snippet           string
}

// severityRank orders severity strings for "worst-wins" reductions.
// Higher number == more severe. Unknown / unspecified severities map
// to 0 so they never win against a declared severity.
var severityRank = map[string]int{
	"info":     1,
	"low":      2,
	"medium":   3,
	"high":     4,
	"critical": 5,
}

// severityByDetectionID is precomputed at package init() from the
// loaded rule set so worstSeverity is O(N) over its input list of IDs
// rather than O(N×M) over (input IDs × all known detections). The map
// is read-only after init and safe to share across goroutines.
var severityByDetectionID = func() map[string]string {
	out := make(map[string]string, len(detectionRules.Detections))
	for i := range detectionRules.Detections {
		d := &detectionRules.Detections[i]
		out[d.ID] = d.Severity
	}
	return out
}()

// worstSeverity returns the highest-ranked severity in ids by looking
// each id up in the loaded rule set. Returns "" if no id has a
// recognised severity (treated as "unspecified" by callers).
func worstSeverity(ids []string) string {
	best := ""
	bestRank := 0
	for _, id := range ids {
		sev, ok := severityByDetectionID[id]
		if !ok {
			continue
		}
		if r, ok := severityRank[sev]; ok && r > bestRank {
			best = sev
			bestRank = r
		}
	}
	return best
}

// MtimeConcRow is one row of Q8: recent-mtime concentration per
// (host, module). Spikes mean "something rewrote a lot of config on
// this host in the last 7 days".
type MtimeConcRow struct {
	Host          string
	Module        string
	RecentRecords int
	RecentLoci    int
}

// ExecInTmpRow is one row of Q9: exec_target in /tmp, /var/tmp,
// /dev/shm, /run/shm. Complements Q4 by surfacing armed implants
// whose payload IS currently on disk (no orphan signal).
//
// Calibration (ADR-0014): exec_target is "the binary the persistence
// INVOKES", not "the path the directive touches". Modules whose
// directives touch a path without executing it (systemd.tmpfiles)
// or that act as marker-only enablement points (systemd.linger,
// systemd.sysusers) MUST leave ExecTarget empty so Q9 does not get
// polluted with the targets they merely manipulate.
type ExecInTmpRow struct {
	Host       string
	Module     string
	SiteClass  string
	Locus      string
	ExecTarget string
	IsOrphan   bool
	Snippet    string
}

// HostCoverageRow is one row of Q10: per-host collection health
// and coverage outliers. Sort DESC for outliers above the median,
// ASC for collection failures below it.
type HostCoverageRow struct {
	Host          string
	OSID          string
	Records       int
	Modules       int
	SiteClasses   int
	RecentRecords int
	// GapModules lists modules that the rest of the fleet emits (fleet
	// median > 0) but this host emitted ZERO records for — a silent
	// collection-failure / image-gap tell. Empty for a healthy host.
	GapModules []string
}

// BasenameClusterRow is one row of Q12: same basename of
// exec_target (or locus when exec_target is empty), appearing in
// >=2 modules and on >=2 hosts. The query catches multi-arm
// campaigns whose individual arms each surface as a separate Q1
// singleton in a different module -- the v0.2.0 deploy-sync
// example coordinated arms across cron, profile and systemd
// pointing at the same basename.
type BasenameClusterRow struct {
	Basename         string
	Hosts            int
	Modules          []string
	Records          int
	SampleHost       string
	SampleLocus      string
	SampleExecTarget string
}

// OrphanOutsideTmpRow is one row of Q11: exec_target paths flagged as
// non_package_path AND not located under any tmp-class prefix. The
// implant pattern Q4 and Q9 miss entirely (payload dropped under
// /opt/, /var/lib/, /srv/, /usr/local/, etc.). LFA-sorted so
// single-host hits surface first.
type OrphanOutsideTmpRow struct {
	ExecTarget    string
	Hosts         int
	Records       int
	Module        string
	SiteClass     string
	SampleHost    string // first host (lexicographic) that carries the record
	SampleLocus   string
	SampleSnippet string
}

type HistogramBucket struct {
	Label  string
	Count  int
	IsTail bool // singletons get highlighted as the LFA target
}

// hostKey returns the canonical host identifier used to count distinct
// hosts: hostname (when --include-hostname was set on the agent) or
// host_id otherwise. Falls back to "<unknown>" if neither is present.
func hostKey(r core.Record) string {
	if r.HostMeta.Hostname != "" {
		return r.HostMeta.Hostname
	}
	if r.HostID != "" {
		return r.HostID
	}
	return "<unknown>"
}

// shortHash returns the first 12 hex chars of a sha256 string for
// display.
func shortHash(s string) string {
	if len(s) >= 12 {
		return s[:12]
	}
	return s
}

// snippetTrim normalizes a content snippet for display. It collapses
// embedded newlines and tabs to spaces so the snippet renders on a
// single line in column-aligned outputs (tabwriter text mode, HTML
// table rows) and never breaks the surrounding layout.
//
// The maxLen argument is preserved for call-site signature stability
// but is intentionally ignored: an analyst running triage needs the
// full snippet for grep / awk / copy-paste / pasting into a ticket.
// Truncating with "…" was the v0.2.0 behavior and was reverted in
// the polish pass after operator feedback. Columns just get wider.
func snippetTrim(s string, _ int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	return s
}

// build assembles a Report from a flat slice of records.
//
// peerFloor sets the minimum number of hosts required in a peer-group
// for Q3 to consider its rows; values <= 2 reproduce the os_id-only
// era's permissiveness, the default 3 reproduces the v0.3.1 behavior,
// values >= 4 are operator knobs for over-tagged fleets that surface
// many tiny peer-groups (see docs/stacking-cookbook.md, Query 3).
func build(records []core.Record, sources []string, skipped int, agentVersion string, peerFloor int) *Report {
	r := &Report{
		Generated:    time.Now().UTC(),
		AgentVersion: agentVersion,
		Sources:      sources,
		SkippedLines: skipped,
	}
	r.Overview = computeOverview(records)
	r.Q1Singletons = computeQ1(records)
	r.Q2LocusSingletons = computeQ2(records)
	r.Q3PeerGroupSingletons = computeQ3(records, peerFloor)
	r.Q4ImplantFingerprint = computeQ4(records)
	r.Q5SignalDistribution = computeQ5(records)
	r.Q6ExecTargetStacking = computeQ6(records)
	r.Q7ImplantRollCall = computeQ7(records)
	r.Q8MtimeConcentration = computeQ8(records)
	r.Q9ExecInTmp = computeQ9(records)
	r.Q10HostCoverage = computeQ10(records)
	r.Q11OrphanOutsideTmp = computeQ11(records)
	r.Q12BasenameClustering = computeQ12(records)
	r.HistogramBuckets = computeHistogram(records)
	// Severity counts derived from Q7 rows. Lives on Overview rather
	// than Report so the HTML template and text renderer share one
	// access path.
	sevCounts := make(map[string]int, 6)
	for _, row := range r.Q7ImplantRollCall {
		sevCounts[row.MaxSeverity]++
	}
	r.Overview.SeverityCounts = sevCounts
	// Q4 (orphan+tmp fingerprint) badge for the consolidated HTML overview.
	r.Overview.OrphanTmpCount = len(r.Q4ImplantFingerprint)
	// Peer-group cohort sizing for the Q3 empty-state and the LFA-triage-only
	// banner: a fleet with no (os_id, tag_set) cohort at/above the floor has
	// no cross-host comparand, so Q1/Q3 are triage-only (rung-1 Actionable +
	// Q7 still hold — they are population-independent).
	r.PeerFloor = peerFloor
	r.SuppressedPeerGroups, r.QualifyingPeerGroups = peerCohortCounts(records, peerFloor)
	r.LFATriageOnly = r.Overview.TotalHosts <= 1 || r.QualifyingPeerGroups == 0
	r.MITRECoverage = computeMITRECoverage(records)
	return r
}

// peerCohortCounts returns how many (os_id, tag_set) cohorts fall below the
// peer-floor and how many reach it. A cohort with no os_id is ignored
// (computeQ3 skips those records too).
func peerCohortCounts(records []core.Record, peerFloor int) (below, atOrAbove int) {
	cohorts := map[string]map[string]struct{}{}
	for _, r := range records {
		if r.HostMeta.OSID == "" {
			continue
		}
		key := r.HostMeta.OSID + "\x00" + core.CanonicalTagKey(r.HostMeta.Tags)
		if cohorts[key] == nil {
			cohorts[key] = map[string]struct{}{}
		}
		cohorts[key][hostKey(r)] = struct{}{}
	}
	for _, hosts := range cohorts {
		if len(hosts) >= peerFloor {
			atOrAbove++
		} else {
			below++
		}
	}
	return below, atOrAbove
}

// --- Overview ----------------------------------------------------------

func computeOverview(records []core.Record) Overview {
	hosts := map[string]struct{}{}
	modulesCount := map[string]struct {
		records int
		hosts   map[string]struct{}
	}{}
	siteClassCount := map[string]struct {
		records int
		hosts   map[string]struct{}
	}{}
	osIDCount := map[string]struct {
		records int
		hosts   map[string]struct{}
	}{}
	signalCount := map[string]struct {
		records int
		hosts   map[string]struct{}
	}{}
	// Per-host package-manager observation, to flag provenance-blind hosts.
	hostPkgMgr := map[string]string{}
	hostOSID := map[string]string{}

	for _, rec := range records {
		hk := hostKey(rec)
		hosts[hk] = struct{}{}
		if _, ok := hostPkgMgr[hk]; !ok {
			hostPkgMgr[hk] = rec.HostMeta.PkgMgr
			hostOSID[hk] = rec.HostMeta.OSID
		}

		m := modulesCount[rec.Module]
		if m.hosts == nil {
			m.hosts = map[string]struct{}{}
		}
		m.records++
		m.hosts[hk] = struct{}{}
		modulesCount[rec.Module] = m

		sc := siteClassCount[rec.SiteClass]
		if sc.hosts == nil {
			sc.hosts = map[string]struct{}{}
		}
		sc.records++
		sc.hosts[hk] = struct{}{}
		siteClassCount[rec.SiteClass] = sc

		osid := rec.HostMeta.OSID
		if osid == "" {
			osid = "<unknown>"
		}
		o := osIDCount[osid]
		if o.hosts == nil {
			o.hosts = map[string]struct{}{}
		}
		o.records++
		o.hosts[hk] = struct{}{}
		osIDCount[osid] = o

		for _, sig := range rec.Signals {
			s := signalCount[sig]
			if s.hosts == nil {
				s.hosts = map[string]struct{}{}
			}
			s.records++
			s.hosts[hk] = struct{}{}
			signalCount[sig] = s
		}
	}

	ov := Overview{
		TotalRecords:     len(records),
		TotalHosts:       len(hosts),
		TotalModules:     len(modulesCount),
		TotalSiteClasses: len(siteClassCount),
	}
	for name, c := range modulesCount {
		ov.ByModule = append(ov.ByModule, NamedCount{Name: name, Records: c.records, Hosts: len(c.hosts)})
	}
	sort.Slice(ov.ByModule, func(i, j int) bool { return ov.ByModule[i].Name < ov.ByModule[j].Name })
	for name, c := range siteClassCount {
		ov.BySiteClass = append(ov.BySiteClass, NamedCount{Name: name, Records: c.records, Hosts: len(c.hosts)})
	}
	sort.Slice(ov.BySiteClass, func(i, j int) bool {
		if ov.BySiteClass[i].Records != ov.BySiteClass[j].Records {
			return ov.BySiteClass[i].Records > ov.BySiteClass[j].Records
		}
		// Tiebreaker by Name keeps the ordering deterministic when
		// multiple site_classes have equal record counts — otherwise
		// sort.Slice is unstable and the report would shuffle the tied
		// rows between runs on the same input.
		return ov.BySiteClass[i].Name < ov.BySiteClass[j].Name
	})
	for name, c := range osIDCount {
		ov.ByOSID = append(ov.ByOSID, NamedCount{Name: name, Records: c.records, Hosts: len(c.hosts)})
	}
	sort.Slice(ov.ByOSID, func(i, j int) bool {
		if ov.ByOSID[i].Hosts != ov.ByOSID[j].Hosts {
			return ov.ByOSID[i].Hosts > ov.ByOSID[j].Hosts
		}
		return ov.ByOSID[i].Name < ov.ByOSID[j].Name
	})
	for name, c := range signalCount {
		ov.BySignal = append(ov.BySignal, NamedCount{Name: name, Records: c.records, Hosts: len(c.hosts)})
	}
	sort.Slice(ov.BySignal, func(i, j int) bool {
		if ov.BySignal[i].Hosts != ov.BySignal[j].Hosts {
			return ov.BySignal[i].Hosts < ov.BySignal[j].Hosts
		}
		return ov.BySignal[i].Name < ov.BySignal[j].Name
	})
	for hk, pm := range hostPkgMgr {
		// "none"/"" == provenance resolver found no package DB. (A real
		// manager string like "dpkg"/"rpm"/"apk"/"pacman"/"portage" means
		// the gate ran.) Surface the host so the analyst knows coverage on
		// it is degraded, not clean.
		if pm == "" || pm == "none" {
			ov.DegradedHosts = append(ov.DegradedHosts, DegradedHost{Host: hk, OSID: hostOSID[hk]})
		}
	}
	sort.Slice(ov.DegradedHosts, func(i, j int) bool {
		return ov.DegradedHosts[i].Host < ov.DegradedHosts[j].Host
	})
	return ov
}

// --- Q1: pure LFA singletons -------------------------------------------

type q1Key struct{ module, siteClass, contentNorm string }
type q1Agg struct {
	hosts         map[string]struct{}
	sampleHost    string
	sampleLocus   string
	sampleSnippet string
	coIndicators  int
	recency       int
}

// q1StrongTells are the STRONG structural co-indicators that lift a
// content-singleton to rung-1 Actionable (ADR-0017). They are population-
// AND provisioning-independent: a non-package path, a tampered package
// file, an orphan/tmp exec target, a world-writable persistence file, an
// immutable/append-only inode, or a shadowing mount is meaningful on a
// single host and on a freshly-imaged one alike. recent_{mtime,ctime} are
// NOT here — see q1Recency.
var q1StrongTells = map[string]struct{}{
	core.SignalWorldWritable:       {},
	core.SignalNonPackagePath:      {},
	core.SignalPackageFileTampered: {},
	core.SignalExecTargetOrphan:    {},
	core.SignalInterpreterInTmp:    {},
	core.SignalImmutableFlag:       {},
	core.SignalAppendOnlyFlag:      {},
	core.SignalMountShadowsPath:    {},
	// Tier-B behavioral grammars (ADR-0017): a persistence command that
	// pipes a fetch/decode into a shell, or wires a socket to a shell, is
	// rung-1 Actionable even on owned paths with no Tier-A tell.
	core.SignalFetchPipedToInterpreter: {},
	core.SignalReverseShellSocketIdiom: {},
}

// q1Recency are the temporal tells. They are a SECONDARY rank only (never
// promote to Actionable): on a freshly-provisioned/imaged host they fire
// on nearly every file, so a record carrying ONLY these is still a bare
// rung-4 singleton — but among bare singletons, the recently-changed one
// is the likelier implant, so recency floats it up within Informational.
var q1Recency = map[string]struct{}{
	core.SignalRecentMtime7d:  {},
	core.SignalRecentMtime30d: {},
	core.SignalRecentCtime7d:  {},
	core.SignalRecentCtime30d: {},
}

func countSignals(sigs []string, set map[string]struct{}) int {
	n := 0
	for _, s := range sigs {
		if _, ok := set[s]; ok {
			n++
		}
	}
	return n
}

func computeQ1(records []core.Record) []SingletonRow {
	agg := map[q1Key]*q1Agg{}
	for _, r := range records {
		if r.ContentNormSHA256 == "" {
			continue
		}
		k := q1Key{r.Module, r.SiteClass, r.ContentNormSHA256}
		a := agg[k]
		if a == nil {
			a = &q1Agg{hosts: map[string]struct{}{}, sampleLocus: r.Locus, sampleSnippet: r.ContentSnippet}
			agg[k] = a
		}
		hk := hostKey(r)
		a.hosts[hk] = struct{}{}
		if a.sampleHost == "" {
			a.sampleHost = hk
			a.coIndicators = countSignals(r.Signals, q1StrongTells)
			a.recency = countSignals(r.Signals, q1Recency)
		}
	}
	var out []SingletonRow
	for k, a := range agg {
		if len(a.hosts) != 1 {
			continue
		}
		disc, _ := classifySiteClass(k.siteClass)
		out = append(out, SingletonRow{
			Module:        k.module,
			SiteClass:     k.siteClass,
			ContentNorm:   shortHash(k.contentNorm),
			SampleHost:    a.sampleHost,
			SampleLocus:   a.sampleLocus,
			SampleSnippet: snippetTrim(a.sampleSnippet, 100),
			CoIndicators:  a.coIndicators,
			Recency:       a.recency,
			Disc:          discLabel(disc),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		// Rung-1 strong tells first (Actionable), then recency as the
		// secondary rank so a freshly-changed bare singleton floats above
		// a settled one within the Informational partition.
		if out[i].CoIndicators != out[j].CoIndicators {
			return out[i].CoIndicators > out[j].CoIndicators
		}
		if out[i].Recency != out[j].Recency {
			return out[i].Recency > out[j].Recency
		}
		if out[i].Module != out[j].Module {
			return out[i].Module < out[j].Module
		}
		if out[i].SiteClass != out[j].SiteClass {
			return out[i].SiteClass < out[j].SiteClass
		}
		return out[i].SampleHost < out[j].SampleHost
	})
	return out
}

// --- Q2: per-locus LFA singletons --------------------------------------

type q2Key struct{ module, siteClass, locus, contentNorm string }
type q2Agg struct {
	hosts         map[string]struct{}
	sampleHost    string
	sampleSnippet string
}

func computeQ2(records []core.Record) []LocusSingletonRow {
	agg := map[q2Key]*q2Agg{}
	for _, r := range records {
		if r.ContentNormSHA256 == "" {
			continue
		}
		k := q2Key{r.Module, r.SiteClass, r.Locus, r.ContentNormSHA256}
		a := agg[k]
		if a == nil {
			a = &q2Agg{hosts: map[string]struct{}{}, sampleSnippet: r.ContentSnippet}
			agg[k] = a
		}
		hk := hostKey(r)
		a.hosts[hk] = struct{}{}
		if a.sampleHost == "" {
			a.sampleHost = hk
		}
	}
	var out []LocusSingletonRow
	for k, a := range agg {
		if len(a.hosts) != 1 {
			continue
		}
		out = append(out, LocusSingletonRow{
			Module:        k.module,
			SiteClass:     k.siteClass,
			Locus:         k.locus,
			ContentNorm:   shortHash(k.contentNorm),
			SampleHost:    a.sampleHost,
			SampleSnippet: snippetTrim(a.sampleSnippet, 100),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Module != out[j].Module {
			return out[i].Module < out[j].Module
		}
		return out[i].Locus < out[j].Locus
	})
	return out
}

// --- Q3: peer-group LFA by (os_id, tags) -------------------------------
//
// ADR-0015: the peer-group key is now (os_id, canonical_tag_set). Hosts
// with byte-identical canonical tag sets form one peer-group; hosts with
// any difference form a separate peer-group. Hosts with zero tags form
// the "untagged" peer-group within their os_id family. The default
// floor of 3 (rows surface only when their peer-group has >= 3 hosts)
// is preserved from the os_id-only era; the v0.3.4 --peer-floor flag
// lets the operator tune it for over-tagged fleets where most
// peer-groups have 1-2 hosts.

type q3Key struct{ osID, tagKey, module, siteClass, contentNorm string }
type q3Agg struct {
	hosts         map[string]struct{}
	sampleHost    string
	sampleLocus   string
	sampleSnippet string
}

// q3PeerKey is the (os_id, tagKey) tuple used to size peer-groups.
type q3PeerKey struct{ osID, tagKey string }

// computeQ3 surfaces (os_id, tagKey, module, site_class, content_norm)
// groups whose record is a singleton inside a peer-group of at least
// peerFloor hosts. peerFloor <= 1 effectively disables the floor.
func computeQ3(records []core.Record, peerFloor int) []PeerGroupRow {
	// Single pass builds both the peer-group host sets and the per-key
	// aggregation. CanonicalTagKey is non-trivial (sort + dedup), so
	// caching the result per record avoids hashing the same tag slice
	// twice when both maps need it.
	peers := map[q3PeerKey]map[string]struct{}{}
	agg := map[q3Key]*q3Agg{}
	for _, r := range records {
		osid := r.HostMeta.OSID
		if osid == "" {
			continue
		}
		tagKey := core.CanonicalTagKey(r.HostMeta.Tags)
		hk := hostKey(r)
		pk := q3PeerKey{osid, tagKey}
		if peers[pk] == nil {
			peers[pk] = map[string]struct{}{}
		}
		peers[pk][hk] = struct{}{}
		if r.ContentNormSHA256 == "" {
			continue
		}
		k := q3Key{osid, tagKey, r.Module, r.SiteClass, r.ContentNormSHA256}
		a := agg[k]
		if a == nil {
			a = &q3Agg{hosts: map[string]struct{}{}, sampleLocus: r.Locus, sampleSnippet: r.ContentSnippet}
			agg[k] = a
		}
		a.hosts[hk] = struct{}{}
		if a.sampleHost == "" {
			a.sampleHost = hk
		}
	}

	var out []PeerGroupRow
	for k, a := range agg {
		peerSize := len(peers[q3PeerKey{k.osID, k.tagKey}])
		if peerSize < peerFloor {
			continue
		}
		if len(a.hosts) != 1 {
			continue
		}
		out = append(out, PeerGroupRow{
			OSID:          k.osID,
			TagKey:        k.tagKey,
			Module:        k.module,
			SiteClass:     k.siteClass,
			ContentNorm:   shortHash(k.contentNorm),
			HostsInOS:     len(a.hosts),
			PeerSize:      peerSize,
			SampleHost:    a.sampleHost,
			SampleLocus:   a.sampleLocus,
			SampleSnippet: snippetTrim(a.sampleSnippet, 100),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OSID != out[j].OSID {
			return out[i].OSID < out[j].OSID
		}
		if out[i].TagKey != out[j].TagKey {
			return out[i].TagKey < out[j].TagKey
		}
		return out[i].Module < out[j].Module
	})
	return out
}

// --- Q4: implant fingerprint -------------------------------------------

func computeQ4(records []core.Record) []ImplantRow {
	var out []ImplantRow
	for _, r := range records {
		if !containsAll(r.Signals, core.SignalExecTargetOrphan, core.SignalInterpreterInTmp) {
			continue
		}
		out = append(out, ImplantRow{
			Host:       hostKey(r),
			Module:     r.Module,
			SiteClass:  r.SiteClass,
			Locus:      r.Locus,
			ExecTarget: r.ExecTarget,
			Signals:    r.Signals,
			Snippet:    snippetTrim(r.ContentSnippet, 120),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		if out[i].Module != out[j].Module {
			return out[i].Module < out[j].Module
		}
		return out[i].Locus < out[j].Locus
	})
	return out
}

// containsAll returns true iff every needle is in haystack.
func containsAll(haystack []string, needles ...string) bool {
	if len(haystack) == 0 {
		return false
	}
	set := map[string]struct{}{}
	for _, h := range haystack {
		set[h] = struct{}{}
	}
	for _, n := range needles {
		if _, ok := set[n]; !ok {
			return false
		}
	}
	return true
}

// --- Q5: signal distribution -------------------------------------------

type q5Key struct{ module, signal string }
type q5Agg struct {
	hosts   map[string]struct{}
	records int
}

func computeQ5(records []core.Record) []SignalRow {
	agg := map[q5Key]*q5Agg{}
	for _, r := range records {
		for _, sig := range r.Signals {
			k := q5Key{r.Module, sig}
			a := agg[k]
			if a == nil {
				a = &q5Agg{hosts: map[string]struct{}{}}
				agg[k] = a
			}
			a.records++
			a.hosts[hostKey(r)] = struct{}{}
		}
	}
	var out []SignalRow
	for k, a := range agg {
		out = append(out, SignalRow{
			Module:  k.module,
			Signal:  k.signal,
			Hosts:   len(a.hosts),
			Records: a.records,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Module != out[j].Module {
			return out[i].Module < out[j].Module
		}
		if out[i].Hosts != out[j].Hosts {
			return out[i].Hosts < out[j].Hosts
		}
		return out[i].Signal < out[j].Signal
	})
	return out
}

// --- Q6: cross-host exec_target stacking -------------------------------

type q6Agg struct {
	hosts        map[string]struct{}
	records      int
	modules      map[string]struct{}
	siteClasses  map[string]struct{}
	sampleTarget string
}

// q6Suspicious reports whether a record's exec_target is worth stacking
// in Q6: it must be non-package (or already orphaned), the hallmark of an
// attacker payload rather than a fleet-wide packaged binary. Packaged
// targets shared across every host are baseline noise, not worms.
func q6Suspicious(signals []string) bool {
	for _, s := range signals {
		if s == core.SignalNonPackagePath || s == core.SignalExecTargetOrphan {
			return true
		}
	}
	return false
}

func computeQ6(records []core.Record) []ExecTargetRow {
	agg := map[string]*q6Agg{}
	totalHosts := map[string]struct{}{}
	for _, r := range records {
		totalHosts[hostKey(r)] = struct{}{}
		if r.ExecTargetSHA256 == "" {
			continue
		}
		// Only stack NON-package exec_targets. A worm's payload is never
		// package-managed, so it carries non_package_path (or
		// exec_target_orphan once the binary is gone). Without this filter
		// a homogeneous fleet floods Q6 with the hundreds of packaged
		// binaries every host legitimately shares (agetty,
		// apt.systemd.daily, ...), burying the worm among them. A
		// package-owned target shared fleet-wide is baseline, not a worm.
		if !q6Suspicious(r.Signals) {
			continue
		}
		a := agg[r.ExecTargetSHA256]
		if a == nil {
			a = &q6Agg{
				hosts:        map[string]struct{}{},
				modules:      map[string]struct{}{},
				siteClasses:  map[string]struct{}{},
				sampleTarget: q6SampleTarget(r),
			}
			agg[r.ExecTargetSHA256] = a
		}
		a.records++
		a.hosts[hostKey(r)] = struct{}{}
		a.modules[r.Module] = struct{}{}
		a.siteClasses[r.SiteClass] = struct{}{}
	}
	// Upper bound philosophy: on a large fleet, skip baseline
	// binaries (anything present on >= 10% of hosts) so the worm
	// pattern stands out. On a small fleet (< 20 hosts), 10% would
	// be 0-1 hosts, which would filter out all results. Disable
	// the upper bound in that regime and let the analyst eyeball.
	fleetSize := len(totalHosts)
	upper := fleetSize / 10
	useUpper := upper >= 2
	var out []ExecTargetRow
	for sha, a := range agg {
		if len(a.hosts) < 2 {
			continue
		}
		if useUpper && len(a.hosts) >= upper {
			continue
		}
		mods := mapKeys(a.modules)
		sort.Strings(mods)
		out = append(out, ExecTargetRow{
			ExecTargetSHA256: shortHash(sha),
			Hosts:            len(a.hosts),
			Records:          a.records,
			Modules:          len(a.modules),
			SiteClasses:      len(a.siteClasses),
			SampleTarget:     a.sampleTarget,
			SpreadModules:    mods,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hosts != out[j].Hosts {
			return out[i].Hosts > out[j].Hosts
		}
		return out[i].Modules > out[j].Modules
	})
	return out
}

// q6SampleTarget returns the display string for a Q6 row's
// sample_target column. Most records carry an absolute path in
// ExecTarget and the path is the right answer; ssh.authkeys records
// without a `command="..."` option carry an empty ExecTarget but a
// non-empty ExecTargetSHA256 (the hash of the SSH public-key blob).
// Showing "" in that case is confusing — the record IS the basis of
// a cross-host stacking row, the analyst just can't see what kind.
// Surface "(ssh authorized key)" instead so the row is self-describing.
func q6SampleTarget(r core.Record) string {
	if r.ExecTarget != "" {
		return r.ExecTarget
	}
	if r.Module == "ssh" && r.SiteClass == "ssh.authkeys" {
		return "(ssh authorized key)"
	}
	return ""
}

func mapKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// --- Histogram of host-frequency per (module, content_norm) group ------

func computeHistogram(records []core.Record) []HistogramBucket {
	type k struct{ module, contentNorm string }
	agg := map[k]map[string]struct{}{}
	for _, r := range records {
		if r.ContentNormSHA256 == "" {
			continue
		}
		key := k{r.Module, r.ContentNormSHA256}
		if agg[key] == nil {
			agg[key] = map[string]struct{}{}
		}
		agg[key][hostKey(r)] = struct{}{}
	}
	bands := []struct {
		label  string
		low    int
		high   int // inclusive; -1 = no upper
		isTail bool
	}{
		{"1 (singletons)", 1, 1, true},
		{"2–4", 2, 4, false},
		{"5–9", 5, 9, false},
		{"10–49", 10, 49, false},
		{"50–99", 50, 99, false},
		{"≥100", 100, -1, false},
	}
	buckets := make([]HistogramBucket, len(bands))
	for i, b := range bands {
		buckets[i] = HistogramBucket{Label: b.label, IsTail: b.isTail}
	}
	for _, hostsSet := range agg {
		n := len(hostsSet)
		for i, b := range bands {
			if n >= b.low && (b.high == -1 || n <= b.high) {
				buckets[i].Count++
				break
			}
		}
	}
	return buckets
}

// --- Q7: implant roll-call (cross-cutting union) -----------------------

// rollCallSignals are the signals surfaced as "triage" pills in the
// Q7 row. They are a curated subset of all signals: the ones that
// historically correlate with offensive patterns (matches the SQL
// list in tools/stack_demo.sql Q7). Names go through the core
// catalog so a typo or rename here breaks compilation rather than
// silently emitting an empty triage_signals column.
var rollCallSignals = []string{
	core.SignalExecTargetOrphan,
	core.SignalInterpreterInTmp,
	core.SignalSSHForcedCommand,
	core.SignalSudoersNoPasswd,
	core.SignalSudoersAllCommands,
	core.SignalPasswdUIDZero,
	core.SignalSSHDAuthorizedKeysCommand,
	core.SignalSSHDPermitRootLoginYes,
	core.SignalKmodInstallDirective,
	core.SignalUdevRunDirective,
	core.SignalSystemdExternalUnitSymlink,
	core.SignalSysvExternalInitSymlink,
}

// rollCallMatches reports whether r matches any detection in the
// loaded rule set. The clauses themselves live in detections.yaml at
// the repo root; see ADR-0013 for the schema and the release-gate
// mechanics that keep this consumer and tools/stack_demo.sql in sync.
func rollCallMatches(r core.Record) bool {
	return detectionRules.MatchAny(r)
}

// rollCallDetectionIDs returns the IDs of every detection that
// matched r. Used to populate the report's new "matched_detections"
// column, which gives the analyst direct triage context ("matched:
// sudoers_nopasswd_all_backdoor") instead of forcing them to infer
// the rule from the triage_signals pill set.
func rollCallDetectionIDs(r core.Record) []string {
	return detectionRules.Match(r)
}

func computeQ7(records []core.Record) []RollCallRow {
	var out []RollCallRow
	for _, r := range records {
		matched := rollCallDetectionIDs(r)
		if len(matched) == 0 {
			continue
		}
		out = append(out, RollCallRow{
			Host:              hostKey(r),
			Module:            r.Module,
			SiteClass:         r.SiteClass,
			Locus:             r.Locus,
			ExecTarget:        r.ExecTarget,
			TriageSignals:     filterSignals(r.Signals, rollCallSignals),
			MatchedDetections: matched,
			MaxSeverity:       worstSeverity(matched),
			Snippet:           snippetTrim(r.ContentSnippet, 120),
		})
	}
	// Severity-DESC first so criticals land at the top of the tab analysts
	// click first; then a stable host/module/locus tiebreak.
	sort.Slice(out, func(i, j int) bool {
		if ri, rj := severityRank[out[i].MaxSeverity], severityRank[out[j].MaxSeverity]; ri != rj {
			return ri > rj
		}
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		if out[i].Module != out[j].Module {
			return out[i].Module < out[j].Module
		}
		return out[i].Locus < out[j].Locus
	})
	return out
}

// sigSet returns a presence map of signals on a record. Used by
// rollCallMatches for O(1) lookups across a fixed needle list.
//
// For single-signal probes inside a hot per-record loop, prefer
// hasSignal: building a map per record is wasted allocation when the
// caller will only do one or two lookups against it.
func sigSet(sigs []string) map[string]struct{} {
	m := make(map[string]struct{}, len(sigs))
	for _, s := range sigs {
		m[s] = struct{}{}
	}
	return m
}

// hasSignal reports whether name appears in sigs via linear scan. For
// the typical Signals slice (2–5 entries) this is faster than building
// a temporary map per record, and it avoids the GC pressure that the
// per-record sigSet(...) pattern caused inside Q9, Q10 and Q11 hot loops.
func hasSignal(sigs []string, name string) bool {
	for _, s := range sigs {
		if s == name {
			return true
		}
	}
	return false
}

// filterSignals returns the subset of `actual` that appears in `pick`,
// preserving the order of `pick`. Used to emit the triage_signals
// column in the Q7 row in the same canonical order across the report.
func filterSignals(actual, pick []string) []string {
	present := sigSet(actual)
	var out []string
	for _, s := range pick {
		if _, ok := present[s]; ok {
			out = append(out, s)
		}
	}
	return out
}

// --- Q8: recent-mtime concentration per (host, module) ----------------

func computeQ8(records []core.Record) []MtimeConcRow {
	type k struct{ host, module string }
	type agg struct {
		recs int
		loci map[string]struct{}
	}
	m := map[k]*agg{}
	for _, r := range records {
		if !hasSignal(r.Signals, core.SignalRecentMtime7d) {
			continue
		}
		key := k{hostKey(r), r.Module}
		a := m[key]
		if a == nil {
			a = &agg{loci: map[string]struct{}{}}
			m[key] = a
		}
		a.recs++
		a.loci[r.Locus] = struct{}{}
	}
	var out []MtimeConcRow
	for k, a := range m {
		if a.recs < 5 {
			continue
		}
		out = append(out, MtimeConcRow{
			Host:          k.host,
			Module:        k.module,
			RecentRecords: a.recs,
			RecentLoci:    len(a.loci),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RecentRecords != out[j].RecentRecords {
			return out[i].RecentRecords > out[j].RecentRecords
		}
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Module < out[j].Module
	})
	return out
}

// --- Q9: exec_target under tmp-class directories ----------------------
//
// Q9 surfaces every record whose exec_target lives under /tmp/,
// /var/tmp/, /dev/shm/, or /run/shm/. Complements Q4 (which AND-s
// orphan + tmp): Q9 \ Q4 = "armed implants on disk right now".
//
// The accuracy of Q9 depends on every module populating exec_target
// only when its directive truly INVOKES a binary (run-the-binary
// category). See ADR-0014 and docs/stacking-cookbook.md "Calibration:
// what exec_target means".

func computeQ9(records []core.Record) []ExecInTmpRow {
	var out []ExecInTmpRow
	for _, r := range records {
		if r.ExecTarget == "" {
			continue
		}
		matched := false
		for _, p := range core.TmpDirs {
			if strings.HasPrefix(r.ExecTarget, p) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		isOrphan := hasSignal(r.Signals, core.SignalExecTargetOrphan)
		out = append(out, ExecInTmpRow{
			Host:       hostKey(r),
			Module:     r.Module,
			SiteClass:  r.SiteClass,
			Locus:      r.Locus,
			ExecTarget: r.ExecTarget,
			IsOrphan:   isOrphan,
			Snippet:    snippetTrim(r.ContentSnippet, 100),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		if out[i].Module != out[j].Module {
			return out[i].Module < out[j].Module
		}
		return out[i].Locus < out[j].Locus
	})
	return out
}

// --- Q10: per-host collection health and coverage outliers ------------

func computeQ10(records []core.Record) []HostCoverageRow {
	type agg struct {
		osID          string
		records       int
		modules       map[string]struct{}
		siteClasses   map[string]struct{}
		recentRecords int
	}
	m := map[string]*agg{}
	for _, r := range records {
		h := hostKey(r)
		a := m[h]
		if a == nil {
			a = &agg{
				modules:     map[string]struct{}{},
				siteClasses: map[string]struct{}{},
			}
			m[h] = a
		}
		if a.osID == "" && r.HostMeta.OSID != "" {
			a.osID = r.HostMeta.OSID
		}
		a.records++
		a.modules[r.Module] = struct{}{}
		a.siteClasses[r.SiteClass] = struct{}{}
		if hasSignal(r.Signals, core.SignalRecentMtime7d) {
			a.recentRecords++
		}
	}
	// Silent-collection-failure detector (ported from the dossier's
	// module-gap detector): a module whose fleet median (across hosts that
	// emit it) is > 0 but which THIS host emitted zero records for is a gap
	// — a crashed/timed-out module or an image that lacks it. Median is
	// taken only over hosts that emit the module so the many structural
	// zeros (hosts that legitimately lack it) do not drag it to 0.
	type modHost struct{ mod, host string }
	fleetCount := map[modHost]int{}
	for _, r := range records {
		fleetCount[modHost{r.Module, hostKey(r)}]++
	}
	perModule := map[string][]int{}
	for k := range fleetCount {
		perModule[k.mod] = append(perModule[k.mod], fleetCount[k])
	}
	moduleMedian := map[string]int{}
	for mod, v := range perModule {
		sort.Ints(v)
		moduleMedian[mod] = v[len(v)/2]
	}

	var out []HostCoverageRow
	for h, a := range m {
		var gaps []string
		for mod, med := range moduleMedian {
			if med > 0 {
				if _, ok := a.modules[mod]; !ok {
					gaps = append(gaps, mod)
				}
			}
		}
		sort.Strings(gaps)
		out = append(out, HostCoverageRow{
			Host:          h,
			OSID:          a.osID,
			Records:       a.records,
			Modules:       len(a.modules),
			SiteClasses:   len(a.siteClasses),
			RecentRecords: a.recentRecords,
			GapModules:    gaps,
		})
	}
	// Hosts WITH gaps bubble to the top (the silent-failure signal), then
	// fewest records, then host name — so a starved host is never buried
	// under healthy ones sorted purely by volume.
	sort.Slice(out, func(i, j int) bool {
		if (len(out[i].GapModules) > 0) != (len(out[j].GapModules) > 0) {
			return len(out[i].GapModules) > 0
		}
		if len(out[i].GapModules) != len(out[j].GapModules) {
			return len(out[i].GapModules) > len(out[j].GapModules)
		}
		if out[i].Records != out[j].Records {
			return out[i].Records > out[j].Records
		}
		return out[i].Host < out[j].Host
	})
	return out
}

// --- Q11: orphan exec_target OUTSIDE tmp-class directories ------------
//
// Clauses mirror tools/stack_demo.sql Q11 row-for-row:
//   - exec_target IS NOT NULL
//   - exec_target NOT LIKE /tmp/, /var/tmp/, /dev/shm/, /run/shm/
//   - signals contains non_package_path
//
// Aggregation: group by exec_target, count distinct hosts and total
// records. LFA-sorted (hosts ASC) so singletons surface first.
// q11BaselineBasename returns true if exec_target's basename is on
// the vendor-baseline allow-list. v0.3.3 introduced this filter so
// Q11 stops surfacing legitimate vendor binaries as orphans; the
// implant shapes (single-host hits in /usr/local/sbin/<name>) bubble
// to the top of the table without competing with 20+ vendor rows.
func q11BaselineBasename(execTarget string) bool {
	s := execTarget
	for len(s) > 1 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			s = s[i+1:]
			break
		}
	}
	_, ok := q11VendorBaselineBasenames[s]
	return ok
}

func computeQ11(records []core.Record) []OrphanOutsideTmpRow {
	tmpPrefixes := []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"}
	type agg struct {
		hosts         map[string]struct{}
		records       int
		module        string
		siteClass     string
		sampleLocus   string
		sampleSnippet string
	}
	m := map[string]*agg{}
	for _, r := range records {
		if r.ExecTarget == "" {
			continue
		}
		inTmp := false
		for _, p := range tmpPrefixes {
			if strings.HasPrefix(r.ExecTarget, p) {
				inTmp = true
				break
			}
		}
		if inTmp {
			continue
		}
		if !hasSignal(r.Signals, core.SignalNonPackagePath) {
			continue
		}
		if q11BaselineBasename(r.ExecTarget) {
			continue
		}
		a := m[r.ExecTarget]
		if a == nil {
			a = &agg{
				hosts:         map[string]struct{}{},
				module:        r.Module,
				siteClass:     r.SiteClass,
				sampleLocus:   r.Locus,
				sampleSnippet: r.ContentSnippet,
			}
			m[r.ExecTarget] = a
		}
		a.hosts[hostKey(r)] = struct{}{}
		a.records++
	}
	out := make([]OrphanOutsideTmpRow, 0, len(m))
	for target, a := range m {
		hosts := make([]string, 0, len(a.hosts))
		for h := range a.hosts {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		sampleHost := ""
		if len(hosts) > 0 {
			sampleHost = hosts[0]
		}
		out = append(out, OrphanOutsideTmpRow{
			ExecTarget:    target,
			Hosts:         len(a.hosts),
			Records:       a.records,
			Module:        a.module,
			SiteClass:     a.siteClass,
			SampleHost:    sampleHost,
			SampleLocus:   a.sampleLocus,
			SampleSnippet: snippetTrim(a.sampleSnippet, 100),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hosts != out[j].Hosts {
			return out[i].Hosts < out[j].Hosts
		}
		if out[i].Records != out[j].Records {
			return out[i].Records > out[j].Records
		}
		return out[i].ExecTarget < out[j].ExecTarget
	})
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}

// --- Q12: campaign basename clustering ---------------------------------
//
// Same basename of exec_target (or locus when exec_target is
// empty), found in >=2 different modules and on >=2 hosts.
// Surfaces multi-arm campaigns whose individual arms each look
// like a Q1 singleton in their own module. The v0.2.0 deploy-sync
// case had three arms (cron, profile, systemd) all pointing at
// /usr/local/sbin/deploy-sync* with subtly different exec_targets;
// Q1 surfaced them as three independent singletons in three
// different modules. Q12 collapses them to one row.
//
// FPs to expect: basenames shared across vendor baselines
// (e.g. `sshd_config`, `bashrc`) trigger this query in
// everyday-fleet shape. The current implementation does not
// filter -- we rely on the analyst sorting ascending by hosts
// and triaging from the top. A v0.3.x calibration may add a
// basename allow-list.

// q12Suspicious reports whether a record carries a persistence-anomaly
// signal that makes a basename cluster worth surfacing (vs coincidental
// package baseline shared across the fleet).
func q12Suspicious(signals []string) bool {
	for _, s := range signals {
		switch s {
		case core.SignalNonPackagePath, core.SignalExecTargetOrphan, core.SignalInterpreterInTmp:
			return true
		}
	}
	return false
}

func computeQ12(records []core.Record) []BasenameClusterRow {
	type agg struct {
		hosts            map[string]struct{}
		modules          map[string]struct{}
		records          int
		suspicious       bool
		sampleHost       string
		sampleLocus      string
		sampleExecTarget string
	}
	groups := map[string]*agg{}
	for _, r := range records {
		base := basenameForQ12(r)
		if base == "" {
			continue
		}
		a := groups[base]
		if a == nil {
			a = &agg{
				hosts:   map[string]struct{}{},
				modules: map[string]struct{}{},
			}
			groups[base] = a
		}
		a.hosts[hostKey(r)] = struct{}{}
		a.modules[r.Module] = struct{}{}
		a.records++
		if !a.suspicious && q12Suspicious(r.Signals) {
			a.suspicious = true
		}
		if a.sampleHost == "" {
			a.sampleHost = hostKey(r)
			a.sampleLocus = r.Locus
			a.sampleExecTarget = r.ExecTarget
		}
	}
	var out []BasenameClusterRow
	for base, a := range groups {
		if len(a.modules) < 2 || len(a.hosts) < 2 {
			continue
		}
		// Require at least one arm to carry a persistence-anomaly signal.
		// A campaign's arms are non-package / orphan / tmp payloads; a
		// basename shared across modules with NO such signal is just
		// coincidental package baseline (bash, dbus, cron on every host)
		// and would otherwise be a fixed wall of noise the analyst scrolls
		// past every run.
		if !a.suspicious {
			continue
		}
		mods := make([]string, 0, len(a.modules))
		for m := range a.modules {
			mods = append(mods, m)
		}
		sort.Strings(mods)
		out = append(out, BasenameClusterRow{
			Basename:         base,
			Hosts:            len(a.hosts),
			Modules:          mods,
			Records:          a.records,
			SampleHost:       a.sampleHost,
			SampleLocus:      a.sampleLocus,
			SampleExecTarget: a.sampleExecTarget,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hosts != out[j].Hosts {
			return out[i].Hosts < out[j].Hosts
		}
		return out[i].Basename < out[j].Basename
	})
	return out
}

// basenameForQ12 returns the basename used for clustering. Prefer
// exec_target over locus because the exec_target is the campaign
// pivot (what is actually invoked across modules); locus is the
// per-module configuration file path which differs by definition.
// Skip path components that are not informative.
func basenameForQ12(r core.Record) string {
	s := r.ExecTarget
	if s == "" {
		s = r.Locus
	}
	if s == "" {
		return ""
	}
	// Strip trailing /, take last path component.
	for len(s) > 1 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			s = s[i+1:]
			break
		}
	}
	if s == "." || s == ".." {
		return ""
	}
	// Strip common operator-shaped extensions so the same logical
	// invocation surfaces across modules whose naming conventions
	// differ (cron drops a file named <name>, profile.d demands
	// <name>.sh, systemd demands <name>.service). Without this,
	// the worm-shared 3-arm pattern fragments by extension.
	// Source list lives in assets/script_extensions.yaml so operators
	// can tune it without recompiling.
	for _, ext := range q12StripExtensions {
		if strings.HasSuffix(s, ext) {
			s = s[:len(s)-len(ext)]
			break
		}
	}
	return s
}
