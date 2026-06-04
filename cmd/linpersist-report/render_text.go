package main

// Text renderer for the fleet report. The ansi / TTY / section helpers
// live in render_common.go so the host dossier and diff renderers can
// share them without duplication.

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
)

// renderText writes a terminal-friendly transcription of the report
// to out. color controls whether ANSI escape sequences are emitted.
func renderText(out io.Writer, report *Report, title string, color bool) error {
	a := &ansi{enabled: color}

	// --- Title -------------------------------------------------------
	fmt.Fprintln(out, a.bold(title))
	fmt.Fprintln(out, strings.Repeat("=", len(title)))
	fmt.Fprintf(out, "generated %s · %d hosts · %s records · %d modules · %d site_classes",
		report.Generated.Format("2006-01-02 15:04 UTC"),
		report.Overview.TotalHosts,
		commaInt(report.Overview.TotalRecords),
		report.Overview.TotalModules,
		report.Overview.TotalSiteClasses)
	if report.SkippedLines > 0 {
		fmt.Fprintf(out, " · %d malformed lines skipped", report.SkippedLines)
	}
	if report.AgentVersion != "" {
		fmt.Fprintf(out, " · agent %s", safeCell(report.AgentVersion))
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out)

	// --- Coverage-degraded banner ------------------------------------
	// Provenance-blind hosts (no package manager) get their ownership
	// gate skipped entirely, so "0 findings" on them means "could not
	// verify", not "clean". Make that loud.
	if n := len(report.Overview.DegradedHosts); n > 0 {
		warn := a.orange(fmt.Sprintf("⚠ coverage degraded on %d host(s): no package manager detected — provenance (non_package_path / package_file_tampered) gate did NOT run; absence of findings is NOT proof of clean. Treat these hosts as HIGHER priority for manual review + EDR pairing, not lower (ADR-0017).", n))
		fmt.Fprintln(out, warn)
		for i, dh := range report.Overview.DegradedHosts {
			if i >= 10 {
				fmt.Fprintf(out, "    … and %d more\n", n-10)
				break
			}
			os := dh.OSID
			if os == "" {
				os = "<unknown>"
			}
			fprintfSafe(out, "    %s (os_id=%s)\n", dh.Host, os)
		}
		fmt.Fprintln(out)
	}

	// --- LFA triage-only banner (ADR-0017) ---------------------------
	// Distinct from the provenance-degraded banner: here cross-host LFA has
	// no comparand (N=1 or no cohort at peer-floor), so Q1/Q3 row counts are
	// triage, not verdicts. The population-independent path (Q7 + Q1
	// Actionable + Tier-B) still holds.
	if report.LFATriageOnly {
		fmt.Fprintln(out, a.orange(fmt.Sprintf("⚠ LFA triage-only: no (os_id, tag_set) cohort reaches the peer-floor (%d); %d cohort(s) below it. Cross-host rarity (Q1/Q3 counts) has no comparand here — trust the population-independent path (Q7, Q1 Actionable, Tier-B). '0 Actionable' is NOT 'clean'.", report.PeerFloor, report.SuppressedPeerGroups)))
		fmt.Fprintln(out)
	}

	// --- Overview cards ----------------------------------------------
	textSection(out, a, "Overview")
	sev := report.Overview.SeverityCounts
	summary := []struct {
		k string
		v string
	}{
		{"hosts", strconv.Itoa(report.Overview.TotalHosts)},
		{"records", commaInt(report.Overview.TotalRecords)},
		{"modules", strconv.Itoa(report.Overview.TotalModules)},
		{"site_classes", strconv.Itoa(report.Overview.TotalSiteClasses)},
		{"Q1 singletons", strconv.Itoa(len(report.Q1Singletons))},
		{"Q4 implant hits", maybeRed(a, strconv.Itoa(len(report.Q4ImplantFingerprint)), len(report.Q4ImplantFingerprint) > 0)},
		{"Q7 roll-call", maybeRed(a, strconv.Itoa(len(report.Q7ImplantRollCall)), len(report.Q7ImplantRollCall) > 0)},
		{"  critical", severityValue(a, sev["critical"], "critical")},
		{"  high", severityValue(a, sev["high"], "high")},
		{"  medium", severityValue(a, sev["medium"], "medium")},
		{"  low", strconv.Itoa(sev["low"])},
		{"  info", strconv.Itoa(sev["info"])},
		{"Q8 mtime spikes", strconv.Itoa(len(report.Q8MtimeConcentration))},
		{"Q11 orphan outside tmp", maybeRed(a, strconv.Itoa(len(report.Q11OrphanOutsideTmp)), len(report.Q11OrphanOutsideTmp) > 0)},
		{"MITRE coverage", mitreCoverageSummary(report.MITRECoverage)},
		{"Q12 basename clusters", strconv.Itoa(len(report.Q12BasenameClustering))},
	}
	for _, s := range summary {
		fmt.Fprintf(out, "  %-26s %s\n", s.k+":", s.v)
	}
	fmt.Fprintln(out)

	// --- Histogram ---------------------------------------------------
	textSection(out, a, "LFA stacking histogram")
	fmt.Fprintln(out, "(distinct (module, content_norm) groups vs how many hosts share them)")
	fmt.Fprintln(out)
	hmax := histMax(report.HistogramBuckets)
	for _, b := range report.HistogramBuckets {
		bar := strings.Repeat("█", barWidth(b.Count, hmax, 40))
		if b.IsTail && b.Count > 0 {
			bar = a.orange(bar)
		}
		fmt.Fprintf(out, "  %-16s %s %d\n", b.Label, bar, b.Count)
	}
	fmt.Fprintln(out)

	// --- Modules -----------------------------------------------------
	textSection(out, a, "Modules")
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  module\trecords\thosts")
	for _, r := range report.Overview.ByModule {
		fprintfSafe(tw, "  %s\t%s\t%d\n", r.Name, commaInt(r.Records), r.Hosts)
	}
	tw.Flush()
	fmt.Fprintln(out)

	// --- Site classes ------------------------------------------------
	textSection(out, a, "Site classes")
	tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  site_class\trecords\thosts")
	for _, r := range report.Overview.BySiteClass {
		fprintfSafe(tw, "  %s\t%s\t%d\n", r.Name, commaInt(r.Records), r.Hosts)
	}
	tw.Flush()
	fmt.Fprintln(out)

	// --- OS distribution --------------------------------------------
	textSection(out, a, "OS distribution")
	tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  os_id\thosts\trecords")
	for _, r := range report.Overview.ByOSID {
		fprintfSafe(tw, "  %s\t%d\t%s\n", r.Name, r.Hosts, commaInt(r.Records))
	}
	tw.Flush()
	fmt.Fprintln(out)

	// --- MITRE ATT&CK coverage -------------------------------------
	textSection(out, a, fmt.Sprintf("MITRE ATT&CK coverage (%s)", mitreCoverageSummary(report.MITRECoverage)))
	if report.MITRECoverage.TotalTechniques == 0 {
		fmt.Fprintln(out, "  (matrix.yaml unavailable -- panel suppressed)")
		fmt.Fprintln(out)
	} else {
		fmt.Fprintln(out, "Techniques declared in matrix.yaml cross-referenced with live records.")
		fmt.Fprintln(out, "surfacing             = at least one record carries the technique ID.")
		fmt.Fprintln(out, "dormant_coverage_gap  = a covering module is active in the dataset but no")
		fmt.Fprintln(out, "                        record carries this technique -- the operationally")
		fmt.Fprintln(out, "                        interesting case (review module MITRE tagging or")
		fmt.Fprintln(out, "                        the fleet sample).")
		fmt.Fprintln(out, "dormant_module_silent = no covering module emitted any record fleet-wide,")
		fmt.Fprintln(out, "                        so the site_class does not apply to this fleet")
		fmt.Fprintln(out, "                        shape (e.g. grub/xdg in container fleets).")
		fmt.Fprintln(out)
		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  technique\tstatus\trecords\thosts\tsite_classes")
		for _, row := range report.MITRECoverage.Rows {
			status := row.Status
			if status != statusSurfacing {
				status = a.orange(status)
			}
			fmt.Fprintf(tw, "  %s\t%s\t%d\t%d\t%s\n",
				safeCell(row.TechniqueID), status, row.Records, row.Hosts,
				safeCell(strings.Join(row.SiteClasses, ", ")))
		}
		tw.Flush()
		fmt.Fprintln(out)
	}

	// --- Signal distribution (fleet-wide) ---------------------------
	textSection(out, a, "Signal distribution (fleet-wide)")
	tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  signal\thosts\trecords")
	for _, r := range report.Overview.BySignal {
		fprintfSafe(tw, "  %s\t%d\t%s\n", r.Name, r.Hosts, commaInt(r.Records))
	}
	tw.Flush()
	fmt.Fprintln(out)

	// --- Q1: pure LFA -----------------------------------------------
	// ADR-0017 discriminator ladder: partition singletons into ACTIONABLE
	// (rung-1: a structural co-indicator is present, so the row is real
	// regardless of fleet population) and INFORMATIONAL (rung-4: a bare
	// content-singleton with no tell — weak without a peer cohort or a
	// prior snapshot). The informational group is NEVER suppressed; it is
	// shown as a separate, labelled section so the doc does not outrun the
	// mechanism (ADR-0017) and so a true positive hiding in it stays visible.
	var q1Actionable, q1Info []SingletonRow
	for _, r := range report.Q1Singletons {
		if r.CoIndicators > 0 {
			q1Actionable = append(q1Actionable, r)
		} else {
			q1Info = append(q1Info, r)
		}
	}
	textSection(out, a, fmt.Sprintf("Q1 · LFA singletons (%d)", len(report.Q1Singletons)))
	fmt.Fprintln(out, "Records whose content_norm_sha256 appears on exactly one host, split by the ADR-0017 ladder.")
	fmt.Fprintln(out)

	fmt.Fprintln(out, a.bold(fmt.Sprintf("  Actionable — rung 1: structural co-indicator present (%d)", len(q1Actionable))))
	fmt.Fprintln(out, "  Real regardless of fleet population (orphan/non-package/tmp/tamper/recent/…); co ranks severity.")
	if len(q1Actionable) == 0 {
		fmt.Fprintln(out, "    no rows")
	} else {
		tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  co\tmodule\tsite_class\tcontent_norm\tsample_host\tsample_locus\tsnippet")
		for _, r := range q1Actionable {
			fprintfSafe(tw, "  %d\t%s\t%s\t%s\t%s\t%s\t%s\n",
				r.CoIndicators, r.Module, r.SiteClass, r.ContentNorm, r.SampleHost,
				r.SampleLocus, r.SampleSnippet)
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	fmt.Fprintln(out, a.bold(fmt.Sprintf("  Informational — rung 4: bare content-novelty, no structural tell (%d)", len(q1Info))))
	fmt.Fprintln(out, "  NOT a verdict and NOT suppressed: triage these. At N=1 every record is a singleton; rarity")
	fmt.Fprintln(out, "  alone is weak here. Restore verdict-power via a sized peer cohort (Q3), a prior snapshot")
	fmt.Fprintln(out, "  (diff mode), or EDR/host-baselining. Sorted by rec (recent_{mtime,ctime} count) — a freshly-")
	fmt.Fprintln(out, "  changed unique file is the likelier implant. disc=novelty-only means provenance was structurally")
	fmt.Fprintln(out, "  inapplicable (no tell was ever possible); disc=no-tell means a tell could have fired and did not.")
	if len(q1Info) == 0 {
		fmt.Fprintln(out, "    no rows")
	} else {
		tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  rec\tdisc\tmodule\tsite_class\tcontent_norm\tsample_host\tsample_locus\tsnippet")
		const q1Cap = 300
		shown := 0
		for _, r := range q1Info {
			if shown >= q1Cap {
				break
			}
			fprintfSafe(tw, "  %d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				r.Recency, r.Disc, r.Module, r.SiteClass, r.ContentNorm, r.SampleHost,
				r.SampleLocus, r.SampleSnippet)
			shown++
		}
		tw.Flush()
		if rest := len(q1Info) - shown; rest > 0 {
			fmt.Fprintf(out, "  … %d more informational rows not shown in text (full list in HTML/JSON; none suppressed)\n", rest)
		}
	}
	fmt.Fprintln(out)

	// --- Q2: per-locus LFA ------------------------------------------
	textSection(out, a, fmt.Sprintf("Q2 · Per-locus LFA singletons (%d)", len(report.Q2LocusSingletons)))
	fmt.Fprintln(out, "Like Q1 but groups by locus. Catches identical content at unusual paths.")
	fmt.Fprintln(out)
	if len(report.Q2LocusSingletons) == 0 {
		fmt.Fprintln(out, "  no rows")
	} else {
		tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  module\tsite_class\tlocus\tcontent_norm\tsample_host\tsnippet")
		for _, r := range report.Q2LocusSingletons {
			fprintfSafe(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n",
				r.Module, r.SiteClass, r.Locus, r.ContentNorm,
				r.SampleHost, r.SampleSnippet)
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Q3: peer-group LFA -----------------------------------------
	textSection(out, a, fmt.Sprintf("Q3 · Peer-group LFA by (os_id, tags) (%d)", len(report.Q3PeerGroupSingletons)))
	fmt.Fprintf(out, "Singletons within a sized (os_id, tag_set) cohort. peer-floor=%d · %d cohort(s) qualify · %d suppressed below floor.\n",
		report.PeerFloor, report.QualifyingPeerGroups, report.SuppressedPeerGroups)
	fmt.Fprintln(out)
	if len(report.Q3PeerGroupSingletons) == 0 {
		if report.QualifyingPeerGroups == 0 {
			fmt.Fprintf(out, "  no rows — SUPPRESSED: all %d cohort(s) are below peer-floor %d (not 'clean'; lower --peer-floor or add role replicas)\n",
				report.SuppressedPeerGroups, report.PeerFloor)
		} else {
			fmt.Fprintln(out, "  no rows — cohorts qualify but carry no singleton")
		}
	} else {
		tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  os_id\tmodule\tsite_class\tcontent_norm\tpeer_size\tsample_host\tsample_locus")
		for _, r := range report.Q3PeerGroupSingletons {
			fprintfSafe(tw, "  %s\t%s\t%s\t%s\t%d\t%s\t%s\n",
				r.OSID, r.Module, r.SiteClass, r.ContentNorm, r.PeerSize,
				r.SampleHost, r.SampleLocus)
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Q4: implant fingerprint -----------------------------------
	// Folded into Q7 in the HTML tabs (strict subset of
	// payload_under_tmp_via_persistence); retained here as the text/SQL
	// reference section.
	nQ4 := len(report.Q4ImplantFingerprint)
	q4Title := fmt.Sprintf("Q4 · Implant fingerprint (%s)",
		maybeRed(a, strconv.Itoa(nQ4), nQ4 > 0))
	textSection(out, a, q4Title)
	fmt.Fprintln(out, "Records carrying both exec_target_orphan and interpreter_in_tmp (HTML: folded into Q7).")
	fmt.Fprintln(out)
	if nQ4 == 0 {
		fmt.Fprintln(out, "  no rows")
	} else {
		tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  host\tmodule\tsite_class\tlocus\texec_target\tsignals")
		for _, r := range report.Q4ImplantFingerprint {
			sigs := strings.Join(r.Signals, ",")
			fprintfSafe(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n",
				r.Host, r.Module, r.SiteClass, r.Locus,
				r.ExecTarget, sigs)
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Q5: signal distribution by module --------------------------
	// Folded into the Overview signal-bars drill-down in the HTML;
	// retained here as the text/SQL reference section.
	textSection(out, a, fmt.Sprintf("Q5 · Signal distribution by module (%d)",
		len(report.Q5SignalDistribution)))
	fmt.Fprintln(out, "Per (module, signal): hosts that fire it and records carrying it (HTML: Overview drill-down).")
	fmt.Fprintln(out)
	if len(report.Q5SignalDistribution) == 0 {
		fmt.Fprintln(out, "  no rows")
	} else {
		tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  module\tsignal\thosts\trecords")
		for _, r := range report.Q5SignalDistribution {
			fprintfSafe(tw, "  %s\t%s\t%d\t%s\n",
				r.Module, r.Signal, r.Hosts, commaInt(r.Records))
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Q6: cross-host exec_target stacking ------------------------
	textSection(out, a, fmt.Sprintf("Q6 · Cross-host exec_target stacking (%d)",
		len(report.Q6ExecTargetStacking)))
	fmt.Fprintln(out, "Identical NON-PACKAGE payload across >=2 hosts (worm pattern); packaged fleet binaries excluded.")
	fmt.Fprintln(out)
	if len(report.Q6ExecTargetStacking) == 0 {
		fmt.Fprintln(out, "  no rows")
	} else {
		tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  exec_target_sha256\thosts\trecords\tmodules\tsample_target\tspread")
		for _, r := range report.Q6ExecTargetStacking {
			spread := strings.Join(r.SpreadModules, ",")
			fprintfSafe(tw, "  %s\t%d\t%s\t%d\t%s\t%s\n",
				r.ExecTargetSHA256, r.Hosts, commaInt(r.Records),
				r.Modules, r.SampleTarget, spread)
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Q7: implant roll-call --------------------------------------
	nQ7 := len(report.Q7ImplantRollCall)
	q7Title := fmt.Sprintf("Q7 · Implant roll-call (%s)",
		maybeRed(a, strconv.Itoa(nQ7), nQ7 > 0))
	textSection(out, a, q7Title)
	fmt.Fprintln(out, "Cross-cutting union: every record matching any canonical implant pattern.")
	fmt.Fprintln(out)
	if nQ7 == 0 {
		fmt.Fprintln(out, "  no rows")
	} else {
		tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  severity\thost\tmodule\tsite_class\tlocus\texec_target\tmatched_detections\ttriage_signals")
		for _, r := range report.Q7ImplantRollCall {
			sigs := strings.Join(r.TriageSignals, ",")
			det := strings.Join(r.MatchedDetections, ",")
			sev := r.MaxSeverity
			if sev == "" {
				sev = "-"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				colorSeverity(a, sev),
				safeCell(r.Host), safeCell(r.Module), safeCell(r.SiteClass),
				safeCell(r.Locus), safeCell(r.ExecTarget), safeCell(det), safeCell(sigs))
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Q8: recent-mtime concentration ----------------------------
	textSection(out, a, fmt.Sprintf("Q8 · Recent-mtime concentration (%d)",
		len(report.Q8MtimeConcentration)))
	fmt.Fprintln(out, "host × module pairs with >=5 records touched in the last 7 days.")
	fmt.Fprintln(out)
	if len(report.Q8MtimeConcentration) == 0 {
		fmt.Fprintln(out, "  no rows")
	} else {
		tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  host\tmodule\trecent_records\trecent_loci")
		for _, r := range report.Q8MtimeConcentration {
			fprintfSafe(tw, "  %s\t%s\t%d\t%d\n",
				r.Host, r.Module, r.RecentRecords, r.RecentLoci)
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Q9: exec targets in tmp ------------------------------------
	textSection(out, a, fmt.Sprintf("Q9 · Exec targets under /tmp, /var/tmp, /dev/shm, /run/shm (%d)",
		len(report.Q9ExecInTmp)))
	fmt.Fprintln(out, "Q4's open half: exec_target in tmp-class dirs, orphan or not.")
	fmt.Fprintln(out)
	if len(report.Q9ExecInTmp) == 0 {
		fmt.Fprintln(out, "  no rows")
	} else {
		tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  host\tmodule\tsite_class\tlocus\texec_target\torphan")
		for _, r := range report.Q9ExecInTmp {
			orph := "no"
			if r.IsOrphan {
				orph = "yes"
			}
			fprintfSafe(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n",
				r.Host, r.Module, r.SiteClass,
				r.Locus, r.ExecTarget, orph)
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Q10: per-host collection health ----------------------------
	gapHosts := 0
	for _, r := range report.Q10HostCoverage {
		if len(r.GapModules) > 0 {
			gapHosts++
		}
	}
	textSection(out, a, fmt.Sprintf("Q10 · Per-host collection health (%d hosts)",
		len(report.Q10HostCoverage)))
	fmt.Fprintf(out, "RUN FIRST. %s host(s) have module gaps = modules the fleet emits but this host did not (silent agent failure / image gap). Gap hosts listed first.\n",
		maybeRed(a, strconv.Itoa(gapHosts), gapHosts > 0))
	fmt.Fprintln(out)
	if len(report.Q10HostCoverage) == 0 {
		fmt.Fprintln(out, "  no rows")
	} else {
		tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  host\tos_id\trecords\tmodules\tsite_classes\trecent\tgap_modules")
		for _, r := range report.Q10HostCoverage {
			gaps := "-"
			if len(r.GapModules) > 0 {
				gaps = maybeRed(a, strings.Join(r.GapModules, ","), true)
			}
			fprintfSafe(tw, "  %s\t%s\t%s\t%d\t%d\t%d\t%s\n",
				r.Host, r.OSID, commaInt(r.Records),
				r.Modules, r.SiteClasses, r.RecentRecords, gaps)
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Q11: orphan exec targets outside tmp-class dirs -------------
	textSection(out, a, fmt.Sprintf("Q11 · Orphan exec_target OUTSIDE tmp-class dirs (%d)",
		len(report.Q11OrphanOutsideTmp)))
	fmt.Fprintln(out, "Unmanaged payloads under /opt, /var/lib, /srv, /usr/local. LFA-sorted.")
	fmt.Fprintln(out)
	if len(report.Q11OrphanOutsideTmp) == 0 {
		fmt.Fprintln(out, "  no rows")
	} else {
		tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  exec_target\thosts\trecords\tmodule\tsite_class\tsample_host\tsample_locus")
		for _, r := range report.Q11OrphanOutsideTmp {
			fprintfSafe(tw, "  %s\t%d\t%d\t%s\t%s\t%s\t%s\n",
				r.ExecTarget, r.Hosts, r.Records,
				r.Module, r.SiteClass, r.SampleHost,
				r.SampleLocus)
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Q12: campaign basename clustering ---------------------------
	textSection(out, a, fmt.Sprintf("Q12 · Campaign basename clusters (%d)",
		len(report.Q12BasenameClustering)))
	fmt.Fprintln(out, "Same basename across >=2 modules on >=2 hosts, where at least one arm")
	fmt.Fprintln(out, "carries a persistence-anomaly signal (non-package / orphan / tmp) -- so")
	fmt.Fprintln(out, "coincidental package baseline (bash, dbus on every host) is excluded.")
	fmt.Fprintln(out, "Sorted ascending by host count -- rare/coordinated patterns surface first.")
	fmt.Fprintln(out)
	if len(report.Q12BasenameClustering) == 0 {
		fmt.Fprintln(out, "  no rows")
	} else {
		tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  basename\thosts\trecords\tmodules\tsample_host\tsample_exec_target")
		for _, r := range report.Q12BasenameClustering {
			sampleExec := r.SampleExecTarget
			if sampleExec == "" {
				sampleExec = "(locus) " + r.SampleLocus
			}
			fprintfSafe(tw, "  %s\t%d\t%d\t%s\t%s\t%s\n",
				r.Basename, r.Hosts, r.Records,
				strings.Join(r.Modules, ", "),
				r.SampleHost, sampleExec)
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Footer ------------------------------------------------------
	fmt.Fprintf(out, "Sources: %d file(s)\n", len(report.Sources))
	return nil
}
