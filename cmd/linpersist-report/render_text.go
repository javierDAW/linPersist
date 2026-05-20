package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
)

// ansi wraps strings with SGR escapes when enabled is true; otherwise
// returns the input unchanged.
//
// Each helper resets only the attribute it set, so nested calls
// compose:
//   - bold uses 1m / 22m (sets bold / cancels bold, color untouched)
//   - red uses 31m / 39m (sets color / default color, bold untouched)
//   - orange uses 38;5;208m / 39m (256-color / default color)
//
// This lets `a.bold(a.red("X"))` produce a "bold red X" without the
// inner red's reset prematurely cancelling the outer bold.
type ansi struct{ enabled bool }

func (a *ansi) bold(s string) string {
	if !a.enabled {
		return s
	}
	return "\x1b[1m" + s + "\x1b[22m"
}
func (a *ansi) red(s string) string {
	if !a.enabled {
		return s
	}
	return "\x1b[31m" + s + "\x1b[39m"
}
func (a *ansi) orange(s string) string {
	if !a.enabled {
		return s
	}
	return "\x1b[38;5;208m" + s + "\x1b[39m"
}

// isTTY returns true if f is a character device (terminal). Used to
// gate ANSI escapes.
func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

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
		fmt.Fprintf(out, " · agent %s", report.AgentVersion)
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out)

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
		fmt.Fprintf(tw, "  %s\t%s\t%d\n", r.Name, commaInt(r.Records), r.Hosts)
	}
	tw.Flush()
	fmt.Fprintln(out)

	// --- Site classes ------------------------------------------------
	textSection(out, a, "Site classes")
	tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  site_class\trecords\thosts")
	for _, r := range report.Overview.BySiteClass {
		fmt.Fprintf(tw, "  %s\t%s\t%d\n", r.Name, commaInt(r.Records), r.Hosts)
	}
	tw.Flush()
	fmt.Fprintln(out)

	// --- OS distribution --------------------------------------------
	textSection(out, a, "OS distribution")
	tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  os_id\thosts\trecords")
	for _, r := range report.Overview.ByOSID {
		fmt.Fprintf(tw, "  %s\t%d\t%s\n", r.Name, r.Hosts, commaInt(r.Records))
	}
	tw.Flush()
	fmt.Fprintln(out)

	// --- Signal distribution (fleet-wide) ---------------------------
	textSection(out, a, "Signal distribution (fleet-wide)")
	tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  signal\thosts\trecords")
	for _, r := range report.Overview.BySignal {
		fmt.Fprintf(tw, "  %s\t%d\t%s\n", r.Name, r.Hosts, commaInt(r.Records))
	}
	tw.Flush()
	fmt.Fprintln(out)

	// --- Q1: pure LFA -----------------------------------------------
	textSection(out, a, fmt.Sprintf("Q1 · LFA singletons (%d)", len(report.Q1Singletons)))
	fmt.Fprintln(out, "Records whose content_norm_sha256 appears on exactly one host.")
	fmt.Fprintln(out)
	if len(report.Q1Singletons) == 0 {
		fmt.Fprintln(out, "  no rows")
	} else {
		tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  module\tsite_class\tcontent_norm\tsample_host\tsample_locus\tsnippet")
		for _, r := range report.Q1Singletons {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n",
				r.Module, r.SiteClass, r.ContentNorm, r.SampleHost,
				r.SampleLocus, r.SampleSnippet)
		}
		tw.Flush()
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
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n",
				r.Module, r.SiteClass, r.Locus, r.ContentNorm,
				r.SampleHost, r.SampleSnippet)
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Q3: peer-group LFA -----------------------------------------
	textSection(out, a, fmt.Sprintf("Q3 · Peer-group LFA by os_id (%d)", len(report.Q3PeerGroupSingletons)))
	fmt.Fprintln(out, "Singletons within their own OS bucket. Only OS groups with >2 hosts.")
	fmt.Fprintln(out)
	if len(report.Q3PeerGroupSingletons) == 0 {
		fmt.Fprintln(out, "  no rows")
	} else {
		tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  os_id\tmodule\tsite_class\tcontent_norm\tpeer_size\tsample_host\tsample_locus")
		for _, r := range report.Q3PeerGroupSingletons {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%d\t%s\t%s\n",
				r.OSID, r.Module, r.SiteClass, r.ContentNorm, r.PeerSize,
				r.SampleHost, r.SampleLocus)
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Q4: implant fingerprint -----------------------------------
	nQ4 := len(report.Q4ImplantFingerprint)
	q4Title := fmt.Sprintf("Q4 · Implant fingerprint (%s)",
		maybeRed(a, strconv.Itoa(nQ4), nQ4 > 0))
	textSection(out, a, q4Title)
	fmt.Fprintln(out, "Records carrying both exec_target_orphan and interpreter_in_tmp.")
	fmt.Fprintln(out)
	if nQ4 == 0 {
		fmt.Fprintln(out, "  no rows")
	} else {
		tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  host\tmodule\tsite_class\tlocus\texec_target\tsignals")
		for _, r := range report.Q4ImplantFingerprint {
			sigs := strings.Join(r.Signals, ",")
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n",
				r.Host, r.Module, r.SiteClass, r.Locus,
				r.ExecTarget, sigs)
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Q5: signal distribution by module --------------------------
	textSection(out, a, fmt.Sprintf("Q5 · Signal distribution by module (%d)",
		len(report.Q5SignalDistribution)))
	fmt.Fprintln(out, "Per (module, signal): hosts that fire it and records carrying it.")
	fmt.Fprintln(out)
	if len(report.Q5SignalDistribution) == 0 {
		fmt.Fprintln(out, "  no rows")
	} else {
		tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  module\tsignal\thosts\trecords")
		for _, r := range report.Q5SignalDistribution {
			fmt.Fprintf(tw, "  %s\t%s\t%d\t%s\n",
				r.Module, r.Signal, r.Hosts, commaInt(r.Records))
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Q6: cross-host exec_target stacking ------------------------
	textSection(out, a, fmt.Sprintf("Q6 · Cross-host exec_target stacking (%d)",
		len(report.Q6ExecTargetStacking)))
	fmt.Fprintln(out, "Identical payload, polymorphic persistence (worm pattern).")
	fmt.Fprintln(out)
	if len(report.Q6ExecTargetStacking) == 0 {
		fmt.Fprintln(out, "  no rows")
	} else {
		tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  exec_target_sha256\thosts\trecords\tmodules\tsample_target\tspread")
		for _, r := range report.Q6ExecTargetStacking {
			spread := strings.Join(r.SpreadModules, ",")
			fmt.Fprintf(tw, "  %s\t%d\t%s\t%d\t%s\t%s\n",
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
				r.Host, r.Module, r.SiteClass,
				r.Locus, r.ExecTarget, det, sigs)
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
			fmt.Fprintf(tw, "  %s\t%s\t%d\t%d\n",
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
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n",
				r.Host, r.Module, r.SiteClass,
				r.Locus, r.ExecTarget, orph)
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Q10: per-host collection health ----------------------------
	textSection(out, a, fmt.Sprintf("Q10 · Per-host collection health (%d hosts)",
		len(report.Q10HostCoverage)))
	fmt.Fprintln(out, "Sort DESC for anomaly outliers, ASC for collection failures.")
	fmt.Fprintln(out)
	if len(report.Q10HostCoverage) == 0 {
		fmt.Fprintln(out, "  no rows")
	} else {
		tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  host\tos_id\trecords\tmodules\tsite_classes\trecent")
		for _, r := range report.Q10HostCoverage {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%d\t%d\t%d\n",
				r.Host, r.OSID, commaInt(r.Records),
				r.Modules, r.SiteClasses, r.RecentRecords)
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
			fmt.Fprintf(tw, "  %s\t%d\t%d\t%s\t%s\t%s\t%s\n",
				r.ExecTarget, r.Hosts, r.Records,
				r.Module, r.SiteClass, r.SampleHost,
				r.SampleLocus)
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Footer ------------------------------------------------------
	fmt.Fprintf(out, "Sources: %d file(s)\n", len(report.Sources))
	return nil
}

// textSection prints a section title with a dashed underline. ANSI bold
// is applied when enabled; the underline uses the visible length so the
// dashes line up regardless of escape sequences.
func textSection(out io.Writer, a *ansi, title string) {
	fmt.Fprintln(out, a.bold(title))
	fmt.Fprintln(out, strings.Repeat("-", visibleLen(title)))
}

// visibleLen returns the printable rune count of s, stripping ANSI SGR
// escapes (\x1b[...m).
func visibleLen(s string) int {
	n := 0
	inEsc := false
	for _, c := range s {
		if inEsc {
			if c == 'm' {
				inEsc = false
			}
			continue
		}
		if c == '\x1b' {
			inEsc = true
			continue
		}
		n++
	}
	return n
}

// barWidth scales a count to a maximum bar width, ensuring any
// non-zero value renders at least one block so the analyst can see
// it.
func barWidth(count, max, scale int) int {
	if max <= 0 || count <= 0 {
		return 0
	}
	w := count * scale / max
	if w < 1 {
		w = 1
	}
	return w
}

func maybeRed(a *ansi, s string, condition bool) string {
	if condition {
		return a.red(s)
	}
	return s
}

// severityValue formats an Overview severity count with the right
// ANSI tint (red for critical-with-hits, orange for high-with-hits,
// plain otherwise). Hits == 0 stays plain regardless of severity so
// the overview reads quiet on a quiet fleet.
func severityValue(a *ansi, count int, sev string) string {
	s := strconv.Itoa(count)
	if count == 0 {
		return s
	}
	switch sev {
	case "critical":
		return a.red(s)
	case "high":
		return a.orange(s)
	}
	return s
}

// colorSeverity returns the severity label tinted to match
// severityValue's count colouring. Used for the Q7 row severity cell.
func colorSeverity(a *ansi, sev string) string {
	switch sev {
	case "critical":
		return a.red(sev)
	case "high":
		return a.orange(sev)
	}
	return sev
}
