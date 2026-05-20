// Text renderer for the per-host dossier.
//
// Mirrors the dual-rendering policy in ADR-0008: render_text.go covers
// the fleet report (Q1..Q11), this file covers the dossier. Both
// renderers share helpers (ansi, textSection, maybeRed, commaInt,
// snippetTrim) so behaviour on a TTY stays consistent across the two
// modes.
//
// Layout (top-to-bottom):
//
//   1. Title + generated line.
//   2. Host header.
//   3. Headline counts (records, modules, signal count, dossier
//      Q-counts).
//   4. Signal panel — rarest fleet-wide signal at the top.
//   5. Implants                       (Q4)
//   6. Implant roll-call              (Q7)
//   7. Fleet-singleton records        (Q1 filtered to this host)
//   8. Per-locus fleet singletons     (Q2 filtered to this host)
//   9. Exec targets in tmp-class      (Q9)
//  10. Orphan exec outside tmp        (Q11 single-host variant)
//  11. Recent-mtime concentration     (Q8 single-host variant)
//  12. Module coverage / gap detector
//
// Q3 / Q5 / Q6 / Q10 are intentionally absent — they are fleet
// aggregates and contain no per-host insight.

package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
)

func renderHostText(out io.Writer, d *HostDossier, title string, color bool) error {
	a := &ansi{enabled: color}

	// --- Title -------------------------------------------------------
	fmt.Fprintln(out, a.bold(title))
	fmt.Fprintln(out, strings.Repeat("=", len(title)))
	fmt.Fprintf(out, "generated %s · host dossier for %s",
		d.Generated.Format("2006-01-02 15:04 UTC"),
		hostLabel(d.Host))
	if d.AgentVersion != "" {
		fmt.Fprintf(out, " · agent %s", d.AgentVersion)
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out)

	// --- Host header -------------------------------------------------
	textSection(out, a, "Host")
	if d.Host.Hostname != "" {
		fmt.Fprintf(out, "  hostname:     %s\n", d.Host.Hostname)
	}
	if d.Host.HostID != "" {
		fmt.Fprintf(out, "  host_id:      %s\n", d.Host.HostID)
	}
	if d.Host.OSID != "" {
		os := d.Host.OSID
		if d.Host.OSVersion != "" {
			os = os + " " + d.Host.OSVersion
		}
		fmt.Fprintf(out, "  os:           %s\n", os)
	}
	if d.Host.Kernel != "" {
		fmt.Fprintf(out, "  kernel:       %s\n", d.Host.Kernel)
	}
	if d.Host.Arch != "" {
		fmt.Fprintf(out, "  arch:         %s\n", d.Host.Arch)
	}
	if d.Host.BootID != "" {
		fmt.Fprintf(out, "  boot_id:      %s\n", d.Host.BootID)
	}
	if len(d.Host.Tags) > 0 {
		fmt.Fprintf(out, "  tags:         %s\n", strings.Join(d.Host.Tags, ", "))
	}
	if d.Host.HasCollected {
		fmt.Fprintf(out, "  collected_at: %s\n", d.Host.CollectedAt.UTC().Format("2006-01-02 15:04 UTC"))
	}
	fmt.Fprintln(out)

	// --- Headline counts --------------------------------------------
	textSection(out, a, "Summary")
	rows := []struct {
		k string
		v string
	}{
		{"records (host / fleet)", fmt.Sprintf("%s / %s", commaInt(d.HostRecords), commaInt(d.FleetRecords))},
		{"modules covered", fmt.Sprintf("%d", d.HostModules)},
		{"site_classes covered", fmt.Sprintf("%d", d.HostSiteClasses)},
		{"distinct signals fired", strconv.Itoa(len(d.SignalPanel))},
		{"Q4 implant hits", maybeRed(a, strconv.Itoa(len(d.Implants)), len(d.Implants) > 0)},
		{"Q7 roll-call", maybeRed(a, strconv.Itoa(len(d.RollCall)), len(d.RollCall) > 0)},
		{"Q1 fleet-singletons", strconv.Itoa(len(d.Singletons))},
		{"Q11 orphan outside tmp", maybeRed(a, strconv.Itoa(len(d.OrphanOutsideTmp)), len(d.OrphanOutsideTmp) > 0)},
		{"Q8 mtime spikes (modules)", strconv.Itoa(len(d.MtimeSpikes))},
		{"module gaps", maybeRed(a, strconv.Itoa(countGaps(d.ModuleCoverage)), countGaps(d.ModuleCoverage) > 0)},
	}
	for _, r := range rows {
		fmt.Fprintf(out, "  %-28s %s\n", r.k+":", r.v)
	}
	fmt.Fprintln(out)

	// --- Signal panel ------------------------------------------------
	textSection(out, a, fmt.Sprintf("Signals on this host (%d) — rarest first", len(d.SignalPanel)))
	if len(d.SignalPanel) == 0 {
		fmt.Fprintln(out, "no rows")
	} else {
		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  signal\thost_records\tfleet_hosts\tfleet_pct\tdescription")
		for _, s := range d.SignalPanel {
			name := s.Signal
			if s.IsWarn {
				name = a.red(name)
			}
			if s.IsUnknown {
				// Unknown signal: surface the fact, do not lie about description.
				name = name + " (unknown)"
			}
			pct := "n/a"
			if s.FleetTotal > 0 {
				pct = fmt.Sprintf("%d%%", s.FleetHosts*100/s.FleetTotal)
			}
			fmt.Fprintf(tw, "  %s\t%d\t%d/%d\t%s\t%s\n",
				name,
				s.HostRecords,
				s.FleetHosts, s.FleetTotal,
				pct,
				s.Description)
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Implants (Q4) -----------------------------------------------
	textSection(out, a, fmt.Sprintf("Implants — orphan + interpreter_in_tmp (%d)", len(d.Implants)))
	if len(d.Implants) == 0 {
		fmt.Fprintln(out, "no rows")
	} else {
		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  module\tsite_class\tlocus\texec_target\tsignals")
		for _, r := range d.Implants {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n",
				r.Module, r.SiteClass, r.Locus, r.ExecTarget,
				strings.Join(r.Signals, ","))
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Roll-call (Q7) ----------------------------------------------
	textSection(out, a, fmt.Sprintf("Implant roll-call (%d)", len(d.RollCall)))
	if len(d.RollCall) == 0 {
		fmt.Fprintln(out, "no rows")
	} else {
		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  module\tsite_class\tlocus\texec_target\ttriage_signals")
		for _, r := range d.RollCall {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n",
				r.Module, r.SiteClass, r.Locus, r.ExecTarget,
				strings.Join(r.TriageSignals, ","))
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Fleet singletons present on this host (Q1) -----------------
	textSection(out, a, fmt.Sprintf("Fleet-unique records on this host (%d)", len(d.Singletons)))
	fmt.Fprintln(out, "(content_norm appears on no other fleet host)")
	if len(d.Singletons) == 0 {
		fmt.Fprintln(out, "no rows")
	} else {
		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  module\tsite_class\tlocus\tcontent_norm\tsnippet")
		for _, r := range d.Singletons {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n",
				r.Module, r.SiteClass, r.Locus, r.ContentNorm, r.Snippet)
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Per-locus fleet singletons (Q2) -----------------------------
	textSection(out, a, fmt.Sprintf("Per-locus fleet-unique records (%d)", len(d.LocusSingletons)))
	if len(d.LocusSingletons) == 0 {
		fmt.Fprintln(out, "no rows")
	} else {
		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  module\tsite_class\tlocus\tcontent_norm\tsnippet")
		for _, r := range d.LocusSingletons {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n",
				r.Module, r.SiteClass, r.Locus, r.ContentNorm, r.Snippet)
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Exec targets in tmp-class (Q9) -------------------------------
	textSection(out, a, fmt.Sprintf("Exec targets in /tmp /var/tmp /dev/shm /run/shm (%d)", len(d.ExecInTmp)))
	if len(d.ExecInTmp) == 0 {
		fmt.Fprintln(out, "no rows")
	} else {
		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  module\tsite_class\tlocus\texec_target\tarmed?")
		for _, r := range d.ExecInTmp {
			armed := "yes"
			if r.IsOrphan {
				armed = "no (orphan)"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n",
				r.Module, r.SiteClass, r.Locus, r.ExecTarget, armed)
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Orphan outside tmp (Q11 host-scoped) ------------------------
	textSection(out, a, fmt.Sprintf("Orphan exec_target outside tmp-class dirs (%d)", len(d.OrphanOutsideTmp)))
	fmt.Fprintln(out, "(non_package_path, exec_target not under /tmp class)")
	if len(d.OrphanOutsideTmp) == 0 {
		fmt.Fprintln(out, "no rows")
	} else {
		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  exec_target\trecords\tmodule\tsite_class\tsample_locus\tsnippet")
		for _, r := range d.OrphanOutsideTmp {
			fmt.Fprintf(tw, "  %s\t%d\t%s\t%s\t%s\t%s\n",
				r.ExecTarget, r.Records, r.Module, r.SiteClass,
				r.SampleLocus, r.SampleSnippet)
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Recent-mtime concentration (Q8 host-scoped) ------------------
	textSection(out, a, fmt.Sprintf("Recent-mtime concentration per module (%d) — >=5 records in 7d", len(d.MtimeSpikes)))
	if len(d.MtimeSpikes) == 0 {
		fmt.Fprintln(out, "no rows")
	} else {
		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  module\trecent_records\trecent_loci")
		for _, r := range d.MtimeSpikes {
			fmt.Fprintf(tw, "  %s\t%d\t%d\n", r.Module, r.RecentRecords, r.RecentLoci)
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	// --- Module coverage --------------------------------------------
	gaps := countGaps(d.ModuleCoverage)
	heading := fmt.Sprintf("Module coverage on this host (%d modules", len(d.ModuleCoverage))
	if gaps > 0 {
		heading = fmt.Sprintf("%s, %s)", heading, a.red(fmt.Sprintf("%d gap", gaps)))
	} else {
		heading = heading + ")"
	}
	textSection(out, a, heading)
	fmt.Fprintln(out, "(records on this host vs fleet median for the module; gaps surface first)")
	if len(d.ModuleCoverage) == 0 {
		fmt.Fprintln(out, "no rows")
	} else {
		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  module\trecords\tsite_classes\tfleet_median\tnote")
		for _, r := range d.ModuleCoverage {
			note := ""
			if r.IsGap {
				note = a.red("GAP — module expected, this host emitted nothing")
			}
			fmt.Fprintf(tw, "  %s\t%d\t%d\t%d\t%s\n",
				r.Module, r.Records, r.SiteClasses, r.FleetMedian, note)
		}
		tw.Flush()
	}
	fmt.Fprintln(out)

	return nil
}

// hostLabel returns a printable representation of the host for the
// dossier header. Prefers hostname (most familiar to the analyst);
// falls back to host_id if no hostname is in the dataset.
func hostLabel(h HostHeader) string {
	if h.Hostname != "" {
		return h.Hostname
	}
	if h.HostID != "" {
		return h.HostID
	}
	return "<unknown>"
}

// countGaps reports how many module-coverage rows are flagged IsGap.
func countGaps(rows []HostModuleRow) int {
	n := 0
	for _, r := range rows {
		if r.IsGap {
			n++
		}
	}
	return n
}
