package main

import (
	"fmt"
	"io"
	"strings"
)

// renderDiffText writes a human-readable summary of a DiffSet to w.
// ANSI color is opt-in via useColor. Output shape mirrors
// render_text.go's section headers so an operator switching
// between modes does not have to relearn the layout.
//
// This is the minimum viable diff renderer. The follow-up
// (per-Q1..Q11 annotated diff with delta counts in each header
// line) lives in #20 of the v0.3.1 sprint; the current renderer
// surfaces the raw set semantics (Added / Removed / Changed /
// hosts gone / hosts new) which is already operational.
func renderDiffText(w io.Writer, ds DiffSet, title string, useColor bool) error {
	a := &ansi{enabled: useColor}

	fmt.Fprintln(w, a.bold(title))
	fmt.Fprintln(w, strings.Repeat("=", len(title)))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Records  prev=%d  curr=%d  delta=%+d\n",
		ds.PrevTotal, ds.CurrTotal, ds.CurrTotal-ds.PrevTotal)
	fmt.Fprintf(w, "Per-record diff: +%d added  -%d removed  changed=%d  unchanged=%d\n",
		len(ds.Added), len(ds.Removed), len(ds.Changed), ds.UnchangedCount)
	fmt.Fprintf(w, "Host churn:      +%d appeared  -%d disappeared\n",
		len(ds.HostsAppeared), len(ds.HostsDisappeared))
	fmt.Fprintln(w)

	if len(ds.HostsDisappeared) > 0 {
		textSection(w, a, fmt.Sprintf("Hosts disappeared (%d)", len(ds.HostsDisappeared)))
		fmt.Fprintln(w, "Hosts present in prev but absent from curr. Per-record entries")
		fmt.Fprintln(w, "are suppressed; per ADR-0015 this surfaces as a host-level row.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  host                                       records-in-prev")
		for _, h := range ds.HostsDisappeared {
			fmt.Fprintf(w, "  %s %-42s %d\n",
				a.red("-"), trimSample(h.HostSample, 42), h.RecordCount)
		}
		fmt.Fprintln(w)
	}

	if len(ds.HostsAppeared) > 0 {
		textSection(w, a, fmt.Sprintf("Hosts appeared (%d)", len(ds.HostsAppeared)))
		fmt.Fprintln(w, "Hosts present in curr but absent from prev. Per-record entries")
		fmt.Fprintln(w, "are suppressed; per ADR-0015 this surfaces as a host-level row.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  host                                       records-in-curr")
		for _, h := range ds.HostsAppeared {
			fmt.Fprintf(w, "  %s %-42s %d\n",
				a.bold("+"), trimSample(h.HostSample, 42), h.RecordCount)
		}
		fmt.Fprintln(w)
	}

	if len(ds.Added) > 0 {
		textSection(w, a, fmt.Sprintf("+ Added records (%d)", len(ds.Added)))
		fmt.Fprintln(w, "Records present in curr that have no identity match in prev.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  mark host                       module        site_class           locus")
		for _, r := range ds.Added {
			fmt.Fprintf(w, "  %s    %-25s %-13s %-20s %s\n",
				a.bold("+"), trimSample(hostKey(r), 25), r.Module, r.SiteClass, r.Locus)
		}
		fmt.Fprintln(w)
	}

	if len(ds.Removed) > 0 {
		textSection(w, a, fmt.Sprintf("- Removed records (%d)", len(ds.Removed)))
		fmt.Fprintln(w, "Records present in prev that have no identity match in curr.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  mark host                       module        site_class           locus")
		for _, r := range ds.Removed {
			fmt.Fprintf(w, "  %s    %-25s %-13s %-20s %s\n",
				a.red("-"), trimSample(hostKey(r), 25), r.Module, r.SiteClass, r.Locus)
		}
		fmt.Fprintln(w)
	}

	if len(ds.Changed) > 0 {
		textSection(w, a, fmt.Sprintf("D Changed records (%d)", len(ds.Changed)))
		fmt.Fprintln(w, "Records with the same (host, module, site_class, locus) tuple")
		fmt.Fprintln(w, "but different content_norm_sha256 between prev and curr.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  mark host                       module        site_class           locus")
		for _, p := range ds.Changed {
			fmt.Fprintf(w, "  %s    %-25s %-13s %-20s %s\n",
				a.orange("D"), trimSample(hostKey(p.Curr), 25),
				p.Curr.Module, p.Curr.SiteClass, p.Curr.Locus)
			fmt.Fprintf(w, "       prev hash %s\n", shortHash(p.Prev.ContentNormSHA256))
			fmt.Fprintf(w, "       curr hash %s\n", shortHash(p.Curr.ContentNormSHA256))
		}
		fmt.Fprintln(w)
	}

	if len(ds.Added) == 0 && len(ds.Removed) == 0 && len(ds.Changed) == 0 &&
		len(ds.HostsAppeared) == 0 && len(ds.HostsDisappeared) == 0 {
		fmt.Fprintln(w, "No changes between prev and curr.")
	}

	return nil
}

// trimSample shortens an over-long host sample for tabular display.
func trimSample(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "..."
}
