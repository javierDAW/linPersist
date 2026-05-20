// Command linpersist-report reads a directory (or single file) of
// linpersist NDJSON output and produces either a fleet-wide report
// (Q1..Q11) or a per-host dossier. Both modes emit HTML (default,
// self-contained, shareable) or text (terminal-friendly, jump-host
// friendly). See ADR-0008 for the dual-rendering policy and ADR-0012
// for the host-dossier mode.
//
// Usage:
//
//	# Fleet HTML report, default. Self-contained, openable in any browser:
//	linpersist-report -i fleet/ -o report.html
//
//	# Fleet terminal report, default ANSI coloring when stdout is a TTY:
//	linpersist-report -i fleet/ -format text
//
//	# Per-host dossier, HTML:
//	linpersist-report -i fleet/ --host r-web-alp-01 -o web-alp-01.html
//
//	# Per-host dossier, text:
//	linpersist-report -i fleet/ --host r-web-alp-01 -format text
//
//	# Pipe to less, no ANSI:
//	linpersist-report -i fleet/ -format text -color=false | less
//
//	# Both modes work against a single NDJSON file too:
//	linpersist-report -i lab-large/out/lab.ndjson > report.html
//
// Flags:
//
//	-i, -input    Path to a directory containing *.ndjson files OR a
//	              single .ndjson file. Required.
//	-o, -output   Path to write the report. Default stdout.
//	-format       Output format: "html" (default) or "text".
//	-host         If set, produce a per-host dossier for the named
//	              host (matched against host_meta.hostname or host_id)
//	              instead of the fleet report. One host per invocation;
//	              use a shell loop for multiple hosts.
//	-color        Force ANSI color on/off in text mode. Default
//	              "auto" (only when stdout is a TTY).
//	-title        Title shown in the report header. Default
//	              "linpersist report".
//	-version      Print version and exit.
//
// The fleet report covers a fleet of any size up to several tens of
// thousands of hosts. The dossier is single-host per invocation, so
// it scales with the number of records on that one host, not with
// fleet size. For larger fleets, use the DuckDB cookbook directly
// (tools/stack_demo.sql).
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jarmidaw/linpersist/internal/core"
)

// version and commit are stamped at link time, mirroring the agent.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	var (
		input   string
		output  string
		format  string
		host    string
		colorM  string
		title   string
		showVer bool
	)
	flag.StringVar(&input, "i", "", "input: directory of *.ndjson files OR a single .ndjson file")
	flag.StringVar(&input, "input", "", "alias for -i")
	flag.StringVar(&output, "o", "", "output path (default stdout)")
	flag.StringVar(&output, "output", "", "alias for -o")
	flag.StringVar(&format, "format", "html", "output format: html | text")
	flag.StringVar(&host, "host", "", "if set, produce a per-host dossier for the named host (matched against hostname or host_id) instead of the fleet report")
	flag.StringVar(&colorM, "color", "auto", "ANSI color in text mode: auto | on | off")
	flag.StringVar(&title, "title", "linpersist report", "title shown in the report header")
	flag.BoolVar(&showVer, "version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "linpersist-report %s — turn linpersist NDJSON into a report.\n\n", version)
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  linpersist-report -i <dir-or-file> [-o report.html]")
		fmt.Fprintln(os.Stderr, "  linpersist-report -i <dir-or-file> -format text")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Flags:")
		flag.PrintDefaults()
	}
	flag.Parse()

	if showVer {
		fmt.Printf("linpersist-report %s (commit %s)\n", version, commit)
		return
	}
	if input == "" {
		flag.Usage()
		os.Exit(2)
	}
	switch format {
	case "html", "text":
		// ok
	default:
		fmt.Fprintf(os.Stderr, "linpersist-report: unknown -format %q (want html|text)\n", format)
		os.Exit(2)
	}

	res, err := load(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "linpersist-report: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr,
		"linpersist-report: loaded %d records from %d file(s); %d malformed lines skipped\n",
		len(res.Records), len(res.Files), res.Skipped)

	agentVersion := pickAgentVersion(res.Records)

	// Dossier mode forks here. The fleet-wide compute pipeline is
	// skipped entirely when --host is set; the dossier reuses the
	// per-Q compute helpers from stats.go internally where they
	// apply, but the entry point and output shape are different.
	var (
		report  *Report
		dossier *HostDossier
	)
	if host != "" {
		d, candidates := buildDossier(res.Records, host, res.Files, res.Skipped, agentVersion)
		if d == nil {
			fmt.Fprintf(os.Stderr,
				"linpersist-report: host %q has no records in this dataset.\n", host)
			printHostCandidates(os.Stderr, candidates)
			os.Exit(1)
		}
		dossier = d
	} else {
		report = build(res.Records, res.Files, res.Skipped, agentVersion)
	}

	var out io.Writer = os.Stdout
	var outFile *os.File
	if output != "" {
		f, err := os.Create(output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "linpersist-report: create %s: %v\n", output, err)
			os.Exit(1)
		}
		defer f.Close()
		out = f
		outFile = f
	}

	switch format {
	case "html":
		var err error
		if dossier != nil {
			err = renderHost(out, dossier, title)
		} else {
			err = render(out, report, title)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "linpersist-report: render: %v\n", err)
			os.Exit(1)
		}
	case "text":
		useColor := resolveColor(colorM, out, outFile)
		var err error
		if dossier != nil {
			err = renderHostText(out, dossier, title, useColor)
		} else {
			err = renderText(out, report, title, useColor)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "linpersist-report: render: %v\n", err)
			os.Exit(1)
		}
	}
	if output != "" {
		fmt.Fprintf(os.Stderr, "linpersist-report: wrote %s\n", output)
	}
}

// printHostCandidates writes a friendly "did you mean?" listing to w.
// Caps the output at 20 entries plus a "... N more" tail so the
// stderr doesn't blow up on a multi-thousand-host fleet.
func printHostCandidates(w io.Writer, hosts []string) {
	const max = 20
	if len(hosts) == 0 {
		fmt.Fprintln(w, "linpersist-report: dataset contains no host identifiers")
		return
	}
	fmt.Fprintf(w, "linpersist-report: known hosts in this dataset (%d):\n", len(hosts))
	limit := len(hosts)
	if limit > max {
		limit = max
	}
	for _, h := range hosts[:limit] {
		fmt.Fprintf(w, "  %s\n", h)
	}
	if len(hosts) > max {
		fmt.Fprintf(w, "  ... and %d more\n", len(hosts)-max)
	}
}

// resolveColor decides whether the text renderer should emit ANSI
// escapes.
//   - "on"   -> always emit.
//   - "off"  -> never emit.
//   - "auto" -> emit only when stdout is a TTY AND no -o file was set.
//     Piping to a file via -o or via shell redirection produces a
//     clean text artefact suitable for ticket attachments.
func resolveColor(mode string, out io.Writer, outFile *os.File) bool {
	switch mode {
	case "on":
		return true
	case "off":
		return false
	case "auto":
		if outFile != nil {
			return false
		}
		return isTTY(os.Stdout)
	default:
		return false
	}
}

// pickAgentVersion returns the agent_version string most commonly
// observed in the loaded records. Hosts running mismatched agent
// versions show up as multiple values; the report surfaces only the
// modal one in the header (the analyst can still query the data by
// agent_version directly if needed).
func pickAgentVersion(records []core.Record) string {
	counts := map[string]int{}
	for _, r := range records {
		if r.AgentVersion != "" {
			counts[r.AgentVersion]++
		}
	}
	var best string
	var bestN int
	for v, n := range counts {
		if n > bestN {
			best, bestN = v, n
		}
	}
	return best
}
