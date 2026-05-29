package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jarmidaw/linpersist/internal/core"
)

// evilPayload bundles the terminal-control sequences a compromised
// monitored host could smuggle into a path, snippet or exec_target to
// scrub its own implant row out of the text report: a line-erase + CR
// (overwrite the current line), an OSC title/clipboard set, a bare
// bell/backspace, and a C1 CSI introducer (U+009B).
const evilPayload = "evil\x1b[2K\rhidden\x1b]0;pwned\x07\x08A"

// assertNoTerminalControls fails if out carries any byte a hostile
// record field could weaponise on a TTY: ESC (0x1b), CR (0x0d), the
// other C0 controls, or DEL (0x7f). Newline and tab are the renderer's
// own structural whitespace and are allowed.
func assertNoTerminalControls(t *testing.T, out []byte) {
	t.Helper()
	for i, b := range out {
		if b == '\n' || b == '\t' {
			continue
		}
		if b < 0x20 || b == 0x7f {
			start := i - 20
			if start < 0 {
				start = 0
			}
			t.Fatalf("control byte 0x%02x at offset %d; context %q", b, i, out[start:i+1])
		}
	}
}

func TestSafeCell(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"clean ascii", "/etc/cron.d/job", "/etc/cron.d/job"},
		{"multibyte utf8 preserved", "café—naïve", "café—naïve"},
		{"esc csi escaped", "a\x1b[2Kb", `a\x1b[2Kb`},
		{"carriage return escaped", "a\rb", `a\x0db`},
		{"bell and backspace", "x\x07\x08y", `x\x07\x08y`},
		{"c1 csi introducer escaped", "zA", `z\x9bA`},
		{"tab escaped (would corrupt columns)", "a\tb", `a\x09b`},
		{"newline escaped (would forge a row)", "a\nb", `a\x0ab`},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := safeCell(c.in); got != c.want {
				t.Errorf("safeCell(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}

	// Whatever safeCell emits must itself be free of control bytes —
	// that is the entire point.
	assertNoTerminalControls(t, []byte(safeCell(evilPayload)))
}

// fleetReportWithEvilFields returns a Report whose every analyst-facing
// string cell carries evilPayload, so a render that fails to sanitize
// any one of them shows up as a control byte in the output.
func fleetReportWithEvilFields() *Report {
	return &Report{
		AgentVersion: evilPayload,
		Overview: Overview{
			TotalHosts:     1,
			ByModule:       []NamedCount{{Name: evilPayload, Records: 1, Hosts: 1}},
			BySiteClass:    []NamedCount{{Name: evilPayload, Records: 1, Hosts: 1}},
			ByOSID:         []NamedCount{{Name: evilPayload, Records: 1, Hosts: 1}},
			BySignal:       []NamedCount{{Name: evilPayload, Records: 1, Hosts: 1}},
			SeverityCounts: map[string]int{"critical": 1},
		},
		Q1Singletons: []SingletonRow{{
			Module: evilPayload, SiteClass: evilPayload, ContentNorm: evilPayload,
			SampleHost: evilPayload, SampleLocus: evilPayload, SampleSnippet: evilPayload,
		}},
		Q2LocusSingletons: []LocusSingletonRow{{
			Module: evilPayload, SiteClass: evilPayload, Locus: evilPayload,
			ContentNorm: evilPayload, SampleHost: evilPayload, SampleSnippet: evilPayload,
		}},
		Q3PeerGroupSingletons: []PeerGroupRow{{
			OSID: evilPayload, Module: evilPayload, SiteClass: evilPayload,
			ContentNorm: evilPayload, PeerSize: 3, SampleHost: evilPayload, SampleLocus: evilPayload,
		}},
		Q4ImplantFingerprint: []ImplantRow{{
			Host: evilPayload, Module: evilPayload, SiteClass: evilPayload,
			Locus: evilPayload, ExecTarget: evilPayload, Signals: []string{evilPayload},
		}},
		Q5SignalDistribution: []SignalRow{{Module: evilPayload, Signal: evilPayload, Hosts: 1, Records: 1}},
		Q6ExecTargetStacking: []ExecTargetRow{{
			ExecTargetSHA256: evilPayload, Hosts: 1, Records: 1, Modules: 1,
			SampleTarget: evilPayload, SpreadModules: []string{evilPayload},
		}},
		Q7ImplantRollCall: []RollCallRow{{
			Host: evilPayload, Module: evilPayload, SiteClass: evilPayload,
			Locus: evilPayload, ExecTarget: evilPayload, TriageSignals: []string{evilPayload},
			MatchedDetections: []string{evilPayload}, MaxSeverity: "critical",
		}},
		Q8MtimeConcentration: []MtimeConcRow{{Host: evilPayload, Module: evilPayload, RecentRecords: 5, RecentLoci: 5}},
		Q9ExecInTmp: []ExecInTmpRow{{
			Host: evilPayload, Module: evilPayload, SiteClass: evilPayload,
			Locus: evilPayload, ExecTarget: evilPayload, IsOrphan: true,
		}},
		Q10HostCoverage: []HostCoverageRow{{Host: evilPayload, OSID: evilPayload, Records: 1, Modules: 1, SiteClasses: 1, RecentRecords: 1}},
		Q11OrphanOutsideTmp: []OrphanOutsideTmpRow{{
			ExecTarget: evilPayload, Hosts: 1, Records: 1, Module: evilPayload,
			SiteClass: evilPayload, SampleHost: evilPayload, SampleLocus: evilPayload,
		}},
		Q12BasenameClustering: []BasenameClusterRow{{
			Basename: evilPayload, Hosts: 1, Records: 1, Modules: []string{evilPayload},
			SampleHost: evilPayload, SampleExecTarget: evilPayload,
		}},
		MITRECoverage: MITRECoverageSection{
			TotalTechniques:     1,
			SurfacingTechniques: 1,
			Rows: []MITRECoverageRow{{
				TechniqueID: evilPayload, Status: statusSurfacing, Records: 1, Hosts: 1,
				SiteClasses: []string{evilPayload},
			}},
		},
	}
}

func TestRenderTextNeutralizesTerminalEscapes(t *testing.T) {
	report := fleetReportWithEvilFields()
	for _, color := range []bool{false, true} {
		var buf bytes.Buffer
		if err := renderText(&buf, report, "evil-report", color); err != nil {
			t.Fatalf("renderText(color=%v): %v", color, err)
		}
		// With color off there are no legitimate escapes at all, so the
		// output must be wholly free of control bytes. (With color on the
		// renderer emits its own SGR escapes, which is why we only assert
		// the strict-clean property in the color=false pass.)
		if !color {
			assertNoTerminalControls(t, buf.Bytes())
		}
		// The literal attack sequence must never survive verbatim in
		// either mode.
		if bytes.Contains(buf.Bytes(), []byte("\x1b[2K")) {
			t.Fatalf("color=%v: raw line-erase sequence survived into output", color)
		}
	}
}

func TestRenderHostTextNeutralizesTerminalEscapes(t *testing.T) {
	d := &HostDossier{
		AgentVersion: evilPayload,
		Host: HostHeader{
			Hostname: evilPayload, HostID: evilPayload, OSID: evilPayload, OSVersion: evilPayload,
			Kernel: evilPayload, Arch: evilPayload, BootID: evilPayload, Tags: []string{evilPayload},
		},
		HostRecords: 1, HostModules: 1, HostSiteClasses: 1, FleetHosts: 1, FleetRecords: 1,
		SignalPanel:      []HostSignalRow{{Signal: evilPayload, HostRecords: 1, FleetHosts: 1, FleetTotal: 1, Description: evilPayload, IsWarn: true}},
		Implants:         []ImplantRow{{Host: evilPayload, Module: evilPayload, SiteClass: evilPayload, Locus: evilPayload, ExecTarget: evilPayload, Signals: []string{evilPayload}}},
		RollCall:         []RollCallRow{{Module: evilPayload, SiteClass: evilPayload, Locus: evilPayload, ExecTarget: evilPayload, TriageSignals: []string{evilPayload}}},
		Singletons:       []HostSingletonRow{{Module: evilPayload, SiteClass: evilPayload, Locus: evilPayload, ContentNorm: evilPayload, Snippet: evilPayload}},
		LocusSingletons:  []HostLocusSingletonRow{{Module: evilPayload, SiteClass: evilPayload, Locus: evilPayload, ContentNorm: evilPayload, Snippet: evilPayload}},
		ExecInTmp:        []ExecInTmpRow{{Module: evilPayload, SiteClass: evilPayload, Locus: evilPayload, ExecTarget: evilPayload, IsOrphan: true}},
		OrphanOutsideTmp: []OrphanOutsideTmpRow{{ExecTarget: evilPayload, Records: 1, Module: evilPayload, SiteClass: evilPayload, SampleLocus: evilPayload, SampleSnippet: evilPayload}},
		MtimeSpikes:      []MtimeConcRow{{Module: evilPayload, RecentRecords: 5, RecentLoci: 5}},
		ModuleCoverage:   []HostModuleRow{{Module: evilPayload, Records: 0, SiteClasses: 0, FleetMedian: 3, IsGap: true}},
	}
	var buf bytes.Buffer
	if err := renderHostText(&buf, d, "evil-dossier", false); err != nil {
		t.Fatalf("renderHostText: %v", err)
	}
	assertNoTerminalControls(t, buf.Bytes())
}

func TestRenderDiffTextNeutralizesTerminalEscapes(t *testing.T) {
	rec := func() core.Record {
		return core.Record{Module: evilPayload, SiteClass: evilPayload, Locus: evilPayload, HostID: evilPayload, ContentNormSHA256: evilPayload}
	}
	ds := DiffSet{
		Added:            []core.Record{rec()},
		Removed:          []core.Record{rec()},
		Changed:          []RecordPair{{Prev: rec(), Curr: rec()}},
		HostsAppeared:    []HostChange{{HostID: evilPayload, HostSample: evilPayload, RecordCount: 1}},
		HostsDisappeared: []HostChange{{HostID: evilPayload, HostSample: evilPayload, RecordCount: 1}},
		PrevTotal:        1, CurrTotal: 2,
	}
	var buf bytes.Buffer
	if err := renderDiffText(&buf, ds, "evil-diff", false); err != nil {
		t.Fatalf("renderDiffText: %v", err)
	}
	assertNoTerminalControls(t, buf.Bytes())
}

// TestReadFileSkipsOversizedLine asserts that a single line exceeding
// maxLineBytes is counted as one skipped line and the surrounding valid
// records still load — one hostile/corrupt host must not abort the whole
// fleet report (F2).
func TestReadFileSkipsOversizedLine(t *testing.T) {
	good := `{"module":"cron","site_class":"cron.d","locus":"/a"}`
	huge := `{"module":"x","locus":"` + strings.Repeat("A", maxLineBytes+16) + `"}`
	content := good + "\n" + huge + "\n" + good + "\n"

	res := &loadResult{}
	if err := readFileFromString(t, content, res); err != nil {
		t.Fatalf("readFile returned fatal error on oversized line: %v", err)
	}
	if len(res.Records) != 2 {
		t.Fatalf("got %d records, want 2 (oversized line dropped, two good lines kept)", len(res.Records))
	}
	if res.Skipped != 1 {
		t.Fatalf("got Skipped=%d, want 1 (the oversized line)", res.Skipped)
	}
}

// readFileFromString writes content to a temp file and runs readFile on
// it, so the bufio bounded-read path is exercised end to end.
func readFileFromString(t *testing.T, content string, res *loadResult) error {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "in.ndjson")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return readFile(p, res)
}
