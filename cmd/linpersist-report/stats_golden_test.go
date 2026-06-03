package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

// updateGolden controls whether the golden test rewrites its expected
// files or asserts equality. The flag exists so the safety net can be
// (re)generated deterministically when an intentional output change
// lands; ordinary CI runs use the default (assert).
//
// Usage:
//
//	go test ./cmd/linpersist-report -run TestBuild_GoldenSmoke -update
var updateGolden = flag.Bool("update", false,
	"rewrite cmd/linpersist-report golden files instead of asserting")

// goldenDir is where the smoke golden expected files live. Keeping
// them under internal/testdata/golden/ mirrors the per-module fixture
// convention enforced by the rest of the repo.
const goldenDir = "../../internal/testdata/golden/stats"

// TestBuild_GoldenSmoke is the safety net for any future restructuring
// of stats.go (e.g. the planned Q-compute fan-out). It pins the
// end-to-end pipeline — build() over a fixed synthetic fixture, then
// renderText() — so any change to output shape, ordering, or content
// surfaces as a diff against a committed golden file. The fixture
// intentionally exercises Q1 (singleton), Q4 (fingerprint match),
// Q7 (detection roll-call), Q11 (orphan outside tmp), and Q12
// (basename clustering) so the dominant codepaths are covered without
// requiring a multi-megabyte capture.
func TestBuild_GoldenSmoke(t *testing.T) {
	records := goldenFixture()
	r := build(records, []string{"fixture.ndjson"}, 0, "linpersist-test", 3)
	// Pin the generated timestamp so the golden does not drift on time.
	r.Generated = time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)

	var buf bytes.Buffer
	if err := renderText(&buf, r, "Test report", false); err != nil {
		t.Fatalf("renderText: %v", err)
	}
	got := buf.Bytes()

	goldenPath := filepath.Join(goldenDir, "build_smoke.text.golden")

	// HTML rendering reuses the same Report; rendering it through the
	// template path catches Go-template-level regressions independently
	// of the text channel.
	var htmlBuf bytes.Buffer
	if err := renderHTML(&htmlBuf, r, "Test report"); err != nil {
		t.Fatalf("renderHTML: %v", err)
	}
	htmlGot := htmlBuf.Bytes()
	htmlGoldenPath := filepath.Join(goldenDir, "build_smoke.html.golden")

	if *updateGolden {
		if err := os.MkdirAll(goldenDir, 0o755); err != nil {
			t.Fatalf("mkdir golden: %v", err)
		}
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		if err := os.WriteFile(htmlGoldenPath, htmlGot, 0o644); err != nil {
			t.Fatalf("write html golden: %v", err)
		}
		t.Logf("wrote text golden %s (%d bytes), html golden %s (%d bytes)",
			goldenPath, len(got), htmlGoldenPath, len(htmlGot))
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden %s: %v (run `go test -run TestBuild_GoldenSmoke -update` to seed)", goldenPath, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("text golden drift. First differing line:\n%s",
			firstDiff(string(got), string(want)))
		dumpPath := goldenPath + ".actual"
		_ = os.WriteFile(dumpPath, got, 0o644)
		t.Logf("actual output written to %s for inspection", dumpPath)
	}

	htmlWant, err := os.ReadFile(htmlGoldenPath)
	if err != nil {
		t.Fatalf("read html golden %s: %v", htmlGoldenPath, err)
	}
	if !bytes.Equal(htmlGot, htmlWant) {
		t.Errorf("HTML golden drift (%d bytes got vs %d want)",
			len(htmlGot), len(htmlWant))
		_ = os.WriteFile(htmlGoldenPath+".actual", htmlGot, 0o644)
	}
}

// goldenFixture builds a small, deterministic record set exercising
// the major Q codepaths. Field choices follow the existing
// stats_test.go conventions (hostID strings, content_norm hashes as
// human-readable strings, signals as bare slices).
func goldenFixture() []core.Record {
	now := time.Date(2026, 5, 22, 11, 0, 0, 0, time.UTC)
	recent := now.Add(-2 * 24 * time.Hour)

	mkRec := func(host, osID, module, siteClass, locus, content string, signals []string, execTarget string) core.Record {
		size := int64(len(content))
		uid := uint32(0)
		return core.Record{
			HostID: host,
			HostMeta: core.HostMeta{
				HostnameHash: host,
				OSID:         osID,
				PkgMgr:       "dpkg", // realistic fleet: provenance ran (no degraded banner)
			},
			Module:            module,
			SiteClass:         siteClass,
			Locus:             locus,
			ContentNormSHA256: content,
			ContentSnippet:    content,
			MTime:             &recent,
			Size:              &size,
			OwnerUID:          &uid,
			Signals:           signals,
			ExecTarget:        execTarget,
			MITRE:             []string{"T1053.003"},
		}
	}

	var recs []core.Record
	// Q1 singleton: cron entry unique to host h1.
	recs = append(recs, mkRec("h1", "ubuntu", "cron", "cron.d",
		"/etc/cron.d/singleton-impl", "cron-singleton-norm",
		[]string{core.SignalNonPackagePath, core.SignalExecTargetOrphan},
		"/tmp/beacon.sh"))

	// Q4 implant fingerprint: same content_norm across h2 and h3 on
	// the same locus (textbook implant shape).
	for _, h := range []string{"h2", "h3"} {
		recs = append(recs, mkRec(h, "ubuntu", "cron", "cron.d",
			"/etc/cron.d/implant", "implant-norm",
			[]string{core.SignalNonPackagePath, core.SignalInterpreterInTmp},
			"/tmp/payload.sh"))
	}

	// Q11 orphan outside /tmp: exec_target missing, not under /tmp.
	recs = append(recs, mkRec("h4", "rhel", "systemd", "systemd.unit",
		"/etc/systemd/system/beacon.service", "beacon-svc-norm",
		[]string{core.SignalExecTargetOrphan, core.SignalNonPackagePath},
		"/opt/notthere/agent"))

	// Q12 basename cluster: same logical name under cron + systemd +
	// profile (3-arm worm).
	recs = append(recs, mkRec("h5", "debian", "cron", "cron.daily",
		"/etc/cron.daily/sync", "sync-cron-norm",
		[]string{core.SignalNonPackagePath}, "/usr/local/bin/sync"))
	recs = append(recs, mkRec("h5", "debian", "systemd", "systemd.unit",
		"/etc/systemd/system/sync.service", "sync-svc-norm",
		[]string{core.SignalNonPackagePath}, "/usr/local/bin/sync"))
	recs = append(recs, mkRec("h5", "debian", "profile", "profile.d",
		"/etc/profile.d/sync.sh", "sync-profile-norm",
		[]string{core.SignalNonPackagePath}, "/usr/local/bin/sync"))

	// Fleet-baseline noise so peer-groups have size >= 3 and Q3 has
	// material to work with.
	for i, h := range []string{"h1", "h2", "h3", "h4", "h5", "h6"} {
		osID := "ubuntu"
		if i >= 3 {
			osID = "rhel"
		}
		recs = append(recs, mkRec(h, osID, "passwd", "passwd.users",
			"/etc/passwd:root", "baseline-passwd-norm",
			nil, ""))
	}

	return recs
}

// firstDiff returns a short snippet showing the first line that
// differs between got and want. Used in golden assertion failures to
// keep the failure message bounded.
func firstDiff(got, want string) string {
	gotLines := strings.Split(got, "\n")
	wantLines := strings.Split(want, "\n")
	n := len(gotLines)
	if len(wantLines) < n {
		n = len(wantLines)
	}
	for i := 0; i < n; i++ {
		if gotLines[i] != wantLines[i] {
			return "line " + itoa(i+1) + ":\n  got:  " + gotLines[i] + "\n  want: " + wantLines[i]
		}
	}
	if len(gotLines) != len(wantLines) {
		return "line count differs: got=" + itoa(len(gotLines)) + " want=" + itoa(len(wantLines))
	}
	return "(no diff found but bytes differ — likely trailing whitespace)"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// renderHTML is a thin alias for the package-level HTML entrypoint
// so the golden test does not need to know whether the function is
// called render, renderReport, or something else.
func renderHTML(out io.Writer, r *Report, title string) error {
	return render(out, r, title)
}
