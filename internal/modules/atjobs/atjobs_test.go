package atjobs

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

var updateGolden = flag.Bool("update", false, "rewrite expected.ndjson files instead of comparing")

func shouldUpdateGolden() bool {
	if updateGolden != nil && *updateGolden {
		return true
	}
	return os.Getenv("LINPERSIST_UPDATE_GOLDEN") == "1"
}

var fixedMtime = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
var fixedNow = time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC)

func TestGolden(t *testing.T) {
	goldenDir := filepath.Join("..", "..", "testdata", "golden", "atjobs")
	entries, err := os.ReadDir(goldenDir)
	if err != nil {
		t.Fatalf("read golden dir %s: %v", goldenDir, err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		t.Run(name, func(t *testing.T) {
			runGolden(t, filepath.Join(goldenDir, name))
		})
	}
}

func runGolden(t *testing.T, caseDir string) {
	t.Helper()
	rootfsSrc := filepath.Join(caseDir, "rootfs")
	if _, err := os.Stat(rootfsSrc); err != nil {
		t.Fatalf("no rootfs/ under %s: %v", caseDir, err)
	}
	tmp := t.TempDir()
	if err := copyTree(rootfsSrc, tmp); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if err := normalizeFixturePerms(tmp); err != nil {
		t.Fatalf("perms: %v", err)
	}
	if err := stampMtimes(tmp, fixedMtime); err != nil {
		t.Fatalf("stamp: %v", err)
	}
	mod := New(Options{Root: tmp, Now: func() time.Time { return fixedNow }})
	var captured []core.Record
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := mod.Collect(ctx, func(r core.Record) { captured = append(captured, r) }); err != nil {
		t.Logf("Collect: %v", err)
	}
	for i := range captured {
		redactVolatile(&captured[i])
	}
	sort.Slice(captured, func(i, j int) bool {
		if captured[i].Locus != captured[j].Locus {
			return captured[i].Locus < captured[j].Locus
		}
		return captured[i].ContentNormSHA256 < captured[j].ContentNormSHA256
	})
	var got bytes.Buffer
	enc := json.NewEncoder(&got)
	enc.SetEscapeHTML(false)
	for _, r := range captured {
		if err := enc.Encode(r); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	expectedPath := filepath.Join(caseDir, "expected.ndjson")
	if shouldUpdateGolden() {
		if err := os.WriteFile(expectedPath, got.Bytes(), 0o644); err != nil {
			t.Fatalf("write expected: %v", err)
		}
		fmt.Fprintf(os.Stderr, "GOLDEN UPDATED: %s (%d records, %d bytes)\n",
			expectedPath, len(captured), got.Len())
		return
	}
	want, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("read expected (run with -update OR env LINPERSIST_UPDATE_GOLDEN=1 to generate): %v", err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("mismatch for case %s\n--- want (%d bytes) ---\n%s\n--- got (%d bytes) ---\n%s",
			filepath.Base(caseDir), len(want), want, got.Len(), got.String())
	}
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		out, err := os.Create(target)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
}

func normalizeFixturePerms(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Chmod(path, 0o755)
		}
		return os.Chmod(path, 0o644)
	})
}

func stampMtimes(root string, when time.Time) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chtimes(path, when, when)
	})
}

func redactVolatile(rec *core.Record) {
	zero := uint32(0)
	rec.OwnerUID = &zero
	rec.OwnerGID = &zero
	rec.CTime = nil
	rec.ATime = nil
	rec.Signals = dropSignal(rec.Signals, core.SignalNonRootOwner)
}

func dropSignal(sigs []string, name string) []string {
	if len(sigs) == 0 {
		return nil
	}
	out := make([]string, 0, len(sigs))
	for _, s := range sigs {
		if s == name {
			continue
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// --- Parser unit tests ---

// TestExtractBody_StructuredJob: the heredoc body is captured and the
// atd header (umask, HOME=, PATH=, ...) is stripped.
func TestExtractBody_StructuredJob(t *testing.T) {
	raw := []byte(`#!/bin/sh
# atrun uid=1000 gid=1000
# mail alice 0
umask 22
HOME=/home/alice; export HOME
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; export PATH
LOGNAME=alice; export LOGNAME
USER=alice; export USER
SHELL=/bin/bash; export SHELL
TERM=xterm; export TERM
cd /home/alice || {
	 echo 'Execution directory inaccessible' >&2
	 exit 1
}
${SHELL:-/bin/sh} << 'marcinDELIMITER567a8b9c'
echo "hello from at"
/usr/local/bin/run-thing --once
marcinDELIMITER567a8b9c
`)
	body, structured := extractBody(raw)
	if !structured {
		t.Fatal("structured=false; want true")
	}
	want := "echo \"hello from at\"\n/usr/local/bin/run-thing --once\n"
	if string(body) != want {
		t.Errorf("body =\n%s\nwant:\n%s", body, want)
	}
}

// TestExtractBody_Unstructured: a hand-edited spool file without the
// heredoc opener falls back to structured=false and returns the raw
// input.
func TestExtractBody_Unstructured(t *testing.T) {
	raw := []byte("# Hand-edited spool file.\n/opt/x/run --silent\n")
	body, structured := extractBody(raw)
	if structured {
		t.Errorf("structured=true; want false on hand-edited spool")
	}
	if !bytes.Equal(body, raw) {
		t.Errorf("body diverged from raw on unstructured fallback")
	}
}

// TestNormalize_EquivalentJobsCollapse: the critical property for
// stacking. Two at jobs scheduled by DIFFERENT users (different HOME,
// LOGNAME, PATH) but executing the SAME inner command must produce
// the same content_norm_sha256.
func TestNormalize_EquivalentJobsCollapse(t *testing.T) {
	jobA := []byte(`#!/bin/sh
# atrun uid=1000 gid=1000
umask 22
HOME=/home/alice; export HOME
PATH=/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin; export PATH
LOGNAME=alice; export LOGNAME
USER=alice; export USER
${SHELL:-/bin/sh} << 'TAG1'
/usr/local/bin/run-thing --once
TAG1
`)
	jobB := []byte(`#!/bin/sh
# atrun uid=2001 gid=2001
umask 22
HOME=/home/bob; export HOME
PATH=/usr/bin:/bin; export PATH
LOGNAME=bob; export LOGNAME
USER=bob; export USER
${SHELL:-/bin/sh} << 'TAG2'
# bob added a comment
/usr/local/bin/run-thing --once
TAG2
`)
	canA := string(Normalize(jobA))
	canB := string(Normalize(jobB))
	if canA != canB {
		t.Errorf("equivalent at jobs did not collapse:\nA: %q\nB: %q", canA, canB)
	}
}

// TestHeredocMarker_QuoteVariants covers single-quoted, double-quoted
// and unquoted heredoc markers, plus the heredoc-tabs form `<<-`.
func TestHeredocMarker_QuoteVariants(t *testing.T) {
	cases := map[string]string{
		`${SHELL:-/bin/sh} << 'TAG1'`:  "TAG1",
		`${SHELL:-/bin/sh} << "TAG2"`:  "TAG2",
		`${SHELL:-/bin/sh} << TAG3`:    "TAG3",
		`${SHELL:-/bin/sh} <<-'TAG4'`:  "TAG4",
		`  ${SHELL:-/bin/sh} << 'XYZ'`: "XYZ",
	}
	for in, want := range cases {
		got, ok := heredocMarker(in)
		if !ok || got != want {
			t.Errorf("heredocMarker(%q) = (%q, %v); want (%q, true)", in, got, ok, want)
		}
	}
}

// TestHeredocMarker_NotAnOpener: lines that look like shell but are
// not the atd heredoc opener must return ok=false.
func TestHeredocMarker_NotAnOpener(t *testing.T) {
	cases := []string{
		`HOME=/home/x; export HOME`,
		`cd /home/x`,
		`${SHELL:-/bin/sh} -c 'echo'`,
		`echo "<< TAG"`,
		``,
	}
	for _, in := range cases {
		if got, ok := heredocMarker(in); ok {
			t.Errorf("heredocMarker(%q) = (%q, true); want ok=false", in, got)
		}
	}
}
