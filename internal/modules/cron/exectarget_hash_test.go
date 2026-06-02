package cron

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

// TestExecTargetHashedRootResolved is the representative regression guard
// for the Class-A fix: a module that resolves an absolute exec_target now
// hashes it (root-resolved) so Q6 can stack a worm dropping the same
// non-package payload across hosts. cron stands in for the ~9 modules
// that share the identical core.HashFileCapped(m.resolve(t)) call.
func TestExecTargetHashedRootResolved(t *testing.T) {
	root := t.TempDir()

	// A present, non-package payload under root at its logical path, so
	// hashing must resolve THROUGH root (the --root correctness property).
	const logical = "/usr/local/bin/payload"
	real := filepath.Join(root, "usr", "local", "bin", "payload")
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := []byte("#!/bin/sh\necho inert-worm\n")
	if err := os.WriteFile(real, payload, 0o755); err != nil {
		t.Fatal(err)
	}

	cd := filepath.Join(root, "etc", "cron.d", "job")
	if err := os.MkdirAll(filepath.Dir(cd), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cd, []byte("*/5 * * * * root "+logical+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var recs []core.Record
	if err := New(Options{Root: root, Now: func() time.Time { return time.Now().UTC() }}).
		Collect(context.Background(), func(r core.Record) { recs = append(recs, r) }); err != nil {
		t.Fatal(err)
	}

	var hit *core.Record
	for i := range recs {
		if recs[i].ExecTarget == logical {
			hit = &recs[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("no cron record with exec_target %s among %d records", logical, len(recs))
	}
	if want := core.HashHex(payload); hit.ExecTargetSHA256 != want {
		t.Errorf("exec_target_sha256 = %q, want %q (root-resolved Q6 hash)", hit.ExecTargetSHA256, want)
	}
}
