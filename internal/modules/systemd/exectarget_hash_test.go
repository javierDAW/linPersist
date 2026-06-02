package systemd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

// TestExecTargetHashedRootResolved guards the systemd ExecStart hashing
// path: it must use the hardened, root-resolved, size-bounded reader
// (core.HashFileCapped) and populate exec_target_sha256, so Q6 can stack
// a worm dropping the same non-package binary across hosts. Regression
// guard for the line-484 unhardened-hashFile bug the final audit caught.
func TestExecTargetHashedRootResolved(t *testing.T) {
	root := t.TempDir()

	const logical = "/usr/local/bin/payload"
	real := filepath.Join(root, "usr", "local", "bin", "payload")
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := []byte("#!/bin/sh\necho inert-worm\n")
	if err := os.WriteFile(real, payload, 0o755); err != nil {
		t.Fatal(err)
	}

	unit := filepath.Join(root, "etc", "systemd", "system", "worm.service")
	if err := os.MkdirAll(filepath.Dir(unit), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unit, []byte("[Service]\nExecStart="+logical+"\n"), 0o644); err != nil {
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
		t.Fatalf("no systemd record with exec_target %s among %d records", logical, len(recs))
	}
	if want := core.HashHex(payload); hit.ExecTargetSHA256 != want {
		t.Errorf("exec_target_sha256 = %q, want %q (root-resolved hardened hash)", hit.ExecTargetSHA256, want)
	}
}
