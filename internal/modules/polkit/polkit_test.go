package polkit

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
	goldenDir := filepath.Join("..", "..", "testdata", "golden", "polkit")
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

// --- Normalize unit tests ---

func TestNormalize_StripsLineComments(t *testing.T) {
	in := []byte(`// header comment
polkit.addRule(function(action, subject) {
    // inline note
    return polkit.Result.NO;
});
`)
	want := "polkit.addRule(function(action, subject) {\n    return polkit.Result.NO;\n});\n"
	got := string(Normalize(in))
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestNormalize_StripsBlockComments(t *testing.T) {
	in := []byte(`/* multi-line
   block comment */
polkit.addRule(function(action, subject) {
    return /* mid-line */ polkit.Result.NO;
});
`)
	got := string(Normalize(in))
	if bytes.Contains([]byte(got), []byte("multi-line")) {
		t.Errorf("block comment leaked into canonical: %q", got)
	}
	if !bytes.Contains([]byte(got), []byte("polkit.Result.NO")) {
		t.Errorf("policy body lost: %q", got)
	}
}

func TestNormalize_PreservesStringContent(t *testing.T) {
	// A // sequence inside a string MUST stay; it is not a comment.
	in := []byte(`polkit.addRule(function(action, subject) {
    var url = "http://example.org/path";
    if (action.id == "org.freedesktop.policykit.exec") {
        return polkit.Result.NO;
    }
});
`)
	got := string(Normalize(in))
	if !bytes.Contains([]byte(got), []byte(`"http://example.org/path"`)) {
		t.Errorf("string content lost: %q", got)
	}
}

func TestNormalize_EquivalentRulesCollapse(t *testing.T) {
	a := []byte(`// File-level comment.
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.NetworkManager.enable-disable-network") {
        return polkit.Result.YES;
    }
});
`)
	b := []byte(`/* Author: bob
   Date:   2026-01-01 */

polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.NetworkManager.enable-disable-network") {
        return polkit.Result.YES;   // explicit grant for console users
    }
});

`)
	canA := string(Normalize(a))
	canB := string(Normalize(b))
	if canA != canB {
		t.Errorf("equivalent rules did not collapse:\nA: %q\nB: %q", canA, canB)
	}
}

func TestContainsToken_FindsAdminRule(t *testing.T) {
	canon := []byte("polkit.addAdminRule(function(action, subject) {\n    return [\"unix-user:alice\"];\n});\n")
	if !containsToken(canon, "addAdminRule(") {
		t.Errorf("containsToken missed addAdminRule(")
	}
}

func TestContainsToken_FindsYesConstant(t *testing.T) {
	canon := []byte("return polkit.Result.YES;\n")
	if !containsToken(canon, "polkit.Result.YES") {
		t.Errorf("containsToken missed polkit.Result.YES")
	}
}
