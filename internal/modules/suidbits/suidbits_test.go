package suidbits

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

// stageBinary writes a stub binary at <root>/<rel> and applies the
// POSIX mode bits via syscall.Chmod. We deliberately do NOT use
// os.Chmod here because Go's os.FileMode reserves its high bits for
// platform-portable flags (os.ModeSetuid is 0x800000, not 0o4000), so
// passing the natural POSIX form 0o4755 to os.Chmod silently masks
// off the suid bit on Linux. syscall.Chmod takes the POSIX octal as-is
// and applies it directly to the inode.
func stageBinary(t *testing.T, root, rel string, mode uint32, body string) string {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", rel, err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
	if err := syscall.Chmod(full, mode); err != nil {
		t.Fatalf("chmod %s -> %#o: %v", rel, mode, err)
	}
	return full
}

// collect runs a Module against the given options and returns every
// record emitted, sorted by locus for deterministic test assertions.
func collect(t *testing.T, m *Module) []core.Record {
	t.Helper()
	var out []core.Record
	if err := m.Collect(context.Background(), func(r core.Record) {
		out = append(out, r)
	}); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Locus < out[j].Locus })
	return out
}

// signalSet returns the signal slice as a presence map for O(1)
// membership checks inside assertions.
func signalSet(sigs []string) map[string]struct{} {
	out := make(map[string]struct{}, len(sigs))
	for _, s := range sigs {
		out[s] = struct{}{}
	}
	return out
}

// TestCollect_SuidUnderTmp is the canonical implant case: a
// user-writable root carries an attacker-dropped binary with mode
// 4755. It must surface as suid.user with suid_bit_set.
func TestCollect_SuidUnderTmp(t *testing.T) {
	root := t.TempDir()
	stageBinary(t, root, "/tmp/.x", 0o4755, "implant")
	m := New(Options{
		Root:  root,
		Roots: []string{"/tmp"},
		Now:   func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) },
	})
	recs := collect(t, m)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d: %+v", len(recs), recs)
	}
	r := recs[0]
	if r.SiteClass != "suid.user" {
		t.Errorf("site_class: got %q, want suid.user", r.SiteClass)
	}
	if r.Locus != "/tmp/.x" {
		t.Errorf("locus: got %q, want /tmp/.x", r.Locus)
	}
	if r.ExecTarget != "/tmp/.x" {
		t.Errorf("exec_target: got %q, want /tmp/.x", r.ExecTarget)
	}
	if len(r.MITRE) != 1 || r.MITRE[0] != "T1548.001" {
		t.Errorf("mitre: got %v, want [T1548.001]", r.MITRE)
	}
	sigs := signalSet(r.Signals)
	if _, ok := sigs[core.SignalSuidBitSet]; !ok {
		t.Errorf("missing suid_bit_set signal (got %v)", r.Signals)
	}
	if _, ok := sigs[core.SignalSgidBitSet]; ok {
		t.Errorf("unexpected sgid_bit_set on suid-only file (got %v)", r.Signals)
	}
}

// TestCollect_SgidUnderUsr classifies a sgid-only binary under a
// system root as sgid.system.
func TestCollect_SgidUnderUsr(t *testing.T) {
	root := t.TempDir()
	stageBinary(t, root, "/usr/bin/wall", 0o2755, "wall stub")
	m := New(Options{Root: root, Roots: []string{"/usr/bin"}})
	recs := collect(t, m)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	if recs[0].SiteClass != "sgid.system" {
		t.Errorf("site_class: got %q, want sgid.system", recs[0].SiteClass)
	}
	sigs := signalSet(recs[0].Signals)
	if _, ok := sigs[core.SignalSgidBitSet]; !ok {
		t.Errorf("missing sgid_bit_set signal")
	}
	if _, ok := sigs[core.SignalSuidBitSet]; ok {
		t.Errorf("unexpected suid_bit_set on sgid-only file")
	}
}

// TestCollect_BothBits fires both signals and prefers suid for the
// site_class (the more dangerous bit wins).
func TestCollect_BothBits(t *testing.T) {
	root := t.TempDir()
	stageBinary(t, root, "/usr/bin/dual", 0o6755, "dual stub")
	m := New(Options{Root: root, Roots: []string{"/usr/bin"}})
	recs := collect(t, m)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	if recs[0].SiteClass != "suid.system" {
		t.Errorf("site_class: got %q, want suid.system (suid takes precedence)", recs[0].SiteClass)
	}
	sigs := signalSet(recs[0].Signals)
	if _, ok := sigs[core.SignalSuidBitSet]; !ok {
		t.Errorf("missing suid_bit_set")
	}
	if _, ok := sigs[core.SignalSgidBitSet]; !ok {
		t.Errorf("missing sgid_bit_set")
	}
}

// TestCollect_NoSpecialBits_Empty exercises the negative path: a
// regular 0755 binary under /usr/bin emits zero records. Without
// this the module would flood the report with every executable on
// the host.
func TestCollect_NoSpecialBits_Empty(t *testing.T) {
	root := t.TempDir()
	stageBinary(t, root, "/usr/bin/ls", 0o755, "ls stub")
	stageBinary(t, root, "/usr/bin/cat", 0o755, "cat stub")
	m := New(Options{Root: root, Roots: []string{"/usr/bin"}})
	recs := collect(t, m)
	if len(recs) != 0 {
		t.Fatalf("want 0 records on a plain-mode root, got %d: %+v", len(recs), recs)
	}
}

// TestCollect_SkipsSymlinks: a symlink with suid bits on the link
// itself is meaningless (the kernel honours the target's bits). The
// walker must use Lstat and skip the symlink, otherwise an attacker
// could trick the report by symlinking /usr/bin/sudo into /tmp.
func TestCollect_SkipsSymlinks(t *testing.T) {
	root := t.TempDir()
	target := stageBinary(t, root, "/usr/bin/real", 0o4755, "real")
	linkLogical := "/tmp/.link"
	linkReal := filepath.Join(root, linkLogical)
	_ = os.MkdirAll(filepath.Dir(linkReal), 0o755)
	if err := os.Symlink(target, linkReal); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	m := New(Options{Root: root, Roots: []string{"/usr/bin", "/tmp"}})
	recs := collect(t, m)
	// Expect exactly one record — the real binary, NOT the symlink.
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d: %+v", len(recs), recs)
	}
	if !strings.HasSuffix(recs[0].Locus, "/usr/bin/real") {
		t.Errorf("locus: got %q, want suffix /usr/bin/real", recs[0].Locus)
	}
}

// TestCollect_NonexistentRoot_NoError: a root that does not exist on
// the host (e.g. /opt in a container) must NOT abort the walk of
// the other roots.
func TestCollect_NonexistentRoot_NoError(t *testing.T) {
	root := t.TempDir()
	stageBinary(t, root, "/usr/bin/passwd", 0o4755, "passwd")
	m := New(Options{Root: root, Roots: []string{"/opt", "/usr/bin"}})
	recs := collect(t, m)
	if len(recs) != 1 {
		t.Fatalf("want 1 record (only /usr/bin populated), got %d", len(recs))
	}
}

// TestCollect_DeterministicCanon: the same binary at the same locus
// on two synthetic hosts must produce IDENTICAL content_norm_sha256.
// Without this Q1/Q4 stacking falls apart — every legitimate suid
// binary would look like a singleton because hosts have different
// inode metadata.
func TestCollect_DeterministicCanon(t *testing.T) {
	hostA := t.TempDir()
	hostB := t.TempDir()
	stageBinary(t, hostA, "/usr/bin/passwd", 0o4755, "different body A")
	stageBinary(t, hostB, "/usr/bin/passwd", 0o4755, "different body B and longer")
	mA := New(Options{Root: hostA, Roots: []string{"/usr/bin"}})
	mB := New(Options{Root: hostB, Roots: []string{"/usr/bin"}})
	recA := collect(t, mA)
	recB := collect(t, mB)
	if len(recA) != 1 || len(recB) != 1 {
		t.Fatalf("want 1 record per host, got A=%d B=%d", len(recA), len(recB))
	}
	if recA[0].ContentNormSHA256 != recB[0].ContentNormSHA256 {
		t.Errorf("content_norm_sha256 differs across hosts for same locus+mode: A=%q B=%q",
			recA[0].ContentNormSHA256, recB[0].ContentNormSHA256)
	}
	// content_sha256 should differ (the bodies are different) so Q6
	// cross-host stacking can still tell them apart.
	if recA[0].ContentSHA256 == recB[0].ContentSHA256 {
		t.Errorf("content_sha256 collided across distinct bodies: %q", recA[0].ContentSHA256)
	}
}

// TestClassify covers the system/user split decisions in isolation.
func TestClassify(t *testing.T) {
	cases := []struct {
		path string
		suid bool
		want string
	}{
		{"/usr/bin/passwd", true, "suid.system"},
		{"/usr/sbin/mount.cifs", true, "suid.system"},
		{"/usr/local/bin/foo", true, "suid.system"},
		{"/opt/vendor/tool", true, "suid.system"},
		{"/usr/bin/wall", false, "sgid.system"},
		{"/tmp/.x", true, "suid.user"},
		{"/var/tmp/.y", true, "suid.user"},
		{"/home/eve/run", true, "suid.user"},
		{"/home/eve/log", false, "sgid.user"},
		// Non-system-prefix paths default to user side.
		{"/srv/data/x", true, "suid.user"},
	}
	for _, c := range cases {
		if got := classify(c.path, c.suid); got != c.want {
			t.Errorf("classify(%q, suid=%v) = %q, want %q", c.path, c.suid, got, c.want)
		}
	}
}

// TestCollect_SkipsPseudoFilesystems: if /proc or /sys is configured
// as a walk root the walker must short-circuit before reading any
// entries. This is paranoia: the default roots don't include them,
// but a misconfigured Options.Roots should not hang the agent.
func TestCollect_SkipsPseudoFilesystems(t *testing.T) {
	root := t.TempDir()
	stageBinary(t, root, "/proc/.fake", 0o4755, "should be skipped")
	stageBinary(t, root, "/usr/bin/passwd", 0o4755, "real")
	m := New(Options{Root: root, Roots: []string{"/proc", "/usr/bin"}})
	recs := collect(t, m)
	for _, r := range recs {
		if strings.HasPrefix(r.Locus, "/proc") {
			t.Errorf("walker descended into /proc: locus=%q", r.Locus)
		}
	}
}
