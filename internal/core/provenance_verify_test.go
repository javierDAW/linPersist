package core

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// md5hex is the test-side counterpart to the resolver's fileMD5: it
// returns the lowercase hex MD5 of s so a fixture can record the exact
// hash dpkg would have stored for that content.
func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// dpkgVerifyFixture builds a dpkg root with one regular packaged file
// (via *.md5sums) and one registered conffile (via the Conffiles:
// stanza of status), writing both the recorded hashes AND the matching
// on-disk content. Returns the root so individual tests can tamper with
// files before warming a fresh resolver.
//
//	/usr/bin/clean-tool   regular packaged file (md5sums)   -> binContent
//	/etc/crontab          registered conffile  (Conffiles)  -> confContent
func dpkgVerifyFixture(t *testing.T, binContent, confContent string) string {
	t.Helper()
	root := t.TempDir()
	info := filepath.Join(root, "var/lib/dpkg/info")

	// Ownership map + detection: an info dir with at least one .list.
	writeFile(t, filepath.Join(info, "coreutils.list"), "/usr/bin/clean-tool\n")
	writeFile(t, filepath.Join(info, "cron.list"), "/etc/crontab\n")
	writeFile(t, filepath.Join(root, "etc/os-release"),
		"ID=debian\nID_LIKE=\nVERSION_ID=\"12\"\n")

	// Regular packaged file: md5sums lists the path WITHOUT a leading
	// slash; the on-disk file lives at the absolute path.
	writeFile(t, filepath.Join(info, "coreutils.md5sums"),
		md5hex(binContent)+"  usr/bin/clean-tool\n")
	writeFile(t, filepath.Join(root, "usr/bin/clean-tool"), binContent)

	// Registered conffile: recorded ONLY in the status Conffiles stanza
	// (deb822 continuation lines begin with a space), never in md5sums.
	writeFile(t, filepath.Join(root, "var/lib/dpkg/status"), strings.Join([]string{
		"Package: cron",
		"Status: install ok installed",
		"Conffiles:",
		" /etc/crontab " + md5hex(confContent),
		" /etc/cron.d/anacron " + md5hex("anacron-clean\n") + " obsolete",
		"Description: process scheduling daemon",
		"",
		"Package: coreutils",
		"Status: install ok installed",
		"Description: core utilities",
		"",
	}, "\n"))
	writeFile(t, filepath.Join(root, "etc/crontab"), confContent)

	return root
}

func warmResolver(t *testing.T, root string) *Resolver {
	t.Helper()
	r := NewResolver(nullLogger(), WithProvenanceRoot(root))
	r.Warmup(context.Background())
	if r.PackageManager() != PkgMgrDpkg {
		t.Fatalf("PackageManager = %v; want PkgMgrDpkg", r.PackageManager())
	}
	return r
}

// TestVerifyPath_CleanFiles: an unmodified regular file and an
// unmodified registered conffile both verify as Matched.
func TestVerifyPath_CleanFiles(t *testing.T) {
	const binC = "#!/bin/sh\nexec /usr/bin/true\n"
	const confC = "SHELL=/bin/sh\nPATH=/usr/sbin:/usr/bin\n17 * * * * root cd / && run-parts /etc/cron.hourly\n"
	r := warmResolver(t, dpkgVerifyFixture(t, binC, confC))

	if got := r.VerifyPath("/usr/bin/clean-tool"); got != PkgVerifyMatched {
		t.Errorf("regular file VerifyPath = %q; want matched", got)
	}
	if got := r.VerifyPath("/etc/crontab"); got != PkgVerifyMatched {
		t.Errorf("clean conffile VerifyPath = %q; want matched", got)
	}
}

// TestVerifyPath_ConffileTampered is the evade-pkg-tamper shape: a
// malicious schedule appended to the package-owned /etc/crontab. The
// recorded hash lives in the Conffiles stanza, NOT in md5sums, so this
// is exactly the case a md5sums-only verifier would miss.
func TestVerifyPath_ConffileTampered(t *testing.T) {
	const confC = "SHELL=/bin/sh\n17 * * * * root cd / && run-parts /etc/cron.hourly\n"
	root := dpkgVerifyFixture(t, "bin\n", confC)

	// Append the implant line AFTER the fixture recorded the clean hash.
	crontab := filepath.Join(root, "etc/crontab")
	f, err := os.OpenFile(crontab, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open crontab: %v", err)
	}
	if _, err := f.WriteString("*/13 * * * * root /usr/bin/bash -c true\n"); err != nil {
		t.Fatalf("append: %v", err)
	}
	f.Close()

	r := warmResolver(t, root)
	if got := r.VerifyPath("/etc/crontab"); got != PkgVerifyMismatched {
		t.Fatalf("tampered conffile VerifyPath = %q; want mismatched", got)
	}
	if sigs := TamperSignal(r.VerifyPath("/etc/crontab")); len(sigs) != 1 || sigs[0] != SignalPackageFileTampered {
		t.Errorf("TamperSignal = %v; want [%s]", sigs, SignalPackageFileTampered)
	}
}

// TestVerifyPath_RegularFileTampered: a modified md5sums-tracked file
// reports Mismatched too (covers the non-conffile branch).
func TestVerifyPath_RegularFileTampered(t *testing.T) {
	root := dpkgVerifyFixture(t, "original\n", "conf\n")
	writeFile(t, filepath.Join(root, "usr/bin/clean-tool"), "TAMPERED\n")

	r := warmResolver(t, root)
	if got := r.VerifyPath("/usr/bin/clean-tool"); got != PkgVerifyMismatched {
		t.Errorf("tampered regular file VerifyPath = %q; want mismatched", got)
	}
}

// TestVerifyPath_Statuses covers the non-tamper verdicts: a path no
// package records, a recorded path whose file is gone, and a relative
// path the resolver refuses to evaluate.
func TestVerifyPath_Statuses(t *testing.T) {
	root := dpkgVerifyFixture(t, "bin\n", "conf\n")
	r := warmResolver(t, root)

	if got := r.VerifyPath("/etc/not-packaged.conf"); got != PkgVerifyNotOwned {
		t.Errorf("unowned path VerifyPath = %q; want not_owned", got)
	}
	if got := r.VerifyPath("relative/path"); got != PkgVerifyUnknown {
		t.Errorf("relative path VerifyPath = %q; want unknown", got)
	}
	// Recorded hash but the on-disk file is missing -> Error, never a
	// false Matched/Mismatched.
	if err := os.Remove(filepath.Join(root, "usr/bin/clean-tool")); err != nil {
		t.Fatalf("remove: %v", err)
	}
	// Fresh resolver so the missing file is not served from a prior
	// cache entry.
	r2 := warmResolver(t, root)
	if got := r2.VerifyPath("/usr/bin/clean-tool"); got != PkgVerifyError {
		t.Errorf("missing file VerifyPath = %q; want error", got)
	}
}

// TestVerifyPath_UsrMergeAlternate: the manifest records /bin/merged
// (pre-merge form) while the file lives at /usr/bin/merged. VerifyPath
// must apply the same usr-merge sibling fallback as LookupPath.
func TestVerifyPath_UsrMergeAlternate(t *testing.T) {
	const content = "merged-binary\n"
	root := dpkgVerifyFixture(t, "bin\n", "conf\n")
	info := filepath.Join(root, "var/lib/dpkg/info")
	writeFile(t, filepath.Join(info, "merged.md5sums"),
		md5hex(content)+"  bin/merged\n")
	writeFile(t, filepath.Join(root, "usr/bin/merged"), content)

	r := warmResolver(t, root)
	if got := r.VerifyPath("/usr/bin/merged"); got != PkgVerifyMatched {
		t.Errorf("usr-merge VerifyPath = %q; want matched", got)
	}
}

// TestVerifyPath_UnwarmedOrDigestlessDegradesToUnknown: VerifyPath
// returns Unknown (never a tamper claim) before Warmup and when the
// integrity database could not be built -- e.g. an rpm host whose digest
// query is unavailable (no rpm binary, no override). Graceful
// degradation: ownership still works, integrity simply abstains.
func TestVerifyPath_UnwarmedOrDigestlessDegradesToUnknown(t *testing.T) {
	// Before warmup.
	cold := NewResolver(nullLogger(), WithProvenanceRoot(dpkgVerifyFixture(t, "b\n", "c\n")))
	if got := cold.VerifyPath("/etc/crontab"); got != PkgVerifyUnknown {
		t.Errorf("pre-warmup VerifyPath = %q; want unknown", got)
	}

	// rpm host whose digest query fails (ownership override returns
	// nothing, no digest binary in the fixture tree) -> fileDigests nil
	// -> Unknown, not a false verdict.
	rpmRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rpmRoot, "var/lib/rpm"), 0o755); err != nil {
		t.Fatalf("mkdir rpm: %v", err)
	}
	writeFile(t, filepath.Join(rpmRoot, "etc/os-release"), "ID=rocky\nID_LIKE=rhel\n")
	rr := NewResolver(nullLogger(), WithProvenanceRoot(rpmRoot),
		WithProvenanceRpmCommand([]string{"/bin/true"}))
	rr.Warmup(context.Background())
	if got := rr.VerifyPath("/etc/crontab"); got != PkgVerifyUnknown {
		t.Errorf("digestless rpm host VerifyPath = %q; want unknown", got)
	}
}

// --- rpm (SHA-256) -------------------------------------------------------

// rpmVerifyFixture builds an rpm root (detected via /var/lib/rpm +
// os-release) whose ownership and per-file digest queries are served by
// fixture shell commands. /etc/crontab is the package-owned file; its
// recorded digest is the SHA-256 of confContent (RHEL7+/Rocky default),
// exercising the 64-hex -> SHA-256 inference branch.
func rpmVerifyFixture(t *testing.T, confContent string) *Resolver {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "var/lib/rpm"), 0o755); err != nil {
		t.Fatalf("mkdir rpm: %v", err)
	}
	writeFile(t, filepath.Join(root, "etc/os-release"), "ID=rocky\nID_LIKE=rhel\n")
	writeFile(t, filepath.Join(root, "etc/crontab"), confContent)
	// A passwd that does NOT match the (bogus) recorded digest, to prove
	// the verify-flag skip holds even on a content mismatch.
	writeFile(t, filepath.Join(root, "etc/passwd"), "root:x:0:0:root:/root:/bin/bash\n")

	sum := sha256.Sum256([]byte(confContent))
	dig := hex.EncodeToString(sum[:])
	own := []string{"/bin/sh", "-c",
		"printf '%s\\n' 'crontabs: /etc/crontab' 'setup: /etc/passwd'"}
	// Digest query emits "<path> <digest> <verifyflags>". /etc/crontab is
	// fully verified (-1 = all bits). /etc/passwd carries a fixed bogus
	// digest with the digest-verify bit CLEARED (setup's %verify(not md5),
	// modelled as -2 = ~RPMVERIFY_FILEDIGEST) -> must be skipped, so a
	// modified /etc/passwd never flags (matches `rpm -V`).
	digc := []string{"/bin/sh", "-c", fmt.Sprintf(
		"printf '%%s\\n' '/etc/crontab %s -1' "+
			"'/etc/passwd 0000000000000000000000000000000000000000000000000000000000000000 -2'",
		dig)}

	r := NewResolver(nullLogger(),
		WithProvenanceRoot(root),
		WithProvenanceRpmCommand(own),
		WithProvenanceRpmDigestCommand(digc))
	r.Warmup(context.Background())
	if r.PackageManager() != PkgMgrRpm {
		t.Fatalf("PackageManager = %v; want PkgMgrRpm", r.PackageManager())
	}
	return r
}

func TestVerifyPath_RpmMatched(t *testing.T) {
	r := rpmVerifyFixture(t, "SHELL=/bin/bash\n0 3 * * * root /usr/bin/touch /tmp/x\n")
	if got := r.VerifyPath("/etc/crontab"); got != PkgVerifyMatched {
		t.Errorf("rpm clean VerifyPath = %q; want matched", got)
	}
}

func TestVerifyPath_RpmMismatched(t *testing.T) {
	// Recorded digest is for the clean content; the on-disk file carries
	// an appended implant line, so SHA-256 must differ -> mismatched.
	clean := "SHELL=/bin/bash\n"
	r := rpmVerifyFixture(t, clean)
	// Overwrite the on-disk file AFTER warmup recorded the clean digest.
	root := r.root
	writeFile(t, filepath.Join(root, "etc/crontab"), clean+"*/13 * * * * root /usr/bin/bash -c true\n")
	if got := r.VerifyPath("/etc/crontab"); got != PkgVerifyMismatched {
		t.Fatalf("rpm tampered VerifyPath = %q; want mismatched", got)
	}
	if sigs := TamperSignal(r.VerifyPath("/etc/crontab")); len(sigs) != 1 {
		t.Errorf("TamperSignal = %v; want package_file_tampered", sigs)
	}
}

// TestVerifyPath_RpmRespectsVerifyFlags: a file rpm marks with the
// digest-verify bit cleared (setup's /etc/passwd, %verify(not md5)) is
// NOT in the digest map, so even a content mismatch yields NotOwned --
// never a tamper claim. This is the fix for the ~108-record/host Rocky
// false-positive flood the nspawn lab surfaced.
func TestVerifyPath_RpmRespectsVerifyFlags(t *testing.T) {
	r := rpmVerifyFixture(t, "SHELL=/bin/bash\n")
	if got := r.VerifyPath("/etc/passwd"); got != PkgVerifyNotOwned {
		t.Errorf("/etc/passwd (%%verify(not md5)) VerifyPath = %q; want not_owned", got)
	}
}

// --- apk (SHA-1) ---------------------------------------------------------

// apkVerifyFixture builds an Alpine root whose /lib/apk/db/installed
// records /etc/crontab with a Q1<base64 SHA-1> checksum, exercising the
// 40-hex -> SHA-1 inference branch and the base64 decode.
func apkVerifyFixture(t *testing.T, confContent string) *Resolver {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "etc/os-release"), "ID=alpine\n")
	writeFile(t, filepath.Join(root, "etc/crontab"), confContent)

	sum := sha1.Sum([]byte(confContent))
	z := "Q1" + base64.StdEncoding.EncodeToString(sum[:])
	installed := strings.Join([]string{
		"P:busybox",
		"V:1.36.1-r0",
		"F:etc",
		"R:crontab",
		"Z:" + z,
		"",
	}, "\n")
	writeFile(t, filepath.Join(root, "lib/apk/db/installed"), installed)

	r := NewResolver(nullLogger(), WithProvenanceRoot(root))
	r.Warmup(context.Background())
	if r.PackageManager() != PkgMgrApk {
		t.Fatalf("PackageManager = %v; want PkgMgrApk", r.PackageManager())
	}
	return r
}

func TestVerifyPath_ApkMatched(t *testing.T) {
	r := apkVerifyFixture(t, "0 3 * * * root /usr/bin/true\n")
	if got := r.VerifyPath("/etc/crontab"); got != PkgVerifyMatched {
		t.Errorf("apk clean VerifyPath = %q; want matched", got)
	}
}

func TestVerifyPath_ApkMismatched(t *testing.T) {
	clean := "0 3 * * * root /usr/bin/true\n"
	r := apkVerifyFixture(t, clean)
	writeFile(t, filepath.Join(r.root, "etc/crontab"), clean+"evil\n")
	if got := r.VerifyPath("/etc/crontab"); got != PkgVerifyMismatched {
		t.Errorf("apk tampered VerifyPath = %q; want mismatched", got)
	}
}

// TestVerifyPath_Cache: repeated lookups for the same path are stable
// and served from the memo (a config file with N records hashes once).
func TestVerifyPath_Cache(t *testing.T) {
	root := dpkgVerifyFixture(t, "bin\n", "conf\n")
	r := warmResolver(t, root)

	first := r.VerifyPath("/etc/crontab")
	// Mutate the file on disk AFTER the first verify; a correctly
	// memoized result must NOT change on the second call.
	writeFile(t, filepath.Join(root, "etc/crontab"), "conf\nTAMPERED LATER\n")
	if second := r.VerifyPath("/etc/crontab"); second != first {
		t.Errorf("cached VerifyPath changed: first=%q second=%q", first, second)
	}
}
