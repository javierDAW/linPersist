package core

import (
	"context"
	"crypto/md5"
	"encoding/hex"
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

// TestVerifyPath_NotDpkgOrUnwarmed: VerifyPath degrades to Unknown
// (never a tamper claim) on a non-dpkg host, before Warmup, and on the
// Noop resolver -- the honest "could not check" verdict rpm/apk hosts
// get until those backends are implemented.
func TestVerifyPath_NotDpkgOrUnwarmed(t *testing.T) {
	// Before warmup.
	cold := NewResolver(nullLogger(), WithProvenanceRoot(dpkgVerifyFixture(t, "b\n", "c\n")))
	if got := cold.VerifyPath("/etc/crontab"); got != PkgVerifyUnknown {
		t.Errorf("pre-warmup VerifyPath = %q; want unknown", got)
	}

	// rpm host: detected as rpm, integrity not implemented -> Unknown.
	rpmRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rpmRoot, "var/lib/rpm"), 0o755); err != nil {
		t.Fatalf("mkdir rpm: %v", err)
	}
	writeFile(t, filepath.Join(rpmRoot, "etc/os-release"), "ID=rocky\nID_LIKE=rhel\n")
	rr := NewResolver(nullLogger(), WithProvenanceRoot(rpmRoot),
		WithProvenanceRpmCommand([]string{"/bin/true"}))
	rr.Warmup(context.Background())
	if got := rr.VerifyPath("/etc/crontab"); got != PkgVerifyUnknown {
		t.Errorf("rpm host VerifyPath = %q; want unknown", got)
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
