package core

import (
	"bufio"
	"io"
	"os"
	"strings"
)

// Mount-shadow detection closes part of the runtime-view-vs-disk-walk gap
// the duel-3 bind-mount implant exposed (and that scope.md §8 disclaims as
// an EDR concern). It does NOT read the mounted bytes — it records the
// DESYNC: a persistence file a module collected is, at runtime, a
// SINGLE-FILE bind/overlay mount target, so the on-disk inode the agent
// hashed is masked by a different file the kernel actually serves. The
// signal is advisory (LFA / triage enrichment), never a Q7 verdict on its
// own — legitimate single-file binds exist (some container/snap setups),
// and the durable discriminator stays LFA + the integrity oracle on the
// underlying inode.

// BuildMountShadowSet reads /proc/self/mountinfo and returns the set of
// mount-point paths whose mount point is a REGULAR FILE — i.e. a
// single-file bind or overlay, NOT a directory mount. Directory mounts
// (the bulk of mountinfo: /proc, /sys, tmpfs, container/WSL dir overlays)
// are excluded, which is the precise discriminator: masking ONE packaged
// file with a payload is the anti-forensic shape; mounting a directory is
// ordinary plumbing. Returns an empty (non-nil) set on any read error.
func BuildMountShadowSet() map[string]struct{} {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return map[string]struct{}{}
	}
	defer f.Close()
	return parseMountShadowSet(f, func(p string) bool {
		info, err := os.Lstat(p)
		return err == nil && info.Mode().IsRegular()
	})
}

// parseMountShadowSet is the testable core: it parses mountinfo lines and
// keeps a mount point when isRegularFile reports the mount point is a file.
// mountinfo field layout (proc(5)): index 4 is the mount point, octal-
// escaped (\040 space, \011 tab, \012 newline, \134 backslash).
func parseMountShadowSet(r io.Reader, isRegularFile func(string) bool) map[string]struct{} {
	out := map[string]struct{}{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		mp := unescapeMountField(fields[4])
		if !strings.HasPrefix(mp, "/") {
			continue
		}
		if isRegularFile(mp) {
			out[mp] = struct{}{}
		}
	}
	return out
}

// MountShadowSignals returns the mount_shadows_path signal when locus is a
// single-file mount target in set, else nil. Called from the emit sink for
// every record's Locus (memoized set, one mountinfo read per run).
func MountShadowSignals(locus string, set map[string]struct{}) []string {
	if locus == "" || set == nil {
		return nil
	}
	if _, ok := set[locus]; ok {
		return []string{SignalMountShadowsPath}
	}
	return nil
}

// unescapeMountField decodes the octal escapes the kernel uses in
// mountinfo path fields.
func unescapeMountField(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	repl := strings.NewReplacer(
		`\040`, " ",
		`\011`, "\t",
		`\012`, "\n",
		`\134`, `\`,
	)
	return repl.Replace(s)
}
