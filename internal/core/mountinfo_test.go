package core

import (
	"strings"
	"testing"
)

func TestParseMountShadowSet(t *testing.T) {
	// Real-ish mountinfo: a dir overlay (WSL-style), pseudo-fs, and a
	// single-FILE bind over a packaged lib. Only the file bind is kept.
	mi := strings.Join([]string{
		"23 28 0:21 / /proc rw,nosuid - proc proc rw",
		"108 80 0:55 / /usr/lib/wsl/lib rw - overlay none rw,lowerdir=/x",              // dir overlay -> excluded
		"200 80 8:1 / /usr/lib/x86_64-linux-gnu/libcrypto.so.3 rw - ext4 /dev/sda1 rw", // file bind -> kept
		"201 80 8:1 / /etc/resolv.conf rw - ext4 /dev/sda1 rw",                         // file bind -> kept
		"202 80 8:1 / /etc rw - ext4 /dev/sda1 rw",                                     // dir -> excluded
	}, "\n")
	isFile := map[string]bool{
		"/usr/lib/x86_64-linux-gnu/libcrypto.so.3": true,
		"/etc/resolv.conf":                         true,
		// the rest are dirs / pseudo
	}
	set := parseMountShadowSet(strings.NewReader(mi), func(p string) bool { return isFile[p] })
	if _, ok := set["/usr/lib/x86_64-linux-gnu/libcrypto.so.3"]; !ok {
		t.Errorf("single-file bind over a lib should be in the set")
	}
	if _, ok := set["/usr/lib/wsl/lib"]; ok {
		t.Errorf("directory overlay must be EXCLUDED (no FP on WSL/container dir mounts)")
	}
	if _, ok := set["/etc"]; ok {
		t.Errorf("directory bind must be excluded")
	}
	if len(set) != 2 {
		t.Errorf("set size = %d, want 2 (the two file binds)", len(set))
	}
	// The signal helper only fires for a collected locus in the set.
	if s := MountShadowSignals("/usr/lib/x86_64-linux-gnu/libcrypto.so.3", set); len(s) != 1 || s[0] != SignalMountShadowsPath {
		t.Errorf("MountShadowSignals = %v; want [mount_shadows_path]", s)
	}
	if s := MountShadowSignals("/etc/passwd", set); s != nil {
		t.Errorf("non-shadowed locus must yield nil, got %v", s)
	}
}

func TestUnescapeMountField(t *testing.T) {
	if got := unescapeMountField(`/mnt/with\040space`); got != "/mnt/with space" {
		t.Errorf("octal-space unescape = %q", got)
	}
	if got := unescapeMountField("/plain/path"); got != "/plain/path" {
		t.Errorf("plain passthrough = %q", got)
	}
}
