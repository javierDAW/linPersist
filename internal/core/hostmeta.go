package core

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
)

// CollectHostMeta gathers the per-host envelope attached to every
// Record. includeHostname controls whether HostMeta.Hostname is set in
// addition to HostnameHash; default operation emits only the hash.
//
// Sources, in order of preference for HostID:
//  1. /etc/machine-id
//  2. /var/lib/dbus/machine-id
//  3. sha256(hostname) as a last-resort stable surrogate
func CollectHostMeta(includeHostname bool) (HostMeta, string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}

	hm := HostMeta{
		HostnameHash: hashHostname(hostname),
		Arch:         runtime.GOARCH,
	}
	if includeHostname {
		hm.Hostname = hostname
	}

	if osID, osVer := readOSRelease("/etc/os-release"); osID != "" {
		hm.OSID = osID
		hm.OSVersion = osVer
	}

	if kernel, err := readFirstLine("/proc/sys/kernel/osrelease"); err == nil {
		hm.Kernel = strings.TrimSpace(kernel)
	}

	if bootID, err := readFirstLine("/proc/sys/kernel/random/boot_id"); err == nil {
		hm.BootID = strings.TrimSpace(bootID)
	}

	hostID := readMachineID()
	if hostID == "" {
		hostID = hm.HostnameHash
	}

	return hm, hostID, nil
}

// normalizeHostname canonicalizes a hostname before hashing so that
// cosmetic variants (case, trailing whitespace, FQDN suffix) collapse
// to the same digest. See ADR-0006 for the rationale: a fleet that
// mixes `WEB-01`, `web-01`, and `web-01.prod.example.com` for the
// same logical host MUST stack to one bucket in LFA, not three.
//
// The transform is:
//   - lower-case (ASCII)
//   - trim surrounding whitespace
//   - truncate at the first '.' (strip domain suffix)
func normalizeHostname(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.IndexByte(h, '.'); i >= 0 {
		h = h[:i]
	}
	return h
}

// hashHostname returns "sha256:" + hex(sha256(normalizeHostname(h))).
// The prefix is mandatory per schema-v1; consumers MUST be able to
// distinguish sha256 from other digest schemes if future schema
// versions introduce them.
func hashHostname(h string) string {
	sum := sha256.Sum256([]byte(normalizeHostname(h)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// HashHostname returns the host_meta.hostname_hash value the agent writes for
// a plaintext hostname (canonical normalization — lower-case, trim, strip
// domain — then sha256). Exported so linpersist-report can reconcile a roster
// of plaintext hostnames (--expected-hosts) against the hostname_hash field in
// collected NDJSON, surfacing agents that never ran.
func HashHostname(h string) string { return hashHostname(h) }

func readMachineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		id := strings.TrimSpace(string(b))
		if id != "" {
			return id
		}
	}
	return ""
}

func readFirstLine(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if sc.Scan() {
		return sc.Text(), nil
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", errors.New("empty file")
}

// readOSRelease parses the subset of /etc/os-release we care about.
// Format reference: os-release(5). Quoted values are unquoted; unknown
// keys are ignored.
func readOSRelease(path string) (id, version string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			id = v
		case "VERSION_ID":
			version = v
		}
	}
	return id, version
}

// FormatMode returns a four-digit octal representation of a Unix mode,
// e.g. "0644" or "4755". Sticky/setuid/setgid bits are preserved.
func FormatMode(m uint32) string {
	return fmt.Sprintf("%04o", m&0o7777)
}
