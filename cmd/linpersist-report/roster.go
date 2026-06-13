package main

import (
	"os"
	"sort"
	"strings"

	"github.com/jarmidaw/linpersist/internal/core"
)

// loadRoster reads an --expected-hosts file: one host identifier per line,
// blank lines and #-comments ignored. Entries may be plaintext hostnames,
// hostname_hash values, or host_ids — reconcileRoster matches any of them.
func loadRoster(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

// reconcileRoster returns the sorted, de-duplicated roster entries that
// produced ZERO records in the dataset. An entry counts as PRESENT if it
// matches a seen host_id, a seen hostname_hash, a seen plaintext hostname
// (when --include-hostname was used), or the hostname_hash of the entry
// hashed as a plaintext hostname (the common case: roster of plaintext names
// vs. the agent's default hashed output).
func reconcileRoster(records []core.Record, roster []string) []string {
	seen := make(map[string]struct{})
	for i := range records {
		r := &records[i]
		if r.HostID != "" {
			seen[r.HostID] = struct{}{}
		}
		if r.HostMeta.HostnameHash != "" {
			seen[r.HostMeta.HostnameHash] = struct{}{}
		}
		if r.HostMeta.Hostname != "" {
			seen[strings.ToLower(strings.TrimSpace(r.HostMeta.Hostname))] = struct{}{}
		}
	}
	present := func(e string) bool {
		if _, ok := seen[e]; ok {
			return true
		}
		if _, ok := seen[strings.ToLower(e)]; ok {
			return true
		}
		if _, ok := seen[core.HashHostname(e)]; ok {
			return true
		}
		return false
	}
	uniq := make(map[string]struct{})
	var absent []string
	for _, e := range roster {
		if _, dup := uniq[e]; dup {
			continue
		}
		uniq[e] = struct{}{}
		if !present(e) {
			absent = append(absent, e)
		}
	}
	sort.Strings(absent)
	return absent
}

// distinctHosts counts unique hosts in the dataset (for the scale guard).
func distinctHosts(records []core.Record) int {
	seen := make(map[string]struct{})
	for i := range records {
		seen[hostKey(records[i])] = struct{}{}
	}
	return len(seen)
}
