package main

import (
	"sort"

	"github.com/jarmidaw/linpersist/internal/core"
)

// ADR-0015 governs the diff semantics. This file is the pure
// computation: load prev + curr from disk happens in main.go.
//
// Identity of a record for diff purposes is the tuple
// (host_id, module, site_class, locus). Two records with the same
// identity are "the same artifact across two collections";
// content_norm_sha256 then distinguishes Δ (changed) from = (idem).
//
// Hosts present in only one side are surfaced as a single
// host-level row (HostsDisappeared / HostsAppeared) rather than
// exploding into N per-record annotations. Container churn on a
// 100-host fleet would otherwise drown the diff.

// recIdentity is the canonical key for matching records across
// prev and curr. The fields are the four dimensions the agent
// guarantees are stable across re-collections of the same logical
// artifact.
type recIdentity struct {
	hostID    string
	module    string
	siteClass string
	locus     string
}

func identityOf(r core.Record) recIdentity {
	return recIdentity{
		hostID:    r.HostID,
		module:    r.Module,
		siteClass: r.SiteClass,
		locus:     r.Locus,
	}
}

// RecordPair couples a record's prev and curr versions, used for
// the Δ (changed) annotation. By construction prev.identity ==
// curr.identity but their content_norm_sha256 differ.
type RecordPair struct {
	Prev core.Record
	Curr core.Record
}

// HostChange summarises a host-level appearance / disappearance.
// RecordCount is the number of records the host had on the side
// where it was present (prev for Disappeared, curr for Appeared).
type HostChange struct {
	HostID      string
	HostSample  string // hostname (if --include-hostname was set) or host_id
	RecordCount int
}

// DiffSet is the output of ComputeDiff. It is the input to the
// rendering layer (text in this file, HTML in render.go later).
type DiffSet struct {
	// Per-record entries for hosts present in both sides.
	Added   []core.Record // present in curr only
	Removed []core.Record // present in prev only
	Changed []RecordPair  // present in both, content_norm differs
	// Records present in both sides with identical content_norm,
	// kept as a count rather than a slice -- the analyst only
	// needs the absolute number for context.
	UnchangedCount int

	// Host-level rows: a host whose entire record set appears or
	// disappears between prev and curr. These suppress the
	// per-record + / - entries that would otherwise saturate.
	HostsDisappeared []HostChange
	HostsAppeared    []HostChange

	// Totals for the header line of each rendered query.
	PrevTotal int
	CurrTotal int
}

// ComputeDiff produces a DiffSet from two record slices. The order
// of inputs in each slice is irrelevant; the function is
// deterministic.
//
// Algorithm:
//
//  1. Partition both sides into "host present in both" and "host
//     present in one only".
//  2. For per-host records, index by identityOf. Walk curr first
//     to classify Added / Changed / Unchanged; whatever remains in
//     the prev index after that pass is Removed.
//  3. For host-level appearances / disappearances, count records
//     for each side.
//
// All slices in the returned DiffSet are sorted deterministically
// so that two runs with identical inputs produce byte-identical
// rendered output.
func ComputeDiff(prev, curr []core.Record) DiffSet {
	prevHosts := hostsIn(prev)
	currHosts := hostsIn(curr)

	// Hosts present in only one side -> host-level rows.
	disappeared := setMinus(prevHosts, currHosts)
	appeared := setMinus(currHosts, prevHosts)

	// Build per-record indexes only for hosts in both sides.
	prevIdx := indexByIdentity(prev, disappeared)
	currIdx := indexByIdentity(curr, appeared)

	var ds DiffSet
	ds.PrevTotal = len(prev)
	ds.CurrTotal = len(curr)

	// Walk curr first: classify into Added / Changed / Unchanged.
	for id, currR := range currIdx {
		prevR, ok := prevIdx[id]
		if !ok {
			ds.Added = append(ds.Added, currR)
			continue
		}
		if prevR.ContentNormSHA256 != currR.ContentNormSHA256 {
			ds.Changed = append(ds.Changed, RecordPair{Prev: prevR, Curr: currR})
		} else {
			ds.UnchangedCount++
		}
		delete(prevIdx, id)
	}
	// Anything left in prevIdx exists only in prev -> Removed.
	for _, prevR := range prevIdx {
		ds.Removed = append(ds.Removed, prevR)
	}

	ds.HostsDisappeared = hostChanges(prev, disappeared)
	ds.HostsAppeared = hostChanges(curr, appeared)

	sortRecords(ds.Added)
	sortRecords(ds.Removed)
	sortPairs(ds.Changed)
	sortHostChanges(ds.HostsDisappeared)
	sortHostChanges(ds.HostsAppeared)

	return ds
}

// hostsIn returns the set of distinct host_ids present in records.
func hostsIn(records []core.Record) map[string]struct{} {
	out := make(map[string]struct{})
	for _, r := range records {
		if r.HostID == "" {
			continue
		}
		out[r.HostID] = struct{}{}
	}
	return out
}

// setMinus returns the elements of a not present in b.
func setMinus(a, b map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{})
	for k := range a {
		if _, ok := b[k]; !ok {
			out[k] = struct{}{}
		}
	}
	return out
}

// indexByIdentity builds an identity -> record map for records
// whose host_id is NOT in excludeHosts. The exclusion lets us
// skip records of hosts handled at the host-level.
func indexByIdentity(records []core.Record, excludeHosts map[string]struct{}) map[recIdentity]core.Record {
	out := make(map[recIdentity]core.Record, len(records))
	for _, r := range records {
		if _, skip := excludeHosts[r.HostID]; skip {
			continue
		}
		// In the rare case the same (host, module, site_class,
		// locus) appears twice in one collection (it shouldn't,
		// per the agent's contract, but a load from a malformed
		// merge could produce it), last-write-wins is the
		// least-surprising semantics.
		out[identityOf(r)] = r
	}
	return out
}

// hostChanges counts records per host for hosts in the change set.
// Used for HostsDisappeared (records in prev) and HostsAppeared
// (records in curr).
func hostChanges(records []core.Record, hosts map[string]struct{}) []HostChange {
	if len(hosts) == 0 {
		return nil
	}
	count := make(map[string]int, len(hosts))
	sample := make(map[string]string, len(hosts))
	for _, r := range records {
		if _, in := hosts[r.HostID]; !in {
			continue
		}
		count[r.HostID]++
		if sample[r.HostID] == "" {
			sample[r.HostID] = hostKey(r)
		}
	}
	out := make([]HostChange, 0, len(count))
	for h, n := range count {
		out = append(out, HostChange{
			HostID:      h,
			HostSample:  sample[h],
			RecordCount: n,
		})
	}
	return out
}

// sortRecords orders a record slice deterministically by
// (host_id, module, site_class, locus, content_norm_sha256).
func sortRecords(rs []core.Record) {
	sort.Slice(rs, func(i, j int) bool {
		a, b := rs[i], rs[j]
		if a.HostID != b.HostID {
			return a.HostID < b.HostID
		}
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		if a.SiteClass != b.SiteClass {
			return a.SiteClass < b.SiteClass
		}
		if a.Locus != b.Locus {
			return a.Locus < b.Locus
		}
		return a.ContentNormSHA256 < b.ContentNormSHA256
	})
}

// sortPairs orders changed-record pairs by the curr side's
// identity, mirroring the per-record sort order so the rendered
// output reads consistently.
func sortPairs(ps []RecordPair) {
	sort.Slice(ps, func(i, j int) bool {
		a, b := ps[i].Curr, ps[j].Curr
		if a.HostID != b.HostID {
			return a.HostID < b.HostID
		}
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		if a.SiteClass != b.SiteClass {
			return a.SiteClass < b.SiteClass
		}
		return a.Locus < b.Locus
	})
}

// sortHostChanges orders host-level rows by host_id for a stable
// rendering.
func sortHostChanges(hs []HostChange) {
	sort.Slice(hs, func(i, j int) bool { return hs[i].HostID < hs[j].HostID })
}
