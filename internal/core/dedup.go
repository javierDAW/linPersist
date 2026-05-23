package core

import "sort"

// DedupSignals returns a slice containing the unique elements of in,
// preserving the order of first occurrence. Returns nil for an empty or
// nil input. This is the variant used by the majority of collection
// modules; signal order is observable in NDJSON output and pinned by
// per-module golden tests.
func DedupSignals(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// DedupSignalsSorted returns the unique elements of in in lexicographic
// order. Returns nil for an empty or nil input. Used by the grub, polkit
// and xdg modules where the on-wire signal ordering is sorted; switching
// these to insertion order would churn their golden fixtures.
func DedupSignalsSorted(in []string) []string {
	out := DedupSignals(in)
	if out == nil {
		return nil
	}
	sort.Strings(out)
	return out
}
