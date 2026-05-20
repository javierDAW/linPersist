// Matcher engine — evaluates a RuleSet against a core.Record.
//
// All predicates within a single Detection are AND-joined; cross-
// detection logic is OR by construction (a record matches the rule
// set if any detection matches). The matcher mirrors the SQL
// generator's semantics byte-for-byte: the release gate verifies
// that the SQL emitted by detgen produces the same set of rows as
// the Go-native matcher when both are run against the same input.

package detections

import (
	"strings"

	"github.com/jarmidaw/linpersist/internal/core"
)

// Match returns the IDs of every detection that matches r, in the
// order they appear in the rule set. An empty slice means no match.
// Callers that only need a bool can check len(...) > 0.
//
// The slice is freshly allocated; callers may mutate it freely.
func (rs *RuleSet) Match(r core.Record) []string {
	var matched []string
	// Pre-compute the signal set once per record. Detections often
	// share signals; the alternative (re-scanning r.Signals per
	// detection) is O(detections * signals).
	sigs := sigSet(r.Signals)
	for i := range rs.Detections {
		if rs.detectionMatches(&rs.Detections[i], r, sigs) {
			matched = append(matched, rs.Detections[i].ID)
		}
	}
	return matched
}

// MatchAny is a convenience for callers that only need to know
// whether r triggers any detection. Cheaper than Match when no
// detection IDs are needed because it short-circuits on the first
// hit.
func (rs *RuleSet) MatchAny(r core.Record) bool {
	sigs := sigSet(r.Signals)
	for i := range rs.Detections {
		if rs.detectionMatches(&rs.Detections[i], r, sigs) {
			return true
		}
	}
	return false
}

// detectionMatches applies the conjunction of every populated
// predicate in d.When to r. An unpopulated When is impossible at
// match time (the loader rejects it), so every detection has at
// least one predicate to evaluate.
func (rs *RuleSet) detectionMatches(d *Detection, r core.Record, sigs map[string]struct{}) bool {
	w := &d.When
	if len(w.SignalsAll) > 0 {
		for _, s := range w.SignalsAll {
			if _, ok := sigs[s]; !ok {
				return false
			}
		}
	}
	if len(w.SignalsAny) > 0 {
		hit := false
		for _, s := range w.SignalsAny {
			if _, ok := sigs[s]; ok {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if len(w.ModuleIn) > 0 {
		hit := false
		for _, m := range w.ModuleIn {
			if r.Module == m {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if len(w.ContentContainsAny) > 0 {
		hit := false
		for _, s := range w.ContentContainsAny {
			if strings.Contains(r.ContentSnippet, s) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

// sigSet returns a presence map of signals on a record. Identical to
// the helper of the same name in cmd/linpersist-report/stats.go; kept
// duplicated here so internal/detections has no upward dependency on
// the report binary.
func sigSet(sigs []string) map[string]struct{} {
	m := make(map[string]struct{}, len(sigs))
	for _, s := range sigs {
		m[s] = struct{}{}
	}
	return m
}
