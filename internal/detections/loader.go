// Package detections loads detections.yaml (the cross-cutting implant
// clauses), validates its references against the signals catalog, and
// exposes the parsed rule set to two consumers:
//
//   - cmd/linpersist-report:  go:embed loads detections.yaml at build
//                              time; the report's Q7 rows are produced
//                              by Match() against every record.
//   - cmd/detgen:             regenerates the Q7 WHERE block of
//                              tools/stack_demo.sql from the same YAML.
//
// The loader validates schema version, predicate shapes, signal names
// (against core.KnownSignalSet), unique detection IDs, and SQL-unsafe
// characters in content substrings before returning. Callers that get
// back a *RuleSet have a tree they can trust to be internally
// consistent and safe to render to either Go-native predicates or
// SQL.
//
// See ADR-0013 for the schema and release-gate rationale.

package detections

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jarmidaw/linpersist/internal/core"
)

// SchemaVersion is the only schema_version value this package accepts.
// Bumping requires a migration path documented in CHANGELOG.
const SchemaVersion = 1

// validSeverities is the closed set of severity values accepted in
// detection entries. Order is the "natural" severity ramp; the field
// is informational and does not affect matching.
var validSeverities = map[string]struct{}{
	"info":     {},
	"low":      {},
	"medium":   {},
	"high":     {},
	"critical": {},
}

// validIDPattern restricts detection ids to snake_case identifiers.
// Same shape used by signal names so contributors don't have to learn
// two conventions.
var validIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// validMITREPattern accepts ATT&CK technique ids of the form T1234 or
// T1234.001. Not exhaustive against the MITRE matrix (no offline
// table), but rejects obvious typos.
var validMITREPattern = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)

// SQL-unsafe characters in content substrings. The matcher uses Go
// string Contains so any byte is fine; the SQL generator emits
// LIKE '%<s>%' so quote, percent, underscore and backslash need to
// either be rejected up front or escaped per backend. We reject
// rather than escape: the implant patterns we care about (curl, wget,
// /tmp/, ...) never need these characters, and rejection means the
// SQL backend is irrelevant to the loader.
var sqlUnsafePattern = regexp.MustCompile("['%_\\\\]")

// RuleSet is the parsed detections.yaml. The fields mirror the YAML
// structure verbatim; the loader does the validation work so callers
// can iterate Detections without re-checking shape invariants.
type RuleSet struct {
	SchemaVersion int         `yaml:"schema_version"`
	Detections    []Detection `yaml:"detections"`
}

// Detection is one detection block.
type Detection struct {
	ID          string   `yaml:"id"`
	Description string   `yaml:"description"`
	Severity    string   `yaml:"severity"`
	MITRE       []string `yaml:"mitre"`
	When        When     `yaml:"when"`
}

// When is the predicate block. Every populated field is AND-joined;
// at least one field must be populated (the loader enforces this).
type When struct {
	SignalsAll         []string `yaml:"signals_all"`
	SignalsAny         []string `yaml:"signals_any"`
	ModuleIn           []string `yaml:"module_in"`
	ContentContainsAny []string `yaml:"content_contains_any"`
}

// Load parses YAML bytes and validates the result. The signals
// argument is the closed set of valid signal names (typically
// core.KnownSignalSet()); pass nil to skip the signal-name check
// (useful for tests that don't pull in the full catalog). The
// modules argument is the closed set of valid module names; nil
// disables that check.
func Load(yamlData []byte, signals map[string]struct{}, modules map[string]struct{}) (*RuleSet, error) {
	if signals == nil {
		signals = core.KnownSignalSet()
	}
	var rs RuleSet
	if err := yaml.Unmarshal(yamlData, &rs); err != nil {
		return nil, fmt.Errorf("detections: parse yaml: %w", err)
	}
	if err := rs.validate(signals, modules); err != nil {
		return nil, err
	}
	return &rs, nil
}

// validate runs every consistency check the loader cares about.
func (rs *RuleSet) validate(signals, modules map[string]struct{}) error {
	if rs.SchemaVersion != SchemaVersion {
		return fmt.Errorf("detections: unsupported schema_version %d (want %d)",
			rs.SchemaVersion, SchemaVersion)
	}
	if len(rs.Detections) == 0 {
		return errors.New("detections: rule set is empty")
	}
	seenIDs := make(map[string]int, len(rs.Detections))
	var errs []string
	for i, d := range rs.Detections {
		if d.ID == "" {
			errs = append(errs, fmt.Sprintf("detection #%d: missing id", i))
			continue
		}
		if !validIDPattern.MatchString(d.ID) {
			errs = append(errs, fmt.Sprintf("detection %q: id must be snake_case (^[a-z][a-z0-9_]*$)", d.ID))
		}
		if prev, dup := seenIDs[d.ID]; dup {
			errs = append(errs, fmt.Sprintf("detection %q: duplicate id (first seen at index %d)", d.ID, prev))
		}
		seenIDs[d.ID] = i
		if d.Severity != "" {
			if _, ok := validSeverities[d.Severity]; !ok {
				errs = append(errs, fmt.Sprintf("detection %q: severity %q not in {info,low,medium,high,critical}",
					d.ID, d.Severity))
			}
		}
		for _, m := range d.MITRE {
			if !validMITREPattern.MatchString(m) {
				errs = append(errs, fmt.Sprintf("detection %q: mitre id %q does not match T#### or T####.###", d.ID, m))
			}
		}
		if !d.When.populated() {
			errs = append(errs, fmt.Sprintf("detection %q: when block has no predicates", d.ID))
			continue
		}
		// Signal-name references must be in the catalog.
		for _, s := range d.When.SignalsAll {
			if _, ok := signals[s]; !ok {
				errs = append(errs, fmt.Sprintf("detection %q: signals_all references unknown signal %q", d.ID, s))
			}
		}
		for _, s := range d.When.SignalsAny {
			if _, ok := signals[s]; !ok {
				errs = append(errs, fmt.Sprintf("detection %q: signals_any references unknown signal %q", d.ID, s))
			}
		}
		// Module names: validated only when caller provided a set.
		if modules != nil {
			for _, m := range d.When.ModuleIn {
				if _, ok := modules[m]; !ok {
					errs = append(errs, fmt.Sprintf("detection %q: module_in references unknown module %q", d.ID, m))
				}
			}
		}
		// Content substrings: reject SQL-unsafe characters so the
		// SQL generator can interpolate them verbatim into LIKE
		// patterns. The matcher would accept anything; the
		// restriction is for the SQL backend.
		for _, s := range d.When.ContentContainsAny {
			if s == "" {
				errs = append(errs, fmt.Sprintf("detection %q: content_contains_any has empty entry", d.ID))
				continue
			}
			if sqlUnsafePattern.MatchString(s) {
				errs = append(errs,
					fmt.Sprintf("detection %q: content_contains_any %q contains SQL-unsafe character (' %% _ \\); "+
						"the SQL backend rejects these", d.ID, s))
			}
		}
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return fmt.Errorf("detections: validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// populated returns true if the When carries at least one predicate.
// A detection with an empty `when:` would match everything (or
// nothing, depending on conjunction semantics) and is rejected at
// load time.
func (w *When) populated() bool {
	return len(w.SignalsAll) > 0 ||
		len(w.SignalsAny) > 0 ||
		len(w.ModuleIn) > 0 ||
		len(w.ContentContainsAny) > 0
}
