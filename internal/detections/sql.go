// SQL generator — renders a RuleSet to the DuckDB WHERE block that
// tools/stack_demo.sql Q7 uses. The output is intentionally
// deterministic (stable ordering, fixed whitespace) so the release
// gate can byte-compare regenerated SQL against the committed file.

package detections

import (
	"fmt"
	"strings"
)

// SQLDialect controls the SQL flavour generated. v0.3.0 only supports
// DuckDB (the dialect used by tools/stack_demo.sql); the type exists
// so a future ClickHouse / Athena backend can be added without
// breaking the function signature.
type SQLDialect int

const (
	DialectDuckDB SQLDialect = iota
)

// SQLOptions controls cosmetic aspects of the rendered block. Stable
// defaults keep diffs small when only the rule set changes; tunables
// are here for future backends.
type SQLOptions struct {
	Dialect SQLDialect
	// IndentBase is the per-clause indent. The block leads with this
	// many characters of horizontal space on every emitted line.
	IndentBase string
}

// DefaultSQLOptions matches the existing tools/stack_demo.sql
// formatting: each clause indented by two spaces inside the WHERE.
var DefaultSQLOptions = SQLOptions{
	Dialect:    DialectDuckDB,
	IndentBase: "  ",
}

// RenderSQL returns the WHERE-clause body (no leading "WHERE", no
// trailing newline) that filters records matching any detection in
// the rule set. Each detection contributes a single disjunct; the
// disjuncts are joined with " OR " preceded by a newline so the
// committed SQL stays readable.
//
// The output is deterministic given the same input: same iteration
// order, same whitespace, same trailing comments.
func (rs *RuleSet) RenderSQL(opts SQLOptions) string {
	var b strings.Builder
	for i := range rs.Detections {
		clause := renderDetectionSQL(&rs.Detections[i], opts)
		if clause == "" {
			continue
		}
		if i > 0 {
			b.WriteString("\n")
			b.WriteString(opts.IndentBase)
			b.WriteString("OR ")
		}
		b.WriteString(clause)
	}
	return b.String()
}

// renderDetectionSQL produces the disjunct for one detection. Empty
// string is returned for a detection with no populated predicates,
// but the loader rejects those so callers never see this in
// practice.
//
// SignalsNone emits one `NOT list_contains(...)` clause per signal,
// AND-joined with the positive predicates. The matcher checks
// SignalsNone first as a short-circuit; the SQL backend doesn't
// short-circuit deterministically but the result is equivalent
// because the WHERE clause is a conjunction.
func renderDetectionSQL(d *Detection, opts SQLOptions) string {
	w := &d.When
	var parts []string
	for _, s := range w.SignalsNone {
		parts = append(parts, fmt.Sprintf("NOT list_contains(signals, '%s')", s))
	}
	for _, s := range w.SignalsAll {
		parts = append(parts, fmt.Sprintf("list_contains(signals, '%s')", s))
	}
	if len(w.SignalsAny) > 0 {
		var any []string
		for _, s := range w.SignalsAny {
			any = append(any, fmt.Sprintf("list_contains(signals, '%s')", s))
		}
		if len(any) == 1 {
			parts = append(parts, any[0])
		} else {
			parts = append(parts, "("+strings.Join(any, " OR ")+")")
		}
	}
	if len(w.ModuleIn) > 0 {
		var any []string
		for _, m := range w.ModuleIn {
			any = append(any, fmt.Sprintf("module = '%s'", m))
		}
		if len(any) == 1 {
			parts = append(parts, any[0])
		} else {
			parts = append(parts, "("+strings.Join(any, " OR ")+")")
		}
	}
	if len(w.SiteClassIn) > 0 {
		var any []string
		for _, sc := range w.SiteClassIn {
			any = append(any, fmt.Sprintf("site_class = '%s'", sc))
		}
		if len(any) == 1 {
			parts = append(parts, any[0])
		} else {
			parts = append(parts, "("+strings.Join(any, " OR ")+")")
		}
	}
	if len(w.ContentContainsAny) > 0 {
		var any []string
		for _, s := range w.ContentContainsAny {
			// Loader rejected ' % _ \\ already; safe to interpolate.
			any = append(any, fmt.Sprintf("content_snippet LIKE '%%%s%%'", s))
		}
		if len(any) == 1 {
			parts = append(parts, any[0])
		} else {
			parts = append(parts, "("+strings.Join(any, " OR ")+")")
		}
	}
	if len(parts) == 0 {
		return ""
	}
	body := strings.Join(parts, " AND ")
	// Annotate the disjunct with the detection id so an SQL reader
	// can map a row back to the YAML rule that fired.
	annotated := fmt.Sprintf("/* %s */ ", d.ID) + body
	if len(parts) > 1 {
		annotated = fmt.Sprintf("/* %s */ (%s)", d.ID, body)
	}
	return annotated
}
