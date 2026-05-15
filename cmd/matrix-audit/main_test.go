package main

import (
	"context"
	"strings"
	"testing"

	"github.com/jarmidaw/linpersist/internal/core"
)

// TestParseMatrix_Valid covers the minimal happy-path shape.
func TestParseMatrix_Valid(t *testing.T) {
	raw := []byte(`
schema_version: 1
target_release: v0.1.0
site_classes:
  - site_class: cron.d
    module: cron
    mitre: [T1053.003]
    status: implemented
    notes: |
      Inline notes go here.
  - site_class: systemd.unit
    module: systemd
    mitre: [T1543.002]
    status: planned
`)
	mf, err := parseMatrix(raw)
	if err != nil {
		t.Fatalf("parseMatrix returned error: %v", err)
	}
	if len(mf.SiteClasses) != 2 {
		t.Fatalf("got %d site_classes, want 2", len(mf.SiteClasses))
	}
	if mf.SiteClasses[0].SiteClass != "cron.d" {
		t.Errorf("first entry SiteClass = %q, want cron.d", mf.SiteClasses[0].SiteClass)
	}
	if mf.SiteClasses[0].Module != "cron" {
		t.Errorf("first entry Module = %q, want cron", mf.SiteClasses[0].Module)
	}
	if mf.SiteClasses[0].Status != "implemented" {
		t.Errorf("first entry Status = %q, want implemented", mf.SiteClasses[0].Status)
	}
	if mf.SiteClasses[1].Status != "planned" {
		t.Errorf("second entry Status = %q, want planned", mf.SiteClasses[1].Status)
	}
}

func TestParseMatrix_Invalid(t *testing.T) {
	raw := []byte("not: [a, valid: yaml:")
	if _, err := parseMatrix(raw); err == nil {
		t.Error("parseMatrix on malformed yaml returned nil error; want non-nil")
	}
}

// TestAudit_HappyPath: matrix entries and code coverage agree.
func TestAudit_HappyPath(t *testing.T) {
	matrix := []matrixEntry{
		{SiteClass: "cron.d", Module: "cron", Status: "implemented"},
		{SiteClass: "cron.user", Module: "cron", Status: "implemented"},
		{SiteClass: "systemd.unit", Module: "systemd", Status: "planned"},
	}
	code := []coverage{
		{Module: "cron", SiteClass: "cron.d"},
		{Module: "cron", SiteClass: "cron.user"},
	}
	got := audit(matrix, code)
	if len(got) != 0 {
		t.Errorf("audit on consistent inputs returned drift: %v", got)
	}
}

// TestAudit_CodeWithoutMatrix: a module emits a site_class that does
// not appear in matrix.yaml.
func TestAudit_CodeWithoutMatrix(t *testing.T) {
	matrix := []matrixEntry{
		{SiteClass: "cron.d", Module: "cron", Status: "implemented"},
	}
	code := []coverage{
		{Module: "cron", SiteClass: "cron.d"},
		{Module: "rogue", SiteClass: "rogue.new"},
	}
	got := audit(matrix, code)
	if !containsSubstr(got, "rogue.new") || !containsSubstr(got, "code-without-matrix") {
		t.Errorf("expected code-without-matrix drift for rogue.new; got %v", got)
	}
}

// TestAudit_MatrixLying_Implemented: matrix says implemented but no
// module emits the site_class.
func TestAudit_MatrixLying_Implemented(t *testing.T) {
	matrix := []matrixEntry{
		{SiteClass: "cron.d", Module: "cron", Status: "implemented"},
		{SiteClass: "ghost.thing", Module: "ghost", Status: "implemented"},
	}
	code := []coverage{
		{Module: "cron", SiteClass: "cron.d"},
	}
	got := audit(matrix, code)
	if !containsSubstr(got, "ghost.thing") || !containsSubstr(got, "matrix-lying") {
		t.Errorf("expected matrix-lying drift for ghost.thing; got %v", got)
	}
}

// TestAudit_MatrixLying_Tested: same rule applies to status "tested".
func TestAudit_MatrixLying_Tested(t *testing.T) {
	matrix := []matrixEntry{
		{SiteClass: "ghost.tested", Module: "ghost", Status: "tested"},
	}
	code := []coverage{} // nothing
	got := audit(matrix, code)
	if !containsSubstr(got, "ghost.tested") || !containsSubstr(got, "matrix-lying") {
		t.Errorf("expected matrix-lying drift for tested status; got %v", got)
	}
}

// TestAudit_PlannedWithCode: matrix says planned but a module emits
// the site_class. Someone started implementing without flipping the
// status. This is the typical "I forgot to update matrix.yaml" case.
func TestAudit_PlannedWithCode(t *testing.T) {
	matrix := []matrixEntry{
		{SiteClass: "systemd.unit", Module: "systemd", Status: "planned"},
	}
	code := []coverage{
		{Module: "systemd", SiteClass: "systemd.unit"},
	}
	got := audit(matrix, code)
	if !containsSubstr(got, "systemd.unit") || !containsSubstr(got, "planned-with-code") {
		t.Errorf("expected planned-with-code drift; got %v", got)
	}
}

// TestAudit_ModuleNameMismatch: matrix says module "foo" owns site_class
// "bar.baz" but the code says module "qux" emits it.
func TestAudit_ModuleNameMismatch(t *testing.T) {
	matrix := []matrixEntry{
		{SiteClass: "shared.thing", Module: "alpha", Status: "implemented"},
	}
	code := []coverage{
		{Module: "beta", SiteClass: "shared.thing"},
	}
	got := audit(matrix, code)
	if !containsSubstr(got, "module-name-mismatch") {
		t.Errorf("expected module-name-mismatch drift; got %v", got)
	}
}

// TestAudit_WipAllowsMissingCode: status wip is the only state that
// tolerates a site_class being absent from code. That is the
// definition of "work in progress".
func TestAudit_WipAllowsMissingCode(t *testing.T) {
	matrix := []matrixEntry{
		{SiteClass: "halfway.there", Module: "halfway", Status: "wip"},
	}
	code := []coverage{} // nothing yet
	got := audit(matrix, code)
	if len(got) != 0 {
		t.Errorf("wip site_class missing from code should NOT drift; got %v", got)
	}
}

// TestAudit_WipFlagsNameMismatch: wip still requires that if the code
// DOES emit the site_class, the module name agrees with matrix.yaml.
func TestAudit_WipFlagsNameMismatch(t *testing.T) {
	matrix := []matrixEntry{
		{SiteClass: "drift.site", Module: "alpha", Status: "wip"},
	}
	code := []coverage{
		{Module: "beta", SiteClass: "drift.site"},
	}
	got := audit(matrix, code)
	if !containsSubstr(got, "module-name-mismatch") {
		t.Errorf("expected wip + name mismatch to drift; got %v", got)
	}
}

// TestAudit_InvalidStatus: status outside the validStatuses set is a
// typo waiting to happen and the audit must catch it.
func TestAudit_InvalidStatus(t *testing.T) {
	matrix := []matrixEntry{
		{SiteClass: "broken.entry", Module: "x", Status: "doneish"},
	}
	got := audit(matrix, nil)
	if !containsSubstr(got, "invalid status") {
		t.Errorf("expected invalid-status drift; got %v", got)
	}
}

// TestAudit_DuplicateSiteClass: the same site_class declared twice in
// matrix.yaml. Catches copy-paste mistakes.
func TestAudit_DuplicateSiteClass(t *testing.T) {
	matrix := []matrixEntry{
		{SiteClass: "cron.d", Module: "cron", Status: "implemented"},
		{SiteClass: "cron.d", Module: "cron", Status: "wip"},
	}
	code := []coverage{
		{Module: "cron", SiteClass: "cron.d"},
	}
	got := audit(matrix, code)
	if !containsSubstr(got, "duplicate site_class") {
		t.Errorf("expected duplicate-site_class drift; got %v", got)
	}
}

// TestAudit_DuplicateCodeEmission: two modules emit the same
// site_class. Forbidden by design -- modules must own disjoint sets.
func TestAudit_DuplicateCodeEmission(t *testing.T) {
	matrix := []matrixEntry{
		{SiteClass: "overlap", Module: "alpha", Status: "implemented"},
	}
	code := []coverage{
		{Module: "alpha", SiteClass: "overlap"},
		{Module: "beta", SiteClass: "overlap"},
	}
	got := audit(matrix, code)
	if !containsSubstr(got, "disjoint site_class") {
		t.Errorf("expected disjoint-site_class drift; got %v", got)
	}
}

// TestAudit_StableOrdering: running audit twice on the same drifted
// inputs produces identical message order. Required for diff-friendly
// CI logs.
func TestAudit_StableOrdering(t *testing.T) {
	matrix := []matrixEntry{
		{SiteClass: "zzz.late", Module: "z", Status: "implemented"},
		{SiteClass: "aaa.early", Module: "a", Status: "implemented"},
	}
	code := []coverage{} // both will trigger matrix-lying
	first := audit(matrix, code)
	second := audit(matrix, code)
	if len(first) != len(second) {
		t.Fatalf("audit length unstable: first=%d second=%d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Errorf("audit ordering unstable at index %d: %q vs %q",
				i, first[i], second[i])
		}
	}
	// Alphabetical: aaa.early should be reported before zzz.late.
	if !strings.Contains(first[0], "aaa.early") {
		t.Errorf("first drift message should be aaa.early, got %q", first[0])
	}
}

// TestSummarize counts status buckets independently of audit drift.
func TestSummarize(t *testing.T) {
	matrix := []matrixEntry{
		{SiteClass: "a", Status: "implemented"},
		{SiteClass: "b", Status: "implemented"},
		{SiteClass: "c", Status: "tested"},
		{SiteClass: "d", Status: "wip"},
		{SiteClass: "e", Status: "planned"},
		{SiteClass: "f", Status: "planned"},
		{SiteClass: "g", Status: "weird-unknown-status"}, // ignored by summarize
	}
	s := summarize(matrix)
	if s.implemented != 2 || s.tested != 1 || s.wip != 1 || s.planned != 2 {
		t.Errorf("summarize = %+v; want implemented=2 tested=1 wip=1 planned=2", s)
	}
}

// TestCodeCoverage flattens a set of Modules into (module, site_class)
// pairs. Cheap fakes implementing core.Module are enough.
func TestCodeCoverage(t *testing.T) {
	modules := []core.Module{
		fakeModule{name: "alpha", scs: []string{"alpha.one", "alpha.two"}},
		fakeModule{name: "beta", scs: []string{"beta.x"}},
	}
	got := codeCoverage(modules)
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3: %v", len(got), got)
	}
	want := map[string]string{
		"alpha.one": "alpha",
		"alpha.two": "alpha",
		"beta.x":    "beta",
	}
	for _, c := range got {
		if want[c.SiteClass] != c.Module {
			t.Errorf("coverage %+v inconsistent with want %v", c, want)
		}
	}
}

// --- test helpers --------------------------------------------------

// fakeModule is a stand-in for core.Module. Collect is a no-op
// because matrix-audit never invokes it; only Name and SiteClasses
// matter for the audit.
type fakeModule struct {
	name string
	scs  []string
}

func (m fakeModule) Name() string          { return m.name }
func (m fakeModule) SiteClasses() []string { return m.scs }
func (m fakeModule) Collect(ctx context.Context, emit func(core.Record)) error {
	return nil
}

// containsSubstr reports whether any message in msgs contains needle.
func containsSubstr(msgs []string, needle string) bool {
	for _, m := range msgs {
		if strings.Contains(m, needle) {
			return true
		}
	}
	return false
}
