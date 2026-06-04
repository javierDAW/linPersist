package main

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// TestDiscriminatorTableExhaustive is the ADR-0017 build gate: every
// site_class in matrix.yaml MUST have a discriminator class. A new module
// that forgets to classify its site_class fails the build here rather than
// silently defaulting (which would either re-open the rung-4 flood or
// silently strip a new known-locus module of its verdict-power).
func TestDiscriminatorTableExhaustive(t *testing.T) {
	var mf matrixFileYAML
	if err := yaml.Unmarshal(embeddedMatrixYAML, &mf); err != nil {
		t.Fatalf("parse embedded matrix.yaml: %v", err)
	}
	if len(mf.SiteClasses) == 0 {
		t.Fatal("matrix.yaml parsed to zero site_classes")
	}
	seen := map[string]bool{}
	for _, e := range mf.SiteClasses {
		seen[e.SiteClass] = true
		if _, ok := classifySiteClass(e.SiteClass); !ok {
			t.Errorf("site_class %q (module %q) is not classified in siteClassDisc — add it (ADR-0017)", e.SiteClass, e.Module)
		}
	}
	// And the reverse: no stale entries for site_classes that no longer
	// exist in matrix.yaml.
	for sc := range siteClassDisc {
		if !seen[sc] {
			t.Errorf("siteClassDisc has stale entry %q with no matrix.yaml site_class", sc)
		}
	}
}

// TestWebrootIsNoveltyOnly pins the one current novelty-only classification
// (the duel-final / ADR-0017 anchor): the docroot walk is the collector
// where provenance is structurally inapplicable.
func TestWebrootIsNoveltyOnly(t *testing.T) {
	c, ok := classifySiteClass("webroot.script")
	if !ok || c != discNoveltyOnly {
		t.Errorf("webroot.script must be discNoveltyOnly, got class=%v ok=%v", c, ok)
	}
	// A structural site_class must not be novelty-only.
	if c, _ := classifySiteClass("cron.d"); c != discStructural {
		t.Error("cron.d must be discStructural (provenance/exec applies)")
	}
}
