package main

import (
	_ "embed"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Q11 vendor-baseline allow-list and the Q12 basename-clustering
// extension list are kept in YAML data files under assets/ so an
// operator can tune them without recompiling the Go source.
//
//go:embed assets/vendor_basenames.yaml
var embeddedVendorBasenamesYAML []byte

//go:embed assets/script_extensions.yaml
var embeddedScriptExtensionsYAML []byte

// q11VendorBaselineBasenames is the set form of the embedded YAML list.
// Initialized once at process start; a malformed YAML file fails the
// binary at init() rather than at first Q11 row.
var q11VendorBaselineBasenames = mustLoadBasenameSet(embeddedVendorBasenamesYAML)

// q12StripExtensions is the ordered list of extensions Q12 strips from
// a basename before clustering. Order is observable — the first match
// wins — but the canonical set is short and non-overlapping today.
var q12StripExtensions = mustLoadStringList(embeddedScriptExtensionsYAML, "extensions")

type basenamesDoc struct {
	Basenames []string `yaml:"basenames"`
}

type stringListDoc map[string][]string

func mustLoadBasenameSet(raw []byte) map[string]struct{} {
	var doc basenamesDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		panic(fmt.Sprintf("linpersist-report: parse vendor_basenames.yaml: %v", err))
	}
	set := make(map[string]struct{}, len(doc.Basenames))
	for _, b := range doc.Basenames {
		if b == "" {
			continue
		}
		set[b] = struct{}{}
	}
	return set
}

func mustLoadStringList(raw []byte, key string) []string {
	var doc stringListDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		panic(fmt.Sprintf("linpersist-report: parse embedded yaml: %v", err))
	}
	list, ok := doc[key]
	if !ok {
		panic(fmt.Sprintf("linpersist-report: embedded yaml missing key %q", key))
	}
	return list
}
