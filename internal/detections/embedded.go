// Embedded copy of the rule set.
//
// `detections.yaml` lives in this package directory rather than at
// the repo root because go:embed forbids `..` patterns in paths.
// Tools that need the raw bytes (cmd/detgen) read it from the same
// path; the report binary calls LoadEmbedded() to get a parsed,
// validated RuleSet without re-parsing on every invocation.

package detections

import (
	_ "embed"
	"fmt"
)

//go:embed detections.yaml
var embeddedYAML []byte

// EmbeddedYAML returns the raw bytes of the bundled detections.yaml.
// Used by cmd/detgen as the source-of-truth when it has no -yaml
// flag override.
func EmbeddedYAML() []byte {
	out := make([]byte, len(embeddedYAML))
	copy(out, embeddedYAML)
	return out
}

// LoadEmbedded parses and validates the bundled rule set using the
// live signals catalog. Returns an error rather than panicking so
// callers can choose between init-time panic and graceful runtime
// degradation.
func LoadEmbedded() (*RuleSet, error) {
	rs, err := Load(embeddedYAML, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("load embedded detections.yaml: %w", err)
	}
	return rs, nil
}

// MustLoadEmbedded is LoadEmbedded for callers that treat a malformed
// rule set as a programming error (typical for init() use).
func MustLoadEmbedded() *RuleSet {
	rs, err := LoadEmbedded()
	if err != nil {
		panic(err)
	}
	return rs
}
