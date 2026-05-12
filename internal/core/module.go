// Package core defines the contract between the linpersist runner and
// each persistence-collection module, plus a handful of shared helpers
// (hashing, normalization, host metadata, NDJSON emission, signals).
//
// Modules MUST be:
//   - read-only on the target host (no writes outside the --output file
//     handled by the runner);
//   - stateless across Collect invocations;
//   - concurrency-safe within a single Collect invocation;
//   - context-aware (cancel promptly on ctx.Done()).
package core

import "context"

// Module is the contract every persistence collector implements.
//
// Implementations live under internal/modules/<name>/ and are wired into
// the runner from cmd/linpersist/main.go. The runner invokes Collect in
// its own goroutine, bounded by a per-module timeout (default 30s).
type Module interface {
	// Name returns the canonical module identifier, e.g. "cron".
	// MUST match the module field in matrix.yaml entries.
	Name() string

	// SiteClasses returns the list of site_class values this module
	// emits. MUST match the site_class entries in matrix.yaml.
	SiteClasses() []string

	// Collect walks the module's loci, normalizes content, computes
	// hashes and signals, and emits one Record per artifact via emit.
	//
	// Collect MUST respect ctx cancellation. On ctx.Err() it should
	// return as soon as possible; partial records already emitted are
	// fine. Errors discovered while processing a single locus should
	// be attached to that locus's Record via Record.Errors and NOT
	// surfaced as the Collect return value; reserve the return value
	// for module-fatal conditions (e.g. the runner can decide whether
	// to mark the whole module as degraded).
	Collect(ctx context.Context, emit func(Record)) error
}
