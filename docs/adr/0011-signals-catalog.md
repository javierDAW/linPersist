# ADR-0011: Iterable signals catalog as a buildtime invariant

- Status: Accepted
- Date: 2026-05-20
- Related: `internal/core/signals.go`, `internal/core/signals_catalog.go`,
  `internal/core/signals_test.go`, `internal/core/signals_emission_test.go`,
  ADR-0001 (matrix.yaml release gate via `matrix-audit`).

## Context

`internal/core/signals.go` declared 40 `Signal*` constants — the names
the agent is allowed to emit in `Record.Signals`. The constants were
documented, but they were just a flat list. Nothing iterated them.

Three concrete failure modes followed from that:

1. **String-literal drift inside the agent itself.** Discovered while
   auditing the catalog before adopting it: `internal/modules/sshd/`
   was emitting two signals as raw string literals
   (`"sshd_permit_root_login_yes"`, `"sshd_authorized_keys_command"`)
   instead of through the `core.Signal*` constants. The string values
   matched by coincidence. If anyone had renamed the constant, the
   module would have kept emitting the old string silently; if anyone
   had renamed the string, every downstream consumer that referenced
   the constant would have been broken without compiler help.
2. **Cross-binary drift.** `tools/stack_demo.sql` Q7 and
   `cmd/linpersist-report/stats.go` `rollCallSignals` each carried a
   curated list of "triage signals" — same set, two copies, no
   structural link to the const declarations. The `CHANGELOG` entry
   for `[Unreleased] D1` already documented an instance of this
   ("Applied to both `tools/stack_demo.sql` Q7 and
   `cmd/linpersist-report/stats.go` `rollCallMatches` so the SQL and
   Go-native paths stay in sync"). Manual two-place edits are not a
   sustainable contract.
3. **No way for downstream consumers to enumerate the universe.** A
   future `detections.yaml` loader (planned) wants to validate that
   every `signals_all` / `signals_any` token in user-supplied rules
   references a real signal. Without an iterable catalog the loader
   would either duplicate the list or skip the check.

The fix is small: keep the constants, add an iterable mirror, and
back it with buildtime tests that fail the build if the two ever
disagree. The shape decisions below are the non-obvious parts.

## Decisions

### A flat `[]SignalDef` slice, not a map

The catalog is a slice ordered to match the const block in
`signals.go`, not a `map[string]SignalDef`. Reasons:

- Order matters for two consumers: the report's signal-distribution
  panel reads better when grouped by category, and any future
  generator (Markdown reference, OpenAPI-style schema dump) wants a
  stable iteration order.
- Iteration over the slice is O(n) and `n = 40`; the per-lookup
  `signalsByName` map is built once in `init()` and gives O(1) for
  the hot path.
- A map literal would also force alphabetical-by-name comprehension;
  the const ordering is by domain (file-meta → core helpers → per-
  module groupings), which is the right cognitive map.

### `EmittedBy` declared, not inferred

Each `SignalDef` carries an `EmittedBy []string` listing the modules
(`"cron"`, `"sshd"`, ...) and core helpers (`"core/provenance"`,
`"core/proclive"`) that emit it. The alternative — inferring the
mapping at test time by scanning the source tree — was rejected:

- The declared form makes the catalog a self-contained reference
  document. Reading `signals_catalog.go` tells you both *what* the
  signal means (`Description`) and *where* it comes from
  (`EmittedBy`). No reader needs to grep the codebase to answer
  "who emits `kmod_install_directive`?".
- The buildtime test (`signals_emission_test.go`) still scans the
  source, but to verify the declared mapping rather than discover
  it. Declared values diverging from observed values is the exact
  failure we want to catch.

### Cross-source audit via regex, not AST

`signals_emission_test.go` scans `internal/modules/<name>/*.go` for
`core.Signal<Foo>` and `internal/core/<helper>.go` for `Signal<Foo>`
using `regexp`, not `go/parser` / `go/ast`. The trade-off:

- The regex approach is ~50 LOC and obvious to read.
- It would in theory accept a false positive if a module mentioned
  `core.SignalSomething` inside a string literal or a comment
  without actually emitting it. The codebase does not do this; a
  reviewer would notice if anyone added one.
- The harder failure mode in any AST approach is build-dependency
  drift: an AST scanner that fails to parse new Go syntax fails
  loudly on unrelated work. The regex scanner does not have that
  risk.

If the regex ever fails us (e.g. a module starts referencing a
signal name from a docstring), switch to AST. Until then the
simplicity is its own merit.

### `EmittedBy` token shape

Tokens are either a bare lowercase module name (`"cron"`, `"sshd"`)
or a `"core/<file>"` form (`"core/provenance"`, `"core/proclive"`).
The shape is enforced by `TestSignalCatalogEmittedByTokenShape`.
This namespace keeps "signal emitted by a module" and "signal applied
by a shared helper" distinguishable without adding a struct field.
The two `core/<file>` cases today are `provenance` (sets
`SignalNonPackagePath` after the dpkg/rpm resolver runs) and
`proclive` (sets `SignalLiveProcessAttached` after the `/proc`
snapshot lookup); see ADR-0009 and ADR-0010 for their rationale.

### Description shape

`Description` is a single-line summary, 20–200 characters, no
trailing period. The full rationale (multi-paragraph context, MITRE
mapping, threat-intel sources) stays in the const's docstring in
`signals.go`. Reasons for keeping them separate:

- The catalog `Description` is consumed at runtime (report tooltips,
  detection rule output, error messages from invalid rule files).
  A multi-paragraph string would be a UX problem in those contexts.
- The docstring on the const is the developer-facing reference. It
  can carry as much context as the next maintainer needs.
- Drift between the two is acceptable: the docstring may evolve
  with more detail without breaking anything, and the `Description`
  is short enough to keep current in code review.

## Consequences

- `internal/core/signals.go` is unchanged. The 40 constants stay
  exactly as before; nothing in the rest of the codebase had to
  switch.
- `internal/core/signals_catalog.go` (new, ~360 LOC) holds the
  `SignalDef` struct, the `Signals` slice, and the lookup helpers
  (`SignalByName`, `KnownSignal`, `KnownSignalSet`).
- `internal/core/signals_test.go` (new, ~125 LOC) runs five internal
  consistency checks on the slice.
- `internal/core/signals_emission_test.go` (new, ~180 LOC) runs the
  cross-source audit: every `EmittedBy` is observed in code, and
  every observed emission is in the catalog.
- `cmd/linpersist-report/stats.go` migrated to use `core.Signal*`
  constants instead of string literals in `rollCallSignals`,
  `rollCallMatches`, Q4 (`containsAll(...)`) and Q9 (`sigSet[...]`).
  No behavioural change against `lab-realistic`: Q1=22, Q4=6, Q7=22,
  Q8=42, Q11=6 unchanged.
- `internal/modules/sshd/normalize.go` had already been migrated in
  the previous polish step (the bug that surfaced this ADR).
- No new dependencies. The audit tests use stdlib only (`os`,
  `path/filepath`, `regexp`, `strings`, `testing`).
- Future detections.yaml work (planned) consumes the catalog via
  `KnownSignalSet()` to validate user-supplied rules before they
  reach the predicate engine.

## Alternatives rejected

- **Generate the catalog from the const block at `go generate` time.**
  Tempting but adds a build step and a generated file in the repo
  that nobody reads. The hand-written catalog is the documentation;
  the test is the link.
- **Make every module register its signals at `init()` time.** Would
  build the `EmittedBy` map at runtime instead of declaring it. The
  catalog would then live in 18 module `init` blocks rather than
  one file; harder to read, harder to diff, harder to validate.
- **Add a `Severity` field to `SignalDef`.** Considered briefly and
  rejected. Severity is a detection-time judgment ("how worried
  should the analyst be?") and belongs in the future
  `detections.yaml`, not on the signal itself. The agent's
  contract is *the agent collects, the backend decides* — keeping
  scoring out of `signals.go` is the same principle as keeping
  scoring out of `cmd/linpersist`.

## References

- `internal/core/signals.go` — canonical const declarations.
- `internal/core/signals_catalog.go` — iterable mirror.
- `internal/core/signals_test.go` — five internal-consistency tests.
- `internal/core/signals_emission_test.go` — cross-source audit.
- ADR-0001 — `matrix-audit`, the analogous release gate for
  `matrix.yaml` ↔ module registration.
- ADR-0009 — dpkg/rpm provenance helper that emits
  `SignalNonPackagePath`.
- ADR-0010 — `/proc` snapshot helper that emits
  `SignalLiveProcessAttached`.
