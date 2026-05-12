# ADR-0001: The `core.Module` interface

- Status: Accepted
- Date: 2026-05-12

## Context

`linpersist` needs to enumerate dozens of persistence sites on Linux,
each with its own file format, locus list, and normalization rules.
Three shapes were on the table:

1. **One monolithic walker** that switches on path prefix and contains
   every parser inline.
2. **Plugin model** loaded via `plugin.Open`.
3. **Compile-time module set** behind a small interface, wired from
   `main.go`.

## Decision

Adopt option 3. Define `core.Module` as:

```go
type Module interface {
    Name() string
    SiteClasses() []string
    Collect(ctx context.Context, emit func(Record)) error
}
```

- `Name()` ties the module to its `matrix.yaml` row.
- `SiteClasses()` is the explicit cross-check used by
  `tools/matrix_audit.go` to refuse a release that ships a site_class
  not declared in the matrix (or vice versa).
- `Collect` takes the cancellation context and a Record emitter. The
  emitter is the only side effect a module is allowed.

The runner (`internal/core/runner.go`) is responsible for the per-module
timeout, the goroutine fan-out, and serializing the sink. Modules
themselves do not know about timeouts, fan-out, or NDJSON.

## Consequences

- Adding a site_class is local: new package under
  `internal/modules/<name>/`, plus one line in `main.go` and one entry
  in `matrix.yaml`.
- `internal/core/` stays small and stable. The runner's contract is the
  only thing module authors need to learn.
- We trade Go's plugin runtime flexibility for static linking. This is
  aligned with the static-binary constraint (`CGO_ENABLED=0`,
  `osusergo netgo`); `plugin.Open` requires CGO, so it was off the
  table from day one.

## Alternatives rejected

- **`plugin.Open`**: requires CGO and dynamic linking; breaks the
  static-binary tenet. Also rules out cross-compilation to other
  architectures from a single host.
- **Monolithic walker**: hostile to testing. Each persistence family
  has unique normalization quirks; sharing one giant `switch` mixes
  responsibilities and inflates the blast radius of every change.
