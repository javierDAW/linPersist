# linpersist

A read-only Linux persistence-artifact collector, written in Go, designed
for fleet-scale execution and downstream frequency stacking (Least
Frequency Analysis).

`linpersist` enumerates known persistence sites on Linux hosts, normalizes
their contents, and emits a stream of NDJSON records to stdout. It does
not classify anything as malicious. The agent collects; the backend
decides.

## Design tenets

- **Single static binary per architecture.** `CGO_ENABLED=0`, build tags
  `osusergo netgo`. `ldd` reports "not a dynamic executable".
- **Read-only on the host.** The only path the agent ever writes to is
  the file given by `--output`; absent that flag, output goes to stdout.
- **Modular by site_class.** One module per family of persistence sites,
  implementing the `core.Module` interface. Adding coverage = adding a
  module, never touching `internal/core`.
- **Deterministic normalization.** Each module computes a
  `content_norm_sha256` over a canonical form of the artifact so that
  semantically-equivalent inputs collapse to the same hash for stacking.
- **MITRE ATT&CK explicit.** Every record carries the precise sub-technique
  IDs (e.g. `T1053.003`, not `T1053`). `matrix.yaml` is the source of
  truth for coverage.
- **Schema versioned.** `schema_v: 1`. Breaking changes bump the major
  version with a migration documented in `docs/`.

## Status

Pre-alpha. Skeleton + portability gate only. No persistence modules
implemented yet. See `matrix.yaml` for planned coverage and current
status per `site_class`.

## Build

```sh
make build-all   # cross-compile linux/{amd64,arm64,386,arm-v7}
make verify      # ldd + file checks for static binary
make test        # go test -race ./...
make lint        # go vet + gofmt
```

## Usage

```sh
linpersist --output /tmp/host.ndjson
linpersist                            # emits NDJSON to stdout
linpersist --include-hostname         # opt in to plaintext hostname
linpersist --module-timeout 60s
```

## License

Apache-2.0. See [LICENSE](./LICENSE).

Copyright (c) 2026 Jarmi (jarmidaw).
