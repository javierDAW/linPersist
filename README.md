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

Alpha, working toward v0.1.0. Eight modules implemented and golden-tested,
covering 17 `site_class` values across nine MITRE ATT&CK techniques.
Cross-compilation matrix and a multi-distro Docker lab are in place. Six
critical modules from the v0.1.0 set are still pending (see below). The
NDJSON schema is at v1; breaking changes will bump the major and ship
with a migration note in `docs/`. See `matrix.yaml` for the canonical
per-`site_class` status.

## Modules

| Module    | site_classes covered                                          | MITRE                       |
| --------- | ------------------------------------------------------------- | --------------------------- |
| `cron`    | `cron.d`, `cron.user`, `cron.periodic`, `cron.anacron`        | T1053.003                   |
| `ldso`    | `ldso.preload`, `ldso.conf`, `ldso.confd`                     | T1574.006                   |
| `ssh`     | `ssh.authkeys`                                                | T1098.004                   |
| `sshd`    | `sshd.config`                                                 | T1098.004, T1556            |
| `sudoers` | `sudoers`                                                     | T1548.003                   |
| `passwd`  | `passwd.user`, `passwd.shadow`, `passwd.group`, `passwd.gshadow` | T1136.001               |
| `pam`     | `pam`                                                         | T1556.003                   |
| `profile` | `profile.system`, `profile.user`                              | T1546.004                   |

Pending for v0.1.0: `systemd.unit`, `systemd.timer`, `sysv.init`, `motd`,
`kmod`, `udev`.

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
linpersist --version
```

## Lab

`lab/` and `lab-large/` contain Dockerfiles for the target distros
(`ubuntu:22.04`, `debian:11`, `rhel:8`, `alpine:3.19`, `amazonlinux:2023`),
baseline + implant fixtures, a `collect_all.sh` script, and DuckDB
queries demonstrating frequency stacking against the resulting NDJSON.
See `lab/README.md` for the end-to-end demo.

## Documentation

- `docs/schema-v1.md` — canonical record description.
- `docs/normalization-rules.md` — invariants every module's `Normalize`
  honors.
- `docs/adr/` — Architecture Decision Records (currently five).

## License

Apache-2.0. See [LICENSE](./LICENSE).

Copyright (c) 2026 Jarmi (jarmidaw).
