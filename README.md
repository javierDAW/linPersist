# linpersist

> Read-only Linux persistence-artifact collector. Single static binary,
> NDJSON output, designed to run on thousands of hosts and feed a
> frequency-stacking backend.

`linpersist` walks every well-known Linux persistence site
(cron, systemd, ssh, sudoers, pam, ld.so.preload, modprobe.d, udev rules,
and ten more), normalizes each artifact's content to a canonical form,
and emits one NDJSON record per artifact to stdout. The agent **does not
classify anything as malicious**. It collects; a downstream database
decides. The design is built for fleet-scale Least Frequency Analysis
(LFA): every record carries a `content_norm_sha256` digest so that
identical artifacts across hosts collapse to the same hash and malicious
singletons surface in the long tail of the histogram.

## What you get

```sh
# Run on a host:
$ ./linpersist | head -1 | python3 -m json.tool
{
  "schema_v": 1,
  "host_id": "8f3b1e2a-...",
  "host_meta": {
    "hostname_hash": "sha256:abc12...",
    "os_id": "ubuntu", "os_version": "22.04",
    "kernel": "5.15.0-91-generic", "arch": "x86_64",
    "boot_id": "f0a8...", "tags": []
  },
  "collected_at": "2026-05-17T10:00:00Z",
  "agent_version": "linpersist-0.1.0-alpha",
  "module": "cron",
  "site_class": "cron.d",
  "mitre": ["T1053.003"],
  "locus": "/etc/cron.d/update-helper",
  "owner_uid": 0, "owner_gid": 0, "mode": "0644",
  "mtime": "2026-05-10T03:14:00Z",
  "size": 142,
  "content_sha256": "ab12...",
  "content_norm_sha256": "cd34...",
  "content_snippet": "*/5 * * * * root /tmp/.h/agent",
  "exec_target": "/tmp/.h/agent",
  "signals": ["exec_target_orphan", "interpreter_in_tmp"]
}
```

One record per persistence artifact, NDJSON-streamed, ready for any
columnar backend (DuckDB, ClickHouse, Athena, BigQuery).

## Coverage (v0.1.0-alpha)

**13 modules, 23 site_classes, 14 MITRE ATT&CK techniques.** Every
module emits the same record shape; what varies is the canonical-form
rule for that site_class family.

| Module    | Covers                                                            | MITRE                       |
| --------- | ----------------------------------------------------------------- | --------------------------- |
| `cron`    | `cron.d`, `cron.user`, `cron.periodic`, `cron.anacron`            | T1053.003                   |
| `systemd` | `systemd.unit`, `systemd.timer`                                   | T1543.002, T1053.006        |
| `sysv`    | `sysv.init` (incl. RHEL `/etc/rc.d/`, `rc.local`, external rc?.d symlinks) | T1037.004           |
| `ssh`     | `ssh.authkeys` (system + per-user, blob never emitted raw)        | T1098.004                   |
| `sshd`    | `sshd.config` (incl. drop-ins, Match blocks)                      | T1098.004, T1556            |
| `sudoers` | `sudoers` (incl. `sudoers.d/*`, NOPASSWD + ALL flags)             | T1548.003                   |
| `passwd`  | `passwd.user`, `passwd.shadow`, `passwd.group`, `passwd.gshadow` (hashes never emitted) | T1136.001 |
| `pam`     | `pam` (`/etc/pam.d/*` + legacy `/etc/pam.conf`)                   | T1556.003                   |
| `profile` | `profile.system`, `profile.user` (Bash + Zsh init)                | T1546.004                   |
| `ldso`    | `ldso.preload`, `ldso.conf`, `ldso.confd`                         | T1574.006                   |
| `kmod`    | `kmod` (modules-load.d + modprobe.d directives)                   | T1547.006                   |
| `udev`    | `udev` (per-rule, with `RUN+=` exec_target extraction)            | T1546                       |
| `motd`    | `motd` (`/etc/motd*`, `/etc/update-motd.d/*`)                     | T1037                       |

See [`matrix.yaml`](./matrix.yaml) for the authoritative per-site_class
status, loci, and notes.

## End-to-end: from one host to a triage page

The project ships two binaries from the same build (`make build-all`
produces both): `linpersist` is the agent, `linpersist-report` is the
self-contained HTML report generator. Pick the path that fits your
fleet size.

### Path A — `linpersist-report` (recommended for fleets ≤ ~10k hosts)

```sh
# 1. Build both binaries (static, no CGO).
make build-all
file dist/linpersist-linux-amd64
# linpersist-linux-amd64: ELF 64-bit LSB executable, x86-64, statically linked, ...

# 2. Deploy linpersist and run on every host (~10 MB, seconds to complete).
./linpersist --output /var/log/linpersist/$(hostname).ndjson

# 3. Pull the per-host files into one directory and generate the report.
./linpersist-report -i fleet/ -o report.html
# Or, from an SSH-only jump host without a browser:
./linpersist-report -i fleet/ -format text | less -R

# 4. Open report.html — fleet overview, 6 stacking queries, signal
#    distribution, LFA histogram, all in one self-contained page.
```

`linpersist-report` ships two output formats from the same binary:
**HTML** (default — dark/light themes, sortable tables, live search,
zero network calls) and **text** (column-aligned ASCII for
terminals, ANSI-colored when stdout is a TTY). Email the HTML, page
the text through `less` on a jump host, or commit either to a
triage-evidence repo. See [`docs/report.md`](./docs/report.md) for
the anatomy of each section and the when-to-use-which matrix; the
binding design decision lives in
[ADR-0008](./docs/adr/0008-report-dual-rendering.md).

### Path B — DuckDB cookbook (for larger fleets or power users)

```sh
# Same steps 1-2. Then:
duckdb fleet.duckdb <<EOF
CREATE TABLE r AS SELECT * FROM read_ndjson_auto('fleet/*.ndjson', ignore_errors=true);
.read tools/stack_demo.sql
EOF
```

Columnar engine scales past the ~10k-host envelope where the Go
report starts taking minutes. The same six queries, executable.
[`docs/stacking-cookbook.md`](./docs/stacking-cookbook.md) walks
through each query with false-positive guidance.

## Why this and not osquery / Velociraptor / UAC

| | `linpersist` | osquery | Velociraptor | UAC |
| - | - | - | - | - |
| Shape | persistence-only collector | general telemetry agent | DFIR agent + server | live-response collector |
| Output | NDJSON, one record per artifact | SQL tables, per-query | VQL artifacts | tar.gz of raw files |
| Optimized for | fleet-scale LFA across thousands of hosts | host-level real-time queries | incident response | single-host triage |
| Footprint | one static 10 MB binary, no daemon | 50+ MB, daemon | server + clients | thousands of shell helpers |
| Decisions on the host | none (zero classification) | thresholds + scheduled packs | rule-based | none |

`linpersist` is intentionally a small piece of the pipeline. It produces
the highest-quality input for stacking that the agent stage can
produce — deterministic canonical hashes, explicit MITRE IDs, no
runtime state — and stops there.

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
- **MITRE ATT&CK explicit.** Every record carries the precise
  sub-technique IDs (e.g. `T1053.003`, not `T1053`). `matrix.yaml` is
  the source of truth for coverage.
- **Schema versioned.** `schema_v: 1` is frozen for the v0.1.x line.
  Breaking changes bump the major and ship with a documented migration.
- **The agent collects; the backend decides.** No allowlists, no
  signatures, no scoring inside the binary. Every "verdict-shaped"
  decision lives in the database.

## Build and run

```sh
make build-all   # cross-compile linux/{amd64,arm64,386,arm-v7}
make verify      # ldd + file checks confirm static
make test        # go test -race ./...
make lint        # go vet + gofmt
make audit       # matrix.yaml ↔ registered modules consistency check
```

Common invocations:

```sh
linpersist                            # NDJSON to stdout
linpersist --output /tmp/host.ndjson  # write to file (only path written)
linpersist --include-hostname         # opt-in plaintext hostname in host_meta
linpersist --module-timeout 60s       # per-module deadline (default 30s)
linpersist --version
```

The agent makes **zero network calls** and **zero state changes** to
the host. The cron-driven deployment pattern is one collection per host
per day; budget ~500 KB-2 MB of NDJSON per host depending on how many
unit files / modprobe directives / etc. exist on it.

## Privacy

Two fields are deliberately conservative by default:

- `host_meta.hostname` is **omitted** from output. `--include-hostname`
  opts in to plaintext; without it only `host_meta.hostname_hash` ships.
  See [`docs/adr/0006-hostname-policy.md`](./docs/adr/0006-hostname-policy.md).
- SSH public-key blobs (`/root/.ssh/authorized_keys` and friends) and
  /etc/shadow / /etc/gshadow password hashes are **never emitted raw**.
  Only digests and a `password_status` enum (`set` / `locked` /
  `disabled` / `empty` / `unknown`). See ADR-0003 and ADR-0005.

## Validation

Every module ships with golden fixture tests under
`internal/testdata/golden/<module>/` exercised by
`go test ./internal/modules/...` — happy paths, edge cases,
malformed inputs, robustness contracts. Plus a `matrix-audit`
release gate (`make audit`) that fails the build if
`matrix.yaml` and the registered modules drift apart.

Beyond the unit envelope, v0.1.0-alpha was validated end-to-end
against a synthetic fleet of **25 Docker containers across five
distros** (Debian 11, RHEL 8, Ubuntu 22.04, Amazon Linux 2023,
Alpine 3.19), five per distro, with **thirteen textbook implants
seeded across the five "compromised" hosts** — one per module
covered by v0.1.0. Each implant maps to a different offensive
pattern: orphan-in-tmp cron / ssh / sshd / pam / ldso / systemd
unit / udev rule, NOPASSWD sudoers, uid-0 passwd backdoor,
curl-bash in `.bashrc`, modprobe `install` directive, curl-bash
in `update-motd.d`, init.d script pointing at `/tmp`.

The full set of thirteen implants surfaces in Q7 (cross-cutting
roll-call) of `tools/stack_demo.sql` with zero false positives.
Q4 (orphan + tmp fingerprint) alone catches seven of them; the
remaining six need their module-specific signals or content
patterns. The fleet-scale validation setup is local development
infrastructure and is not shipped with the project — running
`linpersist-report` against your own NDJSON collection is the
reproducible validation any operator can run.

## Documentation

- [`docs/schema-v1.md`](./docs/schema-v1.md) — canonical NDJSON record
  shape. Every field, every type, every guarantee.
- [`docs/normalization-rules.md`](./docs/normalization-rules.md) — the
  invariants every module's `Normalize` honors. Stacking only works
  because normalization works.
- [`docs/stacking-cookbook.md`](./docs/stacking-cookbook.md) — six
  canonical DuckDB queries with prose walkthrough and false-positive
  guide.
- [`docs/report.md`](./docs/report.md) — anatomy of the HTML report
  produced by `linpersist-report`.
- [`docs/modules/`](./docs/modules) — per-module reference (loci,
  signals, false-positive patterns). Only `systemd.md` is populated
  today; the rest is paid down as queries surface gaps.
- [`docs/adr/`](./docs/adr) — seven Architecture Decision Records
  pinning the binding design choices (granularity per site_class,
  hostname policy, password-hash policy, systemd canonical form, ...).
- [`tools/stack_demo.sql`](./tools/stack_demo.sql) — the six cookbook
  queries in executable form, separated by `--- query separator ---`.
- [`tools/ingest.sh`](./tools/ingest.sh) — thin DuckDB-CLI wrapper:
  NDJSON → DuckDB → optional Parquet export → optional `.sql` exec.

## Roadmap

- **v0.2.0** — Provenance (dpkg + rpm orphan checks wired into
  `exec_target_pkg_status` / `non_package_path` signal). Per-module
  reference docs for the remaining 12 modules. Integration tests in CI
  across the 5 lab distros. Optional `--tag key=value` CLI flag (already
  contracted in ADR-0006).
- **v0.3.0** — eBPF state inspection (read-only). Container-aware
  site_classes (`docker.daemon`, `k8s.static-pods`, `cloud-init`).
  XDG autostart (`T1547.013`).
- **v0.4.0** — Supply-chain site_classes (`npm.global`, `pip.user`,
  `ai-cli.configs`).
- **v0.5.0** — Optional YARA plugin as a separate binary (does not
  contaminate the read-only no-CGO core).

`matrix.yaml` tracks the canonical status; PRs that move a planned
site_class to `wip` / `implemented` are welcome.

## License

Apache-2.0. See [LICENSE](./LICENSE).

Copyright (c) 2026 Jarmi (jarmidaw).
