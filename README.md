# linpersist

> Read-only Linux persistence-artifact collector. Single static binary,
> NDJSON output, designed to run on thousands of hosts and feed a
> frequency-stacking backend.

![End-to-end pipeline](docs/img/pipeline.svg)

`linpersist` walks every well-known Linux persistence site (cron,
systemd, ssh, sudoers, pam, ld.so.preload, modprobe.d, udev rules, and
ten more), normalizes each artifact to a canonical form, and emits one
NDJSON record per artifact. **The agent does not classify anything as
malicious** — it collects, the backend decides. Every record carries a
`content_norm_sha256` digest so that semantically-identical artifacts
across hosts collapse to the same hash and malicious singletons surface
in the long tail of the histogram (Least Frequency Analysis).

---

## 60-second quickstart

Three commands. Zero to a triage page.

```sh
# 1. Build both binaries (static, no CGO).
make build-all

# 2. Run the agent on each host -- NDJSON to stdout.
mkdir -p fleet/
ssh host-1 './linpersist' > fleet/host-1.ndjson
ssh host-2 './linpersist' > fleet/host-2.ndjson
# ... or cron-driven; one file per host

# 3. Aggregate and report.
./dist/linpersist-report-linux-amd64 -i fleet/ -o report.html
```

Open `report.html`. Done.

---

## The two binaries

| Binary                | Role     | Where it runs                              | Default output                   |
| --------------------- | -------- | ------------------------------------------ | -------------------------------- |
| `linpersist`          | Agent    | One per host across your fleet             | NDJSON to stdout (or `--output`) |
| `linpersist-report`   | Renderer | One central host with the fleet's NDJSON   | Self-contained HTML (or text)    |

Both are built from the same source tree by `make build-all`. Both are
static single binaries (10–12 MB). Both have **zero runtime
dependencies** — no Python, no DuckDB, no daemon, no shared libraries
(`ldd` reports *not a dynamic executable*).

Common agent invocations:

```sh
linpersist                            # NDJSON to stdout
linpersist --output /tmp/host.ndjson  # write to file (the only path written)
linpersist --include-hostname         # opt-in plaintext hostname
linpersist --module-timeout 60s       # per-module deadline (default 30s)
linpersist --version
```

The agent makes **zero network calls** and **zero state changes** to
the host. Budget ~500 KB–2 MB of NDJSON per host depending on how many
unit files / modprobe directives / etc. exist on it.

---

## Analyzing your NDJSON

Two paths. Pick by fleet size.

### Path A · `linpersist-report` (recommended for fleets ≲ 10k hosts)

The fastest way to triage. One binary, one command, one self-contained
HTML page — or column-aligned text for SSH-only jump hosts.

```sh
# HTML (default) -- shareable, sortable, filterable, dark/light theme.
./dist/linpersist-report-linux-amd64 -i fleet/ -o report.html

# Text, with ANSI colour, paged through less.
./dist/linpersist-report-linux-amd64 -i fleet/ -format text | less -R

# Text, plain ASCII for ticket attachments.
./dist/linpersist-report-linux-amd64 -i fleet/ -format text -color=off > triage.txt
```

The report runs **all 10 expert queries** (described below) and adds a
fleet overview: per-module / per-site_class / per-`os_id` counts, LFA
stacking histogram (singletons highlighted), signal distribution bar
chart. Each table is sortable by header click and filterable via a live
search input in HTML mode; column-aligned via `text/tabwriter` in text
mode. See [`docs/report.md`](docs/report.md) for the anatomy of every
section.

### Path B · DuckDB cookbook (power users · large fleets)

```sh
# Default: run the 10 cookbook queries from tools/stack_demo.sql.
./tools/ingest.sh fleet/

# Bring your own queries.
./tools/ingest.sh -q my-hunting-queries.sql fleet/

# Load-only (no SQL pass), produce a Parquet export for repeat analysis.
./tools/ingest.sh -q '' -o fleet.parquet fleet/

# Persist a DuckDB file an analyst can attach interactively.
./tools/ingest.sh -d fleet.duckdb fleet/
duckdb fleet.duckdb -c "SELECT module, count(*) FROM r GROUP BY 1;"
```

Columnar processing scales past the ~10k-host envelope where the Go
report starts taking minutes. Same 10 queries, same conclusions; DuckDB
just chews larger fleets faster.

---

## Where the queries live

![Query architecture](docs/img/queries.svg)

The 10 canonical threat-hunting queries are maintained in **two
implementations kept in sync row-for-row**:

| Form | Source file                                                              | Runner                                                |
| ---- | ------------------------------------------------------------------------ | ----------------------------------------------------- |
| SQL  | [`tools/stack_demo.sql`](tools/stack_demo.sql)                           | DuckDB · [`tools/ingest.sh`](tools/ingest.sh)         |
| Go   | [`cmd/linpersist-report/stats.go`](cmd/linpersist-report/stats.go)       | `linpersist-report` binary                            |

You pick which to run based on context; the conclusions are identical.
The Go form requires nothing but the binary; the SQL form requires a
local `duckdb` CLI (single static binary too) and scales further.

### What the 10 queries analyze

| ID  | Name                              | What it surfaces                                                                                                                                              |
| --- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Q1  | LFA singletons                    | Records whose `content_norm_sha256` appears on exactly one host. The load-bearing query — implants by definition live in the long tail.                       |
| Q2  | Per-locus singletons              | Like Q1 but groups by `(module, site_class, locus, content_norm_sha256)`. Catches legitimate content copied into an unusual path.                             |
| Q3  | Peer-group by `os_id`             | Singletons inside their own OS bucket. Necessary for mixed fleets where Debian-only baselines would otherwise look like singletons in an Ubuntu majority.     |
| Q4  | Implant fingerprint               | Records carrying **both** `exec_target_orphan` and `interpreter_in_tmp`. Highest-precision tag team.                                                          |
| Q5  | Signal distribution by module     | Per `(module, signal)`: hosts that fire it and records carrying it. Sort ASC to surface rare signals first — those earn the analyst's triage time.            |
| Q6  | Worm pattern (`exec_target`)      | Same `exec_target_sha256` across different hosts with different persistence text. Identical payload, polymorphic persistence — the lateral-movement signal.   |
| Q7  | Implant roll-call                 | Cross-cutting union of 7 disjoint clauses. The "one query to find them all" — validated against 13 documented implants with **zero false positives**.         |
| Q8  | Recent-mtime concentration        | Per `(host, module)` with ≥ 5 records carrying `recent_mtime_7d`. Spikes mean config-management push or post-compromise sweep.                                 |
| Q9  | Exec in tmp-class directories     | `exec_target` under `/tmp/`, `/var/tmp/`, `/dev/shm/`, `/run/shm/` regardless of orphan state. Q9 minus Q4 = "armed implants currently on disk".              |
| Q10 | Per-host coverage health          | Per host: records, distinct modules, distinct site_classes, recent records. Run this **first** on any new dataset to catch silent agent failures.             |

Full prose walkthrough with false-positive guidance and recommended
triage order: [`docs/stacking-cookbook.md`](docs/stacking-cookbook.md).

### Bringing your own queries

The NDJSON schema is stable (v1, see
[`docs/schema-v1.md`](docs/schema-v1.md)), so you can write any SQL
against it. The recommended pattern:

```sh
cat > my-pack.sql <<'SQL'
-- Q-custom-1: every passwd record with a non-root uid 0.
SELECT host_id, locus, content_snippet
FROM r
WHERE site_class = 'passwd.user'
  AND list_contains(signals, 'passwd_uid_zero');

--- query separator ---

-- Q-custom-2: NOPASSWD sudoers that aren't from %wheel / %sudo.
SELECT host_id, locus, content_snippet
FROM r
WHERE module = 'sudoers'
  AND list_contains(signals, 'sudoers_nopasswd')
  AND content_snippet NOT LIKE '%wheel%'
  AND content_snippet NOT LIKE '%sudo%';
SQL

./tools/ingest.sh -q my-pack.sql fleet/
```

The runner loads the NDJSON once, then executes each `--- query separator ---`-delimited
block and prints the rows. Use this for ad-hoc hunting between cookbook
runs.

Extending the Go-native runner means adding a `computeQ*` function to
[`stats.go`](cmd/linpersist-report/stats.go) and a section to
[`report.tmpl`](cmd/linpersist-report/report.tmpl) — a heavier lift but
needed only if you want the new query to ship inside the binary.

---

## Coverage (v0.1.0-alpha)

**13 modules · 23 site_classes · 14 MITRE ATT&CK techniques.** Every
module emits the same record shape; what varies is the canonical-form
rule for that site_class family.

| Module    | Covers                                                                                  | MITRE                       |
| --------- | --------------------------------------------------------------------------------------- | --------------------------- |
| `cron`    | `cron.d`, `cron.user`, `cron.periodic`, `cron.anacron`                                  | T1053.003                   |
| `systemd` | `systemd.unit`, `systemd.timer` (incl. drop-ins, Match-block scoping, user units)        | T1543.002, T1053.006        |
| `sysv`    | `sysv.init` (incl. RHEL `/etc/rc.d/`, `rc.local`, external `rc?.d` symlinks)            | T1037.004                   |
| `ssh`     | `ssh.authkeys` (system + per-user; public-key blob never emitted raw)                    | T1098.004                   |
| `sshd`    | `sshd.config` (incl. drop-ins, Match blocks)                                            | T1098.004, T1556            |
| `sudoers` | `sudoers` (incl. `sudoers.d/*`, NOPASSWD + ALL flags)                                   | T1548.003                   |
| `passwd`  | `passwd.user`, `passwd.shadow`, `passwd.group`, `passwd.gshadow` (hashes never emitted)  | T1136.001                   |
| `pam`     | `pam` (`/etc/pam.d/*` + legacy `/etc/pam.conf`)                                         | T1556.003                   |
| `profile` | `profile.system`, `profile.user` (Bash + Zsh init)                                      | T1546.004                   |
| `ldso`    | `ldso.preload`, `ldso.conf`, `ldso.confd`                                               | T1574.006                   |
| `kmod`    | `kmod` (modules-load.d + modprobe.d directives)                                          | T1547.006                   |
| `udev`    | `udev` (per-rule, with `RUN+=` exec_target extraction)                                  | T1546                       |
| `motd`    | `motd` (`/etc/motd*`, `/etc/update-motd.d/*`)                                            | T1037                       |

See [`matrix.yaml`](matrix.yaml) for the authoritative per-site_class
status, loci, and notes.

---

## A sample record

```json
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
columnar backend (DuckDB, ClickHouse, Athena, BigQuery). The two
load-bearing fields for stacking are `content_norm_sha256` (semantic
content hash; the LFA grouping key) and `signals[]` (cheap heuristics
the agent observed without making a verdict).

---

## Design tenets

- **Single static binary per architecture.** `CGO_ENABLED=0`, build tags
  `osusergo netgo`. Verified by `ldd` and `file` in CI.
- **Read-only on the host.** The agent's only writable path is the file
  given by `--output`; absent that flag, output goes to stdout.
- **Modular by site_class.** One module per family. Adding coverage =
  adding a module, never touching `internal/core`.
- **Deterministic normalization.** Each module's `content_norm_sha256`
  is computed over a canonical form so that semantically-equivalent
  inputs collapse to the same hash for stacking.
- **MITRE ATT&CK explicit.** Every record carries the precise
  sub-technique IDs (e.g. `T1053.003`, not just `T1053`).
- **Schema versioned.** `schema_v: 1` is frozen for the v0.1.x line.
- **The agent collects; the backend decides.** No allowlists, no
  signatures, no scoring inside the binary.

---

## Build, lint, test

```sh
make build-all   # cross-compile linux/{amd64,arm64,386,arm-v7}
make verify      # ldd + file confirm static; runs against amd64
make test        # go test -race ./...
make lint        # go vet + gofmt
make audit       # matrix.yaml ↔ registered modules consistency check
```

The audit gate fails the build if `matrix.yaml` and the registered
modules drift apart — adding a module without listing it in
`matrix.yaml`, or vice versa, breaks `make all`.

---

## Privacy

Two fields are deliberately conservative by default:

- **`host_meta.hostname`** is omitted from output. `--include-hostname`
  opts in to plaintext; without it only `host_meta.hostname_hash`
  ships. See [ADR-0006](docs/adr/0006-hostname-policy.md).
- **SSH public-key blobs** (`/root/.ssh/authorized_keys` and friends)
  and **`/etc/shadow` / `/etc/gshadow` password hashes** are never
  emitted raw. Only digests and a `password_status` enum (`set` /
  `locked` / `disabled` / `empty` / `unknown`). See
  [ADR-0003](docs/adr/0003-ssh-key-blob-handling.md) and
  [ADR-0005](docs/adr/0005-password-hash-never-emitted.md).

---

## Validation

Every module ships with golden fixture tests under
`internal/testdata/golden/<module>/` exercised by
`go test ./internal/modules/...` — happy paths, edge cases, malformed
inputs, robustness contracts. Plus a `matrix-audit` release gate
(`make audit`) that fails the build if `matrix.yaml` and the registered
modules drift apart.

Beyond the unit envelope, v0.1.0-alpha was validated end-to-end against
a synthetic fleet of 25 Docker containers across five distros (Debian
11, RHEL 8, Ubuntu 22.04, Amazon Linux 2023, Alpine 3.19), with 13
textbook implants seeded across the five "compromised" hosts. The full
set surfaces in Q7 (the cross-cutting roll-call) with zero false
positives. Q4 alone catches seven; the remaining six need their
module-specific signals or content patterns — which is why Q7 exists.

The fleet-scale validation setup is local development infrastructure
and is not shipped with the project. Running `linpersist-report`
against your own NDJSON collection is the reproducible validation any
operator can run.

---

## Why this and not osquery / Velociraptor / UAC

|                              | `linpersist`                                  | osquery                          | Velociraptor                | UAC                          |
| ---------------------------- | --------------------------------------------- | -------------------------------- | --------------------------- | ---------------------------- |
| Shape                        | persistence-only collector                    | general telemetry agent          | DFIR agent + server         | live-response collector      |
| Output                       | NDJSON, one record per artifact               | SQL tables, per-query            | VQL artifacts               | tar.gz of raw files          |
| Optimized for                | fleet-scale LFA across thousands of hosts     | host-level real-time queries     | incident response           | single-host triage           |
| Footprint                    | one static 10 MB binary, no daemon            | 50+ MB, daemon                   | server + clients            | thousands of shell helpers   |
| Decisions on the host        | none (zero classification)                    | thresholds + scheduled packs     | rule-based                  | none                         |

`linpersist` is intentionally a small piece of the pipeline. It
produces the highest-quality input for stacking that the agent stage
can produce — deterministic canonical hashes, explicit MITRE IDs, no
runtime state — and stops there.

---

## Documentation map

| Doc                                                                                  | What it covers                                              |
| ------------------------------------------------------------------------------------ | ----------------------------------------------------------- |
| [`docs/schema-v1.md`](docs/schema-v1.md)                                             | Canonical NDJSON record shape: every field, every guarantee |
| [`docs/normalization-rules.md`](docs/normalization-rules.md)                         | Invariants every `Normalize` honors                         |
| [`docs/stacking-cookbook.md`](docs/stacking-cookbook.md)                             | The 10 cookbook queries as prose, with false-positive notes |
| [`docs/report.md`](docs/report.md)                                                   | Anatomy of the HTML / text report                           |
| [`docs/modules/`](docs/modules)                                                      | Per-module reference (paid down as gaps surface)            |
| [`docs/adr/`](docs/adr)                                                              | Eight Architecture Decision Records                         |
| [`tools/stack_demo.sql`](tools/stack_demo.sql)                                       | The 10 queries in executable DuckDB form                    |
| [`tools/ingest.sh`](tools/ingest.sh)                                                 | NDJSON → DuckDB loader · optional Parquet · custom SQL      |

---

## Roadmap

- **v0.2.0** — Provenance (dpkg + rpm orphan checks wired into
  `exec_target_pkg_status` / `non_package_path` signals). Per-module
  reference docs for the remaining 12 modules. Integration tests in CI
  across the 5 lab distros. Optional `--tag key=value` CLI flag.
- **v0.3.0** — eBPF state inspection (read-only). Container-aware
  site_classes (`docker.daemon`, `k8s.static-pods`, `cloud-init`).
  XDG autostart (`T1547.013`).
- **v0.4.0** — Supply-chain site_classes (`npm.global`, `pip.user`,
  `ai-cli.configs`).
- **v0.5.0** — Optional YARA plugin as a separate binary (does not
  contaminate the read-only no-CGO core).

`matrix.yaml` tracks the canonical status; PRs that move a planned
site_class to `wip` / `implemented` are welcome.

---

## License

Apache-2.0. See [LICENSE](LICENSE).

Copyright (c) 2026 Jarmi (jarmidaw).
