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

# 3b. Drill into a suspect host (Q4 / Q7 flagged it? get its dossier).
./dist/linpersist-report-linux-amd64 -i fleet/ --host host-1 -o host-1.html
```

Open `report.html` for the fleet view; open `host-1.html` for the
single-host dossier. Done.

---

## The binaries

| Binary                | Role                              | Where it runs                              | Default output                   |
| --------------------- | --------------------------------- | ------------------------------------------ | -------------------------------- |
| `linpersist`          | Agent                             | One per host across your fleet             | NDJSON to stdout (or `--output`) |
| `linpersist-report`   | Fleet renderer + per-host dossier | One central host with the fleet's NDJSON   | Self-contained HTML (or text)    |
| `detgen`              | Build-time SQL regenerator        | Maintainer's machine (release gate)        | Rewrites Q7 block of `stack_demo.sql` |

`linpersist` and `linpersist-report` ship to operators; `detgen` is a
maintainer tool that keeps `tools/stack_demo.sql` in sync with
`internal/detections/detections.yaml` (see [ADR-0013](docs/adr/0013-detections-yaml.md)).
All three are built from the same source tree by `make build-all` and
are static single binaries (10–12 MB) with **zero runtime
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

The fastest way to triage. One binary, two modes — fleet-wide report
or per-host dossier — both producing one self-contained HTML page or
column-aligned text for SSH-only jump hosts.

```sh
# Fleet HTML (default) -- shareable, sortable, filterable, dark/light theme.
./dist/linpersist-report-linux-amd64 -i fleet/ -o report.html

# Fleet text with ANSI colour, paged through less.
./dist/linpersist-report-linux-amd64 -i fleet/ -format text | less -R

# Fleet text, plain ASCII for ticket attachments.
./dist/linpersist-report-linux-amd64 -i fleet/ -format text -color=off > triage.txt

# Per-host dossier -- drills into one host that Q4/Q7 flagged.
./dist/linpersist-report-linux-amd64 -i fleet/ --host r-db-amzn-03 -o r-db-amzn-03.html

# Per-host text dossier on a jump box.
./dist/linpersist-report-linux-amd64 -i fleet/ --host r-db-amzn-03 -format text | less -R

# Batch dossiers for every suspect host from a shell loop.
for h in $(cat suspects.txt); do
  ./dist/linpersist-report-linux-amd64 -i fleet/ --host "$h" -o "out/$h.html"
done
```

**Fleet mode** runs all 11 expert queries (Q1–Q11) and adds an
overview: per-module / per-site_class / per-`os_id` counts, LFA
stacking histogram (singletons highlighted), signal distribution bar
chart. The HTML is ~200 KB regardless of fleet size — Q1, Q4, Q7, Q11
are LFA-filtered to anomalous rows, so 25 hosts and 25 000 hosts
produce reports in the same size envelope.

**Dossier mode** (`--host <id>`) produces a single-host artefact
~20 KB scaled to records-of-that-host. Sections in order: host
header (hostname, host_id, os, kernel, agent_version), summary
counts, a **signal panel sorted by fleet rarity ascending** (the
host's rarest fleet-wide signal at the top), then the per-host
slices of Q4 / Q7 / Q1 / Q2 / Q9 / Q11 / Q8, and a **module-coverage
gap detector** that flags modules the host emitted zero records for
when the fleet median is non-zero (silent agent failure / container
image gap). Q3 / Q5 / Q6 / Q10 are intentionally omitted — they are
fleet aggregates with no per-host insight. See
[ADR-0012](docs/adr/0012-host-dossier.md) for the layout rationale and
[`docs/report.md`](docs/report.md) for the anatomy of every section.

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

The 11 canonical threat-hunting queries are maintained in **two
implementations kept in sync by tooling, not by hand**:

| Form | Source file                                                              | Runner                                                |
| ---- | ------------------------------------------------------------------------ | ----------------------------------------------------- |
| SQL  | [`tools/stack_demo.sql`](tools/stack_demo.sql)                           | DuckDB · [`tools/ingest.sh`](tools/ingest.sh)         |
| Go   | [`cmd/linpersist-report/stats.go`](cmd/linpersist-report/stats.go)       | `linpersist-report` binary                            |

You pick which to run based on context; the conclusions are identical.
The Go form requires nothing but the binary; the SQL form requires a
local `duckdb` CLI (single static binary too) and scales further.

Q7 ("Implant roll-call") is special: its clauses are externalised as
**declarative YAML** in
[`internal/detections/detections.yaml`](internal/detections/detections.yaml).
`cmd/linpersist-report` embeds the YAML at build time; `cmd/detgen`
regenerates the SQL block from the same file. `make detgen-verify` is
a release gate that fails the build if the committed SQL has drifted
from the YAML — adding a new detection clause is a one-place edit,
not a two-place sync. See [ADR-0013](docs/adr/0013-detections-yaml.md).

### What the 11 queries analyze

| ID  | Name                              | What it surfaces                                                                                                                                              |
| --- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Q1  | LFA singletons                    | Records whose `content_norm_sha256` appears on exactly one host. The load-bearing query — implants by definition live in the long tail.                       |
| Q2  | Per-locus singletons              | Like Q1 but groups by `(module, site_class, locus, content_norm_sha256)`. Catches legitimate content copied into an unusual path.                             |
| Q3  | Peer-group by `os_id`             | Singletons inside their own OS bucket. Necessary for mixed fleets where Debian-only baselines would otherwise look like singletons in an Ubuntu majority.     |
| Q4  | Implant fingerprint               | Records carrying **both** `exec_target_orphan` and `interpreter_in_tmp`. Highest-precision tag team.                                                          |
| Q5  | Signal distribution by module     | Per `(module, signal)`: hosts that fire it and records carrying it. Sort ASC to surface rare signals first — those earn the analyst's triage time.            |
| Q6  | Worm pattern (`exec_target`)      | Same `exec_target_sha256` across different hosts with different persistence text. Identical payload, polymorphic persistence — the lateral-movement signal.   |
| Q7  | Implant roll-call                 | Cross-cutting union of disjoint clauses loaded from [`detections.yaml`](internal/detections/detections.yaml). Each row carries the **detection id that fired** (`matched_detections` column) so triage maps directly to a named rule. |
| Q8  | Recent-mtime concentration        | Per `(host, module)` with ≥ 5 records carrying `recent_mtime_7d`. Spikes mean config-management push or post-compromise sweep.                                 |
| Q9  | Exec in tmp-class directories     | `exec_target` under `/tmp/`, `/var/tmp/`, `/dev/shm/`, `/run/shm/` regardless of orphan state. Q9 minus Q4 = "armed implants currently on disk".              |
| Q10 | Per-host coverage health          | Per host: records, distinct modules, distinct site_classes, recent records. Run this **first** on any new dataset to catch silent agent failures.             |
| Q11 | Orphan exec_target outside `/tmp` | Payloads dropped under `/opt/`, `/var/lib/`, `/srv/`, `/usr/local/` and similar long-lived but unmanaged paths. The implant family Q4 and Q9 miss entirely — caught by `non_package_path` from the v0.2.0 dpkg/rpm provenance resolver. |

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

## Coverage (v0.2.0)

**18 modules · 29 site_classes · MITRE-mapped end-to-end.** Every
module emits the same record shape; what varies is the canonical-form
rule for that site_class family.

| Module         | Covers                                                                                  | MITRE                       |
| -------------- | --------------------------------------------------------------------------------------- | --------------------------- |
| `cron`         | `cron.d`, `cron.user`, `cron.periodic`, `cron.anacron`                                  | T1053.003                   |
| `atjobs`       | `at.jobs` (atd spool with atd-prepended header stripped from canonical form)            | T1053.001                   |
| `systemd`      | `systemd.unit`, `systemd.timer` (incl. drop-ins, Match-block scoping, user units)       | T1543.002, T1053.006        |
| `sysv`         | `sysv.init` (incl. RHEL `/etc/rc.d/`, `rc.local`, external `rc?.d` symlinks)            | T1037.004                   |
| `ssh`          | `ssh.authkeys` (system + per-user; public-key blob never emitted raw)                   | T1098.004                   |
| `sshd`         | `sshd.config` (incl. drop-ins, Match blocks)                                            | T1098.004, T1556            |
| `sudoers`      | `sudoers` (incl. `sudoers.d/*`, NOPASSWD + ALL flags)                                   | T1548.003                   |
| `passwd`       | `passwd.user`, `passwd.shadow`, `passwd.group`, `passwd.gshadow` (hashes never emitted) | T1136.001                   |
| `pam`          | `pam` (`/etc/pam.d/*` + legacy `/etc/pam.conf`)                                         | T1556.003                   |
| `polkit`       | `polkit.rules` (JS rules; `addAdminRule(` / `polkit.Result.YES` token signals)          | T1548                       |
| `profile`      | `profile.system`, `profile.user` (Bash + Zsh init)                                      | T1546.004                   |
| `ldso`         | `ldso.preload`, `ldso.conf`, `ldso.confd`                                               | T1574.006                   |
| `kmod`         | `kmod` (modules-load.d + modprobe.d directives; `install` directive flagged)            | T1547.006                   |
| `udev`         | `udev` (per-rule, with `RUN+=` exec_target extraction)                                  | T1546                       |
| `motd`         | `motd` (`/etc/motd*`, `/etc/update-motd.d/*`)                                           | T1037                       |
| `netdispatch`  | `network.dispatchers` (NetworkManager, dhclient, dhcpcd, ifupdown hooks)                | T1546                       |
| `grub`         | `kernel.grub.config`, `kernel.grub.dropin` (`init=` cmdline override flagged)           | T1542.003                   |
| `xdg`          | `xdg.autostart` (FreeDesktop `.desktop` files; system + per-user)                       | T1547.013                   |

See [`matrix.yaml`](matrix.yaml) for the authoritative per-site_class
status, loci, and notes. `make audit` (the
[ADR-0001](docs/adr/0001-module-interface.md) release gate) fails if
the matrix and the registered modules drift apart.

Every signal the agent is allowed to emit is declared in a
[canonical catalog](internal/core/signals_catalog.go) cross-checked
by buildtime tests against the actual emission sites — see
[ADR-0011](docs/adr/0011-signals-catalog.md).

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
make build-all       # cross-compile linux/{amd64,arm64,386,arm-v7}
make verify          # ldd + file confirm static; runs against amd64
make test            # go test ./...
make test-race       # go test -race ./...
make lint            # go vet + gofmt
make audit           # matrix.yaml ↔ registered modules consistency check (ADR-0001)
make detgen          # regenerate Q7 SQL block from detections.yaml
make detgen-verify   # release gate: detections.yaml ↔ stack_demo.sql drift check (ADR-0013)
make all             # lint + test + audit + detgen-verify + build
```

Two release gates fail the build on drift:

- **`make audit`** — `matrix.yaml` vs the modules the code actually
  registers ([ADR-0001](docs/adr/0001-module-interface.md)).
- **`make detgen-verify`** — `detections.yaml` vs the Q7 block in
  `tools/stack_demo.sql` ([ADR-0013](docs/adr/0013-detections-yaml.md)).

Adding a module without listing it in `matrix.yaml`, or editing
`detections.yaml` without regenerating the SQL, breaks `make all`.

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
inputs, robustness contracts. The `internal/core` package adds buildtime
audits cross-checking the signals catalog against every emission site
(see [ADR-0011](docs/adr/0011-signals-catalog.md)). The
`internal/detections` package golden-tests every clause in
`detections.yaml` plus 10 loader rejection paths.

Two release gates fail the build on drift: `make audit`
(`matrix.yaml` ↔ modules, [ADR-0001](docs/adr/0001-module-interface.md))
and `make detgen-verify` (`detections.yaml` ↔ SQL,
[ADR-0013](docs/adr/0013-detections-yaml.md)).

End-to-end validation runs against `lab-realistic`: a synthetic fleet
of **75 Docker containers** across five distros (Debian 11, RHEL 8,
Ubuntu 22.04, Amazon Linux 2 & 2023, Alpine 3.19), with documented
textbook implants seeded across the "compromised" hosts. Current
numbers: **31 433 records, 22 Q1 singletons, 6 Q4 implant hits,
22 Q7 roll-call rows, 42 Q8 mtime spikes, 6 Q11 orphan-outside-tmp
hits** — every Q7 row maps to a named detection in `detections.yaml`
via the `matched_detections` column.

The fleet-scale validation setup is local development infrastructure
and is not shipped with the project. Running `linpersist-report`
against your own NDJSON collection is the reproducible validation any
operator can run.

---

## Why this and not osquery / Velociraptor / UAC

|                              | `linpersist`                                          | osquery                          | Velociraptor                | UAC                          |
| ---------------------------- | ----------------------------------------------------- | -------------------------------- | --------------------------- | ---------------------------- |
| Shape                        | persistence-only collector + report binary            | general telemetry agent          | DFIR agent + server         | live-response collector      |
| Output                       | NDJSON, one record per artifact                       | SQL tables, per-query            | VQL artifacts               | tar.gz of raw files          |
| Optimized for                | fleet-scale LFA + per-host drill-down on demand       | host-level real-time queries     | incident response           | single-host triage           |
| Footprint                    | one static 10 MB binary, no daemon                    | 50+ MB, daemon                   | server + clients            | thousands of shell helpers   |
| Decisions on the host        | none (zero classification)                            | thresholds + scheduled packs     | rule-based                  | none                         |
| Detection rules              | declarative YAML, generator-synced with SQL backend   | SQL packs                        | VQL                         | n/a                          |

`linpersist` is intentionally a small piece of the pipeline. It
produces the highest-quality input for stacking that the agent stage
can produce — deterministic canonical hashes, explicit MITRE IDs, no
runtime state — and stops there.

---

## Documentation map

| Doc                                                                                                | What it covers                                                       |
| -------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| [`docs/schema-v1.md`](docs/schema-v1.md)                                                           | Canonical NDJSON record shape: every field, every guarantee          |
| [`docs/normalization-rules.md`](docs/normalization-rules.md)                                       | Invariants every `Normalize` honors                                  |
| [`docs/stacking-cookbook.md`](docs/stacking-cookbook.md)                                           | The cookbook queries as prose, with false-positive notes             |
| [`docs/report.md`](docs/report.md)                                                                 | Anatomy of the HTML / text fleet report and `--host` dossier         |
| [`docs/modules/`](docs/modules)                                                                    | Per-module reference (paid down as gaps surface)                     |
| [`docs/adr/`](docs/adr)                                                                            | Thirteen Architecture Decision Records (ADR-0001..0013)              |
| [`matrix.yaml`](matrix.yaml)                                                                       | MITRE × site_class taxonomy; release-gated by `make audit`           |
| [`internal/detections/detections.yaml`](internal/detections/detections.yaml)                       | Q7 detection clauses; release-gated by `make detgen-verify`          |
| [`internal/core/signals_catalog.go`](internal/core/signals_catalog.go)                             | Canonical signals catalog with `EmittedBy` per module                |
| [`tools/stack_demo.sql`](tools/stack_demo.sql)                                                     | The 11 queries in executable DuckDB form (Q7 generated from YAML)    |
| [`tools/ingest.sh`](tools/ingest.sh)                                                               | NDJSON → DuckDB loader · optional Parquet · custom SQL               |

Highlighted ADRs added in this iteration:

- [ADR-0011](docs/adr/0011-signals-catalog.md) — iterable signals
  catalog as a buildtime invariant.
- [ADR-0012](docs/adr/0012-host-dossier.md) — `linpersist-report --host`
  as a separate single-host mode.
- [ADR-0013](docs/adr/0013-detections-yaml.md) — `detections.yaml` as
  single source of truth for Q7 clauses (Go + SQL).

---

## Roadmap

- ✅ **v0.2.0** (released) — dpkg + rpm provenance wired into
  `exec_target_pkg_status` / `non_package_path`. `/proc` live-process
  correlation. Five new modules (atjobs, polkit, netdispatch, grub,
  xdg). Validation against the 75-host lab-realistic fleet.
- ✅ **v0.2.x polish** (in `[Unreleased]`) — per-host dossier mode
  (`--host`, [ADR-0012](docs/adr/0012-host-dossier.md)), iterable
  signals catalog ([ADR-0011](docs/adr/0011-signals-catalog.md)),
  declarative Q7 via `detections.yaml`
  ([ADR-0013](docs/adr/0013-detections-yaml.md)),
  `matched_detections` column in Q7 output.
- **v0.3.0** — eBPF state inspection (read-only). Container-aware
  site_classes (`docker.daemon`, `k8s.static-pods`, `cloud-init`).
  Per-module reference docs for the remaining modules. Integration
  tests in CI across the lab distros.
- **v0.4.0** — Supply-chain site_classes (`npm.global`, `pip.user`,
  `ai-cli.configs`). Optional Markdown emitter for the report
  ([ADR-0008](docs/adr/0008-report-dual-rendering.md) extension hook).
- **v0.5.0** — Optional YARA plugin as a separate binary (does not
  contaminate the read-only no-CGO core).

`matrix.yaml` tracks the canonical status; PRs that move a planned
site_class to `wip` / `implemented` are welcome. New Q7 detection
rules are now a one-file edit in
[`internal/detections/detections.yaml`](internal/detections/detections.yaml)
plus `make detgen` to regenerate the SQL.

---

## License

Apache-2.0. See [LICENSE](LICENSE).

Copyright (c) 2026 Jarmi (jarmidaw).
