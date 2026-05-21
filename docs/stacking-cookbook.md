# Stacking cookbook

`linpersist` collects every persistence artifact it finds on a host
into NDJSON and walks away. The agent does not decide whether anything
is malicious. That decision lives downstream, in a database that has
seen the same artifacts on every other host in the fleet. The
technique is frequency stacking, also known as Least Frequency
Analysis (LFA). This cookbook explains the model, walks through the
eleven canonical queries shipped in `tools/stack_demo.sql`, and
lists the false-positive patterns that the analyst learns to filter
out. The eleven queries are a curated, non-redundant expert set: each adds
a distinct analytical angle. Per-module variants (e.g. "cron LFA")
are NOT separate queries — the analyst adds a `WHERE module = 'cron'`
filter to Q1.

## The model: why frequency stacking surfaces malware

Real Linux fleets are surprisingly homogeneous in their persistence
configuration. Two Ubuntu 22.04 hosts running the same workload share
identical bytes in `/etc/cron.d/`, `/etc/pam.d/`, `/etc/sudoers.d/`,
`/etc/ld.so.conf.d/`, and most of `/etc/profile.d/`. Distros ship
those files in packages; package managers stamp them onto every host
they touch.

That homogeneity is the property LFA exploits. If you compute the
`content_norm_sha256` of every persistence-relevant record from every
host in the fleet and count how many distinct hosts produce each
digest, the histogram has a long left tail: a handful of digests
appear on thousands of hosts (the legitimate baseline), and the rest
appear on one host each. The interesting records live in that long
tail.

The agent's job is to make the digest stable. Two hosts with the same
crontab entry separated by a trailing tab, a CRLF line ending, or a
stale comment three lines up MUST produce the same
`content_norm_sha256`. That is what the per-module `Normalize`
functions exist for. See `docs/normalization-rules.md` for the shared
invariants, and the per-module `docs/modules/<name>.md` files for the
specifics.

The backend's job is to count. The five queries in
`tools/stack_demo.sql` are the canonical counting strategies.

## Dataset shape

Load the NDJSON into DuckDB:

```sql
CREATE TABLE r AS
  SELECT * FROM read_ndjson_auto(
    'collected/*.ndjson',
    ignore_errors = true
  );
```

`read_ndjson_auto` infers the column types from the records it sees.
Nested fields (`host_meta.os_id`, `host_meta.hostname_hash`, etc.) are
addressable with dotted-path syntax. `signals` lands as a `VARCHAR[]`
array; use `list_contains(signals, 'name')` to filter by membership.

`ignore_errors = true` is recommended because some records may carry
`errors[]` entries with partial data; DuckDB still ingests them, but
the column count for those rows differs from the canonical shape.

For a Parquet pipeline (better at fleet scale), pivot once:

```sql
COPY (SELECT * FROM r) TO 'r.parquet' (FORMAT PARQUET);
```

Subsequent queries read `r.parquet` directly. At fleet scale (millions
of records) the difference is two orders of magnitude in query time.

ClickHouse, Athena, BigQuery, and Snowflake all accept the same
queries with cosmetic edits. The choice of warehouse is the operator's;
linpersist does not have a preference.

## Walkthrough

### Query 1 — Pure LFA

The foundational query. For each `(module, content_norm_sha256)`
pair, count the distinct hosts that produced it. Keep the singletons.

```sql
SELECT module, site_class, content_norm_sha256,
       count(DISTINCT host_id) AS hosts, ...
FROM r
GROUP BY module, site_class, content_norm_sha256
HAVING count(DISTINCT host_id) = 1
ORDER BY module, site_class, sample_snippet;
```

Group also by `module` and `site_class` because mixing artifact kinds
across the same digest is meaningless: a cron line digest and a pam
line digest happen to have different hash spaces and combining them
buys nothing.

In a clean fleet, the singletons are typically: a host that was
imaged from an older base image and has a stale package version, a
host where an admin hand-edited a config file, a host where a CI
process generated a unique config from a template. In a compromised
fleet, one or more of the singletons is the attacker's persistence
line.

### Query 2 — Per-locus LFA

Like Query 1 but groups also by `locus`. Catches the case where a
common digest appears in an uncommon place. Concretely: every host
runs `logrotate` from `/etc/cron.daily/logrotate`, but exactly one
host has a copy of the same content at `/etc/cron.daily/sync` — the
attacker renamed it to look mundane. Query 1 misses this because the
digest is common; Query 2 catches it because `(digest, locus)` is
unique.

The cost: more rows in the output. Per-locus singletons include every
per-user file under `/home/<user>/.ssh/authorized_keys` and
`/home/<user>/.bashrc`, because those paths are by construction
per-host. Filter or exclude `/home/*` if the noise is unacceptable.

### Query 3 — Peer-group LFA by `os_id`

The Achilles' heel of pure LFA is fleet heterogeneity. One RHEL host
in an Ubuntu fleet trivially singleton-stacks every record from
itself, because the Ubuntu baseline does not match its RHEL
baseline. The attacker hides in plain sight under the noise of
distro-specific defaults.

Peer-group LFA fixes that. Group by `host_meta.os_id` first, then
take singletons within each peer group. RHEL records compete with
RHEL records, Ubuntu with Ubuntu, Alpine with Alpine. A malicious
cron line on the one compromised Ubuntu host still surfaces; a
benign apt-listchanges line that all 4,000 Debian-family hosts
share no longer does.

The `peer_hosts > 2` floor in the query exists because a peer group
of one or two hosts cannot meaningfully establish a baseline. Tune
the floor to your fleet shape: at 50,000 hosts you may want
`peer_hosts > 20` instead.

`os_id` is the simplest peer key. More sophisticated deployments
might combine `(os_id, role)`, `(os_id, os_version)`, or
`(os_id, fleet_tag)`. The agent already exposes `host_meta.tags`;
populate it via the planned `--tag KEY=VALUE` flag (deuda explícita
del ADR-0006).

### Query 4 — Cross-module obvious-implant signature

`exec_target_orphan` combined with `interpreter_in_tmp` is the
textbook persistence implant fingerprint across modules. Examples
the agent has surfaced in practice:

- A cron line referencing `/tmp/.cache/poll.sh` (which does not
  exist on disk — the file is dropped at runtime).
- A pam.d directive loading `/tmp/.so/pam_evil.so`.
- An ssh authorized_keys entry forcing
  `command="/tmp/.b/persist"`.
- A sshd_config `AuthorizedKeysCommand=/tmp/x/keys`.
- An ld.so.preload entry pointing at a path under `/dev/shm`.

The conjunction is *very* rare in legitimate configuration. Vendor
software does not put files in `/tmp` and reference them from
persistence; CI pipelines that do (sometimes scratch tests do) are
usually tagged and easy to exclude.

This query is the cheapest insurance the analyst has against a noisy
LFA result: it surfaces a small number of high-signal records that
warrant immediate triage regardless of how the rest of the fleet
looks.

### Query 5 — Signal distribution histogram

The four queries above slice the data by content. This one slices it
by signal. For each `(module, signal)` pair, count distinct hosts
and total records.

Two uses:

1. **Fleet-health overview.** `recent_mtime_7d` should be modest on
   a quiet fleet. A spike (suddenly 80% of hosts have recent mtimes
   on persistence files) means something — config-management push,
   package update, attacker sweep — rewrote configuration recently.
   The histogram does not say which; it says "look".

2. **Calibration of the other queries.** A signal that fires on
   most of the fleet is a baseline and is uninteresting on its own.
   A signal that fires on a handful of hosts IS interesting:
   `ssh_forced_command` on three hosts in a fleet of 5,000 is
   noteworthy even before joining against LFA results.

### Query 6 — Cross-host `exec_target_sha256` stacking

The five queries above stack on the persistence RECORD. This one
stacks on the EXECUTABLE the record points to. Two different cron
entries on two different hosts can carry distinct `content_norm_sha256`
values (the scheduling lines differ) yet both invoke a binary with
the same `exec_target_sha256`. That is a worm pattern: identical
payload, polymorphic persistence.

```sql
SELECT
  exec_target_sha256,
  count(DISTINCT host_id)                          AS hosts,
  count(*)                                         AS records,
  count(DISTINCT module)                           AS modules,
  count(DISTINCT site_class)                       AS site_classes,
  any_value(exec_target)                           AS sample_target,
  list(DISTINCT module)                            AS spread_modules
FROM r
WHERE exec_target_sha256 IS NOT NULL
GROUP BY exec_target_sha256
HAVING count(DISTINCT host_id) >= 2
   AND count(DISTINCT host_id) < (SELECT 0.10 * count(DISTINCT host_id) FROM r)
ORDER BY hosts DESC, modules DESC;
```

The output gives one row per distinct payload, with the count of
hosts that have wired persistence to it. The lower-bound (>= 2)
excludes singletons (already covered by Query 1); the upper-bound
(< 10% of fleet) excludes baseline binaries shipped by the OS
(`/usr/bin/systemctl`, `/bin/sh`, package-manager helpers). The
sweet spot is in the middle: a payload present on 5-50 hosts in a
fleet of thousands, invoked from a heterogeneous set of modules,
almost always lateral movement.

**False positives.**
- Custom internal binaries deployed by configuration management.
  Filter by `exec_target_pkg_status` once provenance is wired
  (v0.2.0).
- Multi-arch fleets where the same source compiles to different
  `exec_target_sha256` per arch — the worm row appears smaller than
  it really is because the digest fragments. Group by exec basename
  in a follow-up query to disambiguate.

### Query 7 — Implant roll-call (cross-cutting union)

The textbook fingerprint of Q4 catches every implant whose
`exec_target` lives under `/tmp` and is currently absent — about
half of the implant classes observed in the wild. The rest need a
different shape:

- A sudoers `NOPASSWD: ALL` row has no `exec_target` at all.
- A uid=0 backdoor in `/etc/passwd` is not a script; it's a database
  row.
- A `curl|bash` line in `/root/.bashrc` references an external URL,
  not a path.
- A `kmod install …` directive carries `/bin/sh` as its
  `exec_target` (the shell running `-c '...'`); the malicious script
  is inside the `-c` argument.

Q7 is the cross-cutting union that the analyst runs first on every
new fleet: it returns one row per record that matches **any** of
the known implant shapes. Validated against the lab-large fleet
(25 hosts, 13 documented implants across 5 hosts): exactly 13 rows,
zero false positives. The clauses are deliberately disjoint to keep
each implant on exactly one row.

The query's source comment lists every clause and why it earns its
place. Module-specific signals
(`kmod_install_directive`, `sudoers_nopasswd`,
`sudoers_all_commands`, `passwd_uid_zero`) carry the load; content
patterns fill the gaps for shell-init implants
(`profile`, `motd`, `sysv`) where the `exec_target` is the script
itself rather than the malicious payload.

### Query 8 — Recent-mtime concentration per host × module

Q1-Q7 slice the data by content. Q8 slices by time. For each
`(host, module)` pair, count records carrying the `recent_mtime_7d`
signal. The interesting output is concentration: one host with 50+
recent records across half its modules is, by definition, doing
something the rest of the fleet is not.

Two interpretations of a spike:

1. **Config-management push** — Ansible / Salt / Chef just rolled
   a playbook against this host. Correlate with the orchestration
   tool's change log; if the timing matches, it's noise.
2. **Post-compromise sweep** — the attacker is hardening
   persistence after initial access: rewriting `authorized_keys`,
   dropping new cron entries, layering systemd units, rotating
   bashrc. The timing pattern is more clustered than a tool would
   produce.

The query returns ZERO rows on a quiet fleet because most
persistence files are touched once at install and never again. Any
output above the `HAVING count(*) >= 5` floor is by definition
worth a look.

### Query 9 — Exec targets under /tmp (regardless of orphan)

Q4 demands BOTH `exec_target_orphan` AND `interpreter_in_tmp`. The
conjunction is precise: it catches the implant whose payload was
deleted post-execution (orphan) or has not been deployed yet. It
misses the case where the payload is on disk right now — exactly
the period when the attacker is still operational.

Q9 closes that gap. Any record whose `exec_target` lives under
`/tmp`, `/var/tmp`, `/dev/shm`, or `/run/shm` surfaces here,
orphan or not. The `is_orphan` column on each row tells the analyst
which of Q4 vs "armed but on disk" they're looking at.

Q9 set minus Q4 set = "currently armed implants". That's the
analyst's worst-case list: persistence wired to a payload that
exists on disk right now.

**Calibration: what `exec_target` means** (ADR-0014). For Q9 to
stay accurate, every module must agree on what populates the
`exec_target` field. The binding rule is: `exec_target` is "the
binary the persistence INVOKES", not "the path the directive
touches". Three categories every module classifies into before
populating:

1. **run-the-binary** — populate `exec_target`. Cron commands,
   systemd `ExecStart=`, PAM module paths, kmod install commands,
   udev `RUN+=` targets, XDG `Exec=`, `ld.so.preload` library
   paths.
2. **touch-this-path-but-no-exec** — do NOT populate. The classic
   trap is `systemd.tmpfiles`: a directive like
   `f /tmp/.cache/payload 0755 root root - /opt/implant` touches
   the target path at boot but does not invoke it. Treating the
   target as `exec_target` polluted Q9 with hundreds of baseline
   rows (X11 socket dirs, systemd-private sandboxes, dnf locks)
   when this rule was violated in v0.3.0-pre.
3. **marker-only** — do NOT populate. `systemd.linger` (presence
   of a marker file enables user-mode systemd to survive
   logout), `systemd.sysusers` (declarative user / group
   creation). These are persistence vectors but do not invoke a
   binary; their fingerprint is the directive itself, not an
   exec.

When in doubt, ask: "if I deleted the binary at this path, would
the persistence stop working?" YES -> run-the-binary, populate.
NO -> leave empty.

### Query 10 — Per-host collection health and coverage outliers

A fleet-health and collection-validity check rather than a hunting
query. For each host, count: records emitted, distinct modules,
distinct site_classes, records with recent_mtime_7d.

Two failure modes Q10 catches:

1. **Silent collection failures.** A host with `records = 0` or
   `modules = 1-2` against a fleet median of 10+ is almost
   certainly a collection failure — the agent didn't run, ran
   without read permissions, ran on a chroot, or got killed by
   timeout. Cron-job alerting should pick this up but rarely does.
2. **Coverage outliers.** A host emitting 3-5× more records than
   its peers is doing something unusual. Could be a workload with
   genuinely more services (k8s control plane, jump host with many
   user accounts) — verify with `tags`. Could also be an attacker's
   campaign of artifact drops.

Sort by `records DESC` for outliers above the median; sort `ASC`
for collection failures below it.

### Query 11 — Orphan exec_target OUTSIDE tmp-class directories

Q4 and Q9 between them catch the textbook implant pattern where the
payload lives in `/tmp`, `/var/tmp`, `/dev/shm`, or `/run/shm`. A
more disciplined attacker drops the payload somewhere long-lived but
unmanaged — `/opt/<innocuous-name>/`, `/var/lib/<service>/`, `/srv/`,
`/usr/local/bin/<binary>` — and wires persistence to it. Neither
`interpreter_in_tmp` nor `exec_target_orphan` fires for that record.
The only thing that catches it is `non_package_path` from the
v0.2.0 provenance resolver: the binary is not owned by any installed
dpkg or rpm package.

Q11 surfaces every record where the `exec_target` is flagged
`non_package_path` AND lives outside the four tmp-class prefixes.
The rows are aggregated by `exec_target` and sorted ascending on
host count, so single-host targets bubble to the top of the table.

The query intentionally excludes the tmp-class prefixes Q9 already
covers, so **Q9 ∪ Q11 partitions** the universe of "non-package
exec_target paths" by location class. Run both for full coverage
of the unmanaged-payload pattern.

False positives:

- **Vendor-installed software outside the package manager.** A
  workstation with `/opt/<vendor>/bin/<binary>` installed by a
  vendor tarball produces `non_package_path` records that look like
  hits but are normal for that role. Filter by `hosts >= 2` to
  ignore them — a real operator deploy lands on a fleet, not one
  host.
- **Operator-managed deploys.** Same shape, same filter.
- **Provenance build failure.** If `exec_target_pkg_status` is
  `error` on many records, the resolver could not build its map
  (rpm DB unreadable, dpkg/info missing). Q11 will be empty in
  that case; check with a `WHERE exec_target_pkg_status = 'error'`
  sanity query.

## False positives the analyst learns to filter

Frequency stacking is not a verdict. The queries above produce
candidate records that warrant attention; the analyst combines them
with context the agent does not have:

- **Cold-start.** A host imaged five minutes before collection has
  had no time to drift toward its peers. Filter on host age if
  available (CMDB lookup, machine-id provisioning date, first-seen
  timestamp).
- **Distro-version skew.** A new Ubuntu point release that just
  rolled out to 5% of the fleet creates synthetic singletons across
  every package-managed config file. Filter on `os_version` peer
  groups, or wait a week.
- **Manual admin edits.** A sysadmin tweaking `/etc/sudoers` on the
  bastion host is indistinguishable from an attacker tweaking it,
  except the sysadmin will own up. Pair with change-management
  audit logs.
- **Hostname fragmentation.** Containers, Kubernetes pods, and
  autoscaling groups produce ephemeral hostnames; their
  `hostname_hash` is unique per instance. Grouping by `host_id`
  (machine-id) and using `host_meta.tags` for fleet-level identity
  is the recommended workaround. See ADR-0006.
- **Per-user files.** `/home/*/.bashrc`, `/home/*/.ssh/authorized_keys`
  and per-user cron jobs under `/var/spool/cron/crontabs/*` are
  per-host by construction. Treat them with a separate stacking
  strategy (compare a user's `.bashrc` across hosts they have
  accounts on, not across the whole fleet).
- **CI / build agents.** These hosts run unusual workloads that
  legitimately drop and remove files under `/tmp` and `/dev/shm`.
  Tag them and exclude from Query 4.

## Recommended workflow

For day-to-day fleet triage:

1. Collect once a day (cron-driven `linpersist --output /var/log/...`
   plus a sync to the warehouse).
2. Run Q10 first. If hosts are missing or way below the fleet
   median, you have a collection problem before you have a hunting
   problem.
3. Run Q7 (implant roll-call) second. It is the single highest-
   signal query in the cookbook: a fleet of 25 hosts with 13
   textbook implants produces exactly 13 rows in Q7 with zero
   false positives. Output of Q7 is the analyst's triage queue
   for the day.
4. Run Q8 (recent-mtime concentration). Spikes that don't
   correlate with a config-management push are the second-tier
   triage queue.
5. Run Q9 (exec targets in /tmp) and diff against Q4: the
   difference is the "armed right now" subset.
6. Run Q11 (orphan outside /tmp). Catches the disciplined-attacker
   pattern Q4/Q9 miss: payloads under `/opt/`, `/var/lib/`, `/srv/`,
   `/usr/local/` that look benign by location and are caught only by
   the provenance resolver flagging them as `non_package_path`.
7. Per-module deep dives via Q1 with `WHERE module = 'X'`. Q3
   when the fleet is mixed across distros.

For an active investigation: Q7 across the suspected hosts, then
Q2 (per-locus) and Q6 (cross-host exec_target) to find lateral
spread.

## Running the queries

```sh
# Default — runs all eleven against a directory of NDJSON:
./tools/ingest.sh -q tools/stack_demo.sql ./fleet/

# Custom set:
./tools/ingest.sh -q my-custom.sql ./fleet/

# Or interactively in DuckDB:
duckdb fleet.duckdb -c "
CREATE TABLE r AS SELECT * FROM read_ndjson_auto('fleet/*.ndjson', ignore_errors=true);
.read tools/stack_demo.sql
"
```

The `linpersist-report` binary embeds a Go-native implementation of
all eleven queries (Q1-Q11) so analysts on a jump host without the
DuckDB CLI still get the full triage view. The SQL file is the
canonical source of truth; the Go path is a row-for-row mirror kept
in sync (the same WHERE clauses, the same aggregation, the same
sort order).

## See also

- `docs/schema-v1.md` — canonical Record shape.
- `docs/normalization-rules.md` — invariants every module's
  `Normalize` honors. Stacking only works if normalization works.
- `docs/adr/0002-record-granularity.md` — why per-line granularity
  is the unit for crontab/sudoers/ssh.authkeys and why per-file is
  the unit for run-parts scripts.
- `docs/adr/0006-hostname-policy.md` — hostname representation and
  the container/k8s correlation strategy.
- `matrix.yaml` — full coverage map.
- `lab/` — end-to-end synthetic fleet with implants, where these
  queries first showed they earn their keep.
