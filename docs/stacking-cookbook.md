# Stacking cookbook

`linpersist` collects every persistence artifact it finds on a host
into NDJSON and walks away. The agent does not decide whether anything
is malicious. That decision lives downstream, in a database that has
seen the same artifacts on every other host in the fleet. The
technique is frequency stacking, also known as Least Frequency
Analysis (LFA). This cookbook explains the model, walks through the
six canonical queries shipped in `tools/stack_demo.sql`, and lists
the false-positive patterns that the analyst learns to filter out.

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
2. Run Query 4 first. It is cheap and the signal-to-noise ratio is
   the best of the five.
3. Run Query 3 per module. Per-module is cheaper than across-module
   and the results are easier to skim.
4. Cross-reference singletons from Query 1 against `host_meta.tags`,
   change-management logs, and ticket trackers.
5. Run Query 5 weekly as a fleet-health check.

For an active investigation: cover Query 2 (per-locus) on the
suspected hosts to surface anything common-but-misplaced, then
Query 4 across the whole fleet to find lateral spread.

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
