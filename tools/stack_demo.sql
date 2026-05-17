-- tools/stack_demo.sql
--
-- Canonical frequency-stacking queries for linpersist NDJSON. Six
-- queries, each illustrating one stacking strategy. Designed for
-- DuckDB; portable to ClickHouse with cosmetic edits and to Athena /
-- BigQuery with bigger ones.
--
-- The queries assume a single table `r` populated from the NDJSON
-- stream emitted by linpersist:
--
--   CREATE TABLE r AS
--     SELECT * FROM read_ndjson_auto('path/to/host-*.ndjson',
--                                    ignore_errors=true);
--
-- The agent does NOT emit host_meta.hostname by default (see ADR-0006).
-- Queries below use `coalesce(host_meta.hostname, host_id)` so they
-- work whether the fleet was collected with `--include-hostname` or
-- not. `host_id` is always populated (from /etc/machine-id when
-- available, falling back to a hash of the hostname).
--
-- Each query is preceded by a comment explaining (1) what it surfaces
-- and (2) what kind of false positives to expect. See
-- `docs/stacking-cookbook.md` for the prose walkthrough.
--
-- Block separator (`--- query separator ---`) matches the convention
-- in `lab/analyzer/queries.sql` and is recognized by `lab/analyzer/
-- ingest.py`. Adopt the same convention if you wire these queries
-- into your own pipeline.

-- Query 1: Pure LFA -- per-module singletons.
--
-- Returns every (module, content_norm_sha256) pair seen on EXACTLY
-- ONE host across the fleet. This is the load-bearing query: an
-- attacker who appends a single malicious line to /etc/crontab on a
-- compromised host produces a content_norm_sha256 no other host has,
-- and it surfaces here.
--
-- False positives:
--   - Distros that fragment the fleet (e.g. one RHEL host in an
--     otherwise Ubuntu fleet): its baseline records all look like
--     singletons. Use Query 3 for a peer-group view.
--   - Cold-start: a host imaged five minutes ago has had no time to
--     drift into matching its peers. Filter on host age if available.
--
-- Recommended invocation: run per module to avoid mixing fleet-wide
-- baselines across heterogeneous artifact kinds.
SELECT
  module,
  site_class,
  content_norm_sha256,
  count(DISTINCT host_id)                                AS hosts,
  any_value(coalesce(host_meta.hostname, host_id))       AS sample_host,
  any_value(locus)                                       AS sample_locus,
  any_value(content_snippet)                             AS sample_snippet
FROM r
GROUP BY module, site_class, content_norm_sha256
HAVING count(DISTINCT host_id) = 1
ORDER BY module, site_class, sample_snippet;

--- query separator ---

-- Query 2: Per-locus LFA -- a singleton AT a specific path.
--
-- Like Query 1 but groups also by `locus`. Catches the case where
-- the same `content_norm_sha256` is common across the fleet but
-- appears at an unusual path on one host. Example: the canonical
-- /etc/cron.daily/logrotate script is universal, but a copy at
-- /etc/cron.daily/sync (renamed to look mundane) is a singleton at
-- that locus.
--
-- False positives:
--   - Same caveats as Query 1 plus: paths under /home/<user>/ are
--     per-host by construction. Exclude or treat carefully.
SELECT
  module,
  site_class,
  locus,
  content_norm_sha256,
  count(DISTINCT host_id)                          AS hosts,
  any_value(coalesce(host_meta.hostname, host_id)) AS sample_host,
  any_value(content_snippet)                       AS sample_snippet
FROM r
GROUP BY module, site_class, locus, content_norm_sha256
HAVING count(DISTINCT host_id) = 1
ORDER BY module, locus;

--- query separator ---

-- Query 3: Peer-group LFA by os_id.
--
-- Records that are singletons inside their own OS bucket. Fixes the
-- Query 1 fragmentation problem: a `apt-listchanges`-style line that
-- legitimately appears on every Debian/Ubuntu host but NOT on RHEL
-- is no longer flagged as a singleton (each os_id has its own
-- baseline), while an attacker's unique cron line on the single
-- compromised Ubuntu host still surfaces.
--
-- The `peer_hosts > 1` filter excludes peer groups too small to
-- learn a baseline from (e.g. a single ppc64le host in an amd64
-- fleet would otherwise show every record as a singleton).
--
-- False positives:
--   - Minority os_id with <=2 hosts produces noisy results until the
--     filter kicks in. Tune the threshold to your fleet shape.
SELECT
  host_meta.os_id                                AS os_id,
  module,
  site_class,
  content_norm_sha256,
  count(DISTINCT host_id)                        AS hosts_in_os,
  any_value(coalesce(r.host_meta.hostname, r.host_id)) AS sample_host,
  any_value(locus)                               AS sample_locus,
  any_value(content_snippet)                     AS sample_snippet
FROM r
WHERE host_meta.os_id IS NOT NULL
GROUP BY host_meta.os_id, module, site_class, content_norm_sha256
HAVING count(DISTINCT host_id) = 1
   AND (
     SELECT count(DISTINCT r2.host_id)
     FROM r r2
     WHERE r2.host_meta.os_id = r.host_meta.os_id
   ) > 2
ORDER BY os_id, module, sample_snippet;

--- query separator ---

-- Query 4: Cross-module obvious-implant signature.
--
-- Records carrying BOTH `exec_target_orphan` AND `interpreter_in_tmp`.
-- This is the textbook fingerprint for "attacker dropped a payload
-- under /tmp and wired persistence to it":
--   - cron entry pointing at /tmp/.x/run
--   - sshd_config AuthorizedKeysCommand=/tmp/.b/keys
--   - pam line referencing /tmp/.so
--   - sudoers line invoking /tmp/script
--   - ldso.preload entry pointing at /tmp/.so
--
-- The conjunction of orphan + tmp is rare in legitimate
-- configuration. Singletons here deserve immediate triage even
-- before correlating with the LFA queries above.
--
-- False positives:
--   - Test fixtures and CI scratch dirs sometimes look like this.
--     Filter out hosts tagged as build/test if you have that signal.
SELECT
  coalesce(host_meta.hostname, host_id) AS host,
  module,
  site_class,
  locus,
  exec_target,
  content_snippet
FROM r
WHERE list_contains(signals, 'exec_target_orphan')
  AND list_contains(signals, 'interpreter_in_tmp')
ORDER BY host, module, locus;

--- query separator ---

-- Query 5: Signal distribution histogram.
--
-- Counts how many hosts and how many records carry each signal,
-- broken down by module. Useful for two things:
--
--   1. Fleet-health overview: signals like `recent_mtime_7d` should
--      be modest in a quiet fleet; a spike means something rewrote
--      a lot of persistence artifacts recently.
--   2. Calibrating other queries: signals that fire on many hosts
--      are not interesting in isolation (they are baselines); pair
--      them with LFA. Signals that fire on few hosts ARE
--      interesting on their own (rare signals).
--
-- The output rows are easy to eyeball at scale: a signal that fires
-- on 1-2 hosts when the fleet has thousands is doing most of the
-- analyst's triage work for them.
SELECT
  module,
  signal,
  count(DISTINCT host_id) AS hosts,
  count(*)                AS records
FROM (
  SELECT host_id, module, unnest(signals) AS signal
  FROM r
  WHERE signals IS NOT NULL
)
GROUP BY module, signal
ORDER BY module, hosts, signal;

--- query separator ---

-- Query 6: Cross-host exec_target_sha256 stacking -- worm pattern.
--
-- Queries 1-3 stack on the persistence record. This one stacks on
-- the EXECUTABLE the record invokes. Different persistence records
-- across hosts can share an `exec_target_sha256`: identical payload,
-- polymorphic persistence. That is the lateral-movement / worm
-- pattern.
--
-- The bounds (>= 2 hosts, < 10% of fleet) carve out the sweet spot:
--   - Singletons (1 host) are already covered by Query 1.
--   - Fleet-baseline binaries (/bin/sh, /usr/bin/systemctl,
--     package-manager helpers) sit above the 10% cap and are
--     uninteresting in isolation.
--   - A payload present on 5-50 hosts in a fleet of thousands,
--     invoked from a heterogeneous mix of modules, is almost always
--     lateral movement.
--
-- False positives:
--   - Custom internal binaries deployed by config management.
--     Filter by `exec_target_pkg_status` once provenance is wired
--     (v0.2.0).
--   - Multi-arch fleets where the same source compiles to different
--     digests per arch -- the worm row appears smaller than it is.
--     Disambiguate by grouping on basename in a follow-up query.
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
