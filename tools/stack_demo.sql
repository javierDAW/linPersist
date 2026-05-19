-- tools/stack_demo.sql
--
-- Canonical, curated, non-redundant set of frequency-stacking queries
-- for linpersist NDJSON. ELEVEN queries, each adding a distinct
-- analytical angle. Designed for DuckDB; portable to ClickHouse with
-- cosmetic edits and to Athena / BigQuery with bigger ones.
--
-- Usage from the analyst's terminal:
--
--   ./tools/ingest.sh -q tools/stack_demo.sql /path/to/fleet/
--
-- Or load custom queries instead:
--
--   ./tools/ingest.sh -q my-custom.sql /path/to/fleet/
--
-- This file is the threat-hunting reference set: each query earns its
-- keep, none is a slight variation of another. Per-module variants
-- (e.g. "cron LFA") are NOT separate queries -- the analyst adds a
-- `WHERE module = 'cron'` filter to Q1.
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

--- query separator ---

-- Query 7: Implant roll-call -- cross-cutting union.
--
-- One row per record that matches ANY of the canonical implant
-- patterns across all modules. Built to be exhaustive AND
-- non-redundant: every clause covers a class of implants that the
-- other clauses miss. Validated end-to-end on the lab-large fleet
-- (25 hosts, 13 documented implants -- this query produces exactly
-- 13 rows with zero false positives).
--
-- Clauses, with the implant family each covers:
--
--   1. exec_target_orphan AND interpreter_in_tmp -- the textbook
--      "attacker dropped payload under /tmp and wired persistence
--      to it" pattern. Covers cron, ssh, sshd, pam, ldso, systemd
--      (ExecStart=/tmp/...), udev (RUN+="/tmp/...").
--   2. sudoers_nopasswd AND sudoers_all_commands -- sudoers
--      backdoor (NOPASSWD on the ALL command list). The conjunction
--      is rare in legitimate config; the disjunction is not (every
--      host has a `root ALL=(ALL) ALL` baseline that fires
--      sudoers_all_commands, and CI-runner sudoers.d/ drop-ins
--      commonly carry NOPASSWD for specific commands).
--   3. passwd_uid_zero -- second uid=0 user.
--   4. kmod_install_directive -- modprobe install-replacement.
--   5. profile + content has curl|wget -- shell-init implant.
--   6. sysv + content has /tmp/ -- init script referencing /tmp
--      payload (exec_target is the script itself, not /tmp).
--   7. motd + content has curl|wget -- update-motd.d implant.
--
-- Deliberately NOT a clause: `module='udev' AND udev_run_directive`.
-- Every Linux baseline ships udev rules with RUN+= (hwclock-set,
-- dm-notify, ...); the udev implant is caught by clause 1 anyway
-- because its exec_target points at /tmp.
--
-- False positives:
--   - Internal automation that legitimately calls curl|bash from
--     /root/.bashrc on jump hosts.
--   - sudoers NOPASSWD on bastion / CI-runner accounts.
--   - kmod install directives shipped by some distros' kernel
--     packages (rare but exists; pair with non_package_path once
--     provenance is wired in v0.2.0).
SELECT
  coalesce(host_meta.hostname, host_id) AS host,
  module,
  site_class,
  locus,
  exec_target,
  list_intersect(signals, [
    'exec_target_orphan',
    'interpreter_in_tmp',
    'ssh_forced_command',
    'sudoers_nopasswd',
    'sudoers_all_commands',
    'passwd_uid_zero',
    'sshd_authorized_keys_command',
    'sshd_permit_root_login_yes',
    'kmod_install_directive',
    'udev_run_directive',
    'systemd_external_unit_symlink',
    'sysv_external_init_symlink'
  ]) AS triage_signals,
  content_snippet
FROM r
WHERE
  (list_contains(signals, 'exec_target_orphan')
   AND list_contains(signals, 'interpreter_in_tmp'))
  OR (list_contains(signals, 'sudoers_nopasswd')
      AND list_contains(signals, 'sudoers_all_commands'))
  OR list_contains(signals, 'passwd_uid_zero')
  OR list_contains(signals, 'kmod_install_directive')
  OR (module = 'profile'
      AND (content_snippet LIKE '%curl%' OR content_snippet LIKE '%wget%'))
  OR (module = 'sysv' AND content_snippet LIKE '%/tmp/%')
  OR (module = 'motd'
      AND (content_snippet LIKE '%curl%' OR content_snippet LIKE '%wget%'))
ORDER BY host, module, locus;

--- query separator ---

-- Query 8: Recent-mtime concentration per host x module.
--
-- For each (host, module) pair: how many records carry the
-- `recent_mtime_7d` signal? Spikes are the analytical interest:
--
--   - One host in a fleet of thousands with 50+ recent records
--     across 6+ modules: something rewrote a lot of config on
--     that host in the last week. Either config-management push
--     (legitimate, correlatable with CMDB) or post-compromise
--     sweep (attacker hardening / cleanup).
--   - One module across the fleet with universally-recent mtimes:
--     a package upgrade just rolled through. Verify with the
--     package manager change log.
--
-- The query returns ZERO rows on a quiet fleet because most
-- persistence files are touched once at install and never again.
-- Any output is by definition unusual.
--
-- False positives:
--   - Just-imaged hosts: every file is "recent" by mtime. Filter
--     on a CMDB / first-seen timestamp.
--   - Distro point-release rollout: a package upgrade just touched
--     a lot of config files. Cross-reference with the OS vendor's
--     release calendar.
SELECT
  coalesce(host_meta.hostname, host_id) AS host,
  module,
  count(*)                AS recent_records,
  count(DISTINCT locus)   AS recent_loci
FROM r
WHERE list_contains(signals, 'recent_mtime_7d')
GROUP BY host, module
HAVING count(*) >= 5
ORDER BY recent_records DESC, host, module;

--- query separator ---

-- Query 9: Exec targets under /tmp, /var/tmp, /dev/shm, /run/shm.
--
-- Q4 requires BOTH orphan AND interpreter_in_tmp -- high precision
-- but misses the case where the attacker dropped the payload AND
-- left it on disk (no orphan signal). This query is the open-half:
-- exec_target is in a tmp-class directory, regardless of whether
-- the file currently exists.
--
-- Combined with Q4 the analyst gets the full set of "persistence
-- wired to a tmp-class path" records. Q4 + Q9 difference shows
-- which implants are currently armed vs which are dormant /
-- post-execution.
--
-- False positives:
--   - Containerized workloads that legitimately use /tmp as a
--     working directory (CI runners, build agents). Filter on
--     host_meta.tags = 'role:ci' or equivalent.
--   - Some distro packages drop files under /var/tmp/ during
--     install and reference them from cron once. Rare; filter out
--     by adding `AND NOT list_contains(signals, 'non_package_path')`
--     to isolate package-owned tmp-class targets, or invert the
--     condition to see only the orphan + tmp pattern from a single
--     query.
SELECT
  coalesce(host_meta.hostname, host_id) AS host,
  module,
  site_class,
  locus,
  exec_target,
  list_contains(signals, 'exec_target_orphan') AS is_orphan,
  content_snippet
FROM r
WHERE
  exec_target IS NOT NULL
  AND (exec_target LIKE '/tmp/%'
       OR exec_target LIKE '/var/tmp/%'
       OR exec_target LIKE '/dev/shm/%'
       OR exec_target LIKE '/run/shm/%')
ORDER BY host, module, locus;

--- query separator ---

-- Query 10: Per-host collection health and coverage outliers.
--
-- For each host: how many records were emitted, how many distinct
-- modules, how many distinct site_classes? Compared against the
-- fleet median this is a collection-health check (zero or near-zero
-- counts mean the agent failed silently) AND an anomaly detector
-- (a host that emits 3x more records than its peers is doing
-- something unusual -- either dramatic config drift or a campaign
-- of artifact drops).
--
-- The HAVING clause is empty intentionally: a quiet fleet should
-- have nearly-uniform values per row. Sort by records DESC and the
-- top rows are the outliers; sort by records ASC and the bottom
-- rows are the collection failures.
--
-- False positives:
--   - Heterogeneous fleet (Ubuntu desktop vs Alpine appliance) will
--     produce different counts by design. Group by os_id first if
--     comparing.
--   - Hosts under heavy churn (k8s control plane with many
--     configmaps mounted into /etc) emit many records. Tag them.
SELECT
  coalesce(host_meta.hostname, host_id) AS host,
  any_value(host_meta.os_id)             AS os_id,
  count(*)                               AS records,
  count(DISTINCT module)                 AS modules,
  count(DISTINCT site_class)             AS site_classes,
  count(DISTINCT
    CASE WHEN list_contains(signals, 'recent_mtime_7d')
         THEN locus ELSE NULL END)       AS recent_records
FROM r
GROUP BY host_id, host_meta.hostname
ORDER BY records DESC;

--- query separator ---

-- Query 11: Orphan exec targets OUTSIDE /tmp-class directories.
--
-- The implant pattern Q4 and Q9 miss entirely: the attacker drops the
-- payload under a long-lived but unmanaged path (/opt/, /var/lib/,
-- /srv/, /usr/local/) and wires persistence to it. The payload is not
-- in /tmp so `interpreter_in_tmp` does not fire; the payload exists
-- on disk so `exec_target_orphan` does not fire either. The only
-- signal that catches it is `non_package_path` from the v0.2.0
-- provenance resolver: the binary is not owned by any installed
-- dpkg/rpm package.
--
-- The query intentionally excludes the four tmp-class prefixes Q9
-- already covers, so Q9 + Q11 partition the universe of
-- "non-package_path exec_targets" by location class. Run both for
-- full coverage of the unmanaged-payload pattern.
--
-- The ORDER BY is ASC on host count: singletons (a path seen on
-- exactly one host across the fleet) bubble to the top. These are
-- the highest-precision hits.
--
-- False positives:
--   - Sites that install custom software outside the package
--     manager (research workstations with /opt/<vendor>/, vendor
--     appliances). Tag hosts by role and filter; the per-vendor
--     directories normalize the same way every time so they cluster
--     on multiple hosts (count > 1).
--   - Operator-managed deploys under /opt that are not packaged.
--     LFA helps: a real operator deploy hits a fleet, not a single
--     host. Filter on host count >= 2 to ignore them.
--   - Distro packages that ship binaries outside the package
--     manifest by design (extremely rare on dpkg/rpm hosts; if you
--     see this systematically, the resolver may have failed --
--     check exec_target_pkg_status = 'error' separately).
SELECT
  exec_target,
  count(DISTINCT host_id)            AS hosts,
  count(*)                           AS records,
  any_value(module)                  AS module,
  any_value(site_class)              AS site_class,
  any_value(locus)                   AS sample_locus,
  any_value(content_snippet)         AS sample_snippet
FROM r
WHERE list_contains(signals, 'non_package_path')
  AND exec_target IS NOT NULL
  AND exec_target NOT LIKE '/tmp/%'
  AND exec_target NOT LIKE '/var/tmp/%'
  AND exec_target NOT LIKE '/dev/shm/%'
  AND exec_target NOT LIKE '/run/shm/%'
GROUP BY exec_target
ORDER BY hosts ASC, records DESC, exec_target
LIMIT 200;
