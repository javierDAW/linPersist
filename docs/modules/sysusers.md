# Module: `sysusers`

| site_class           | MITRE       | granularity   | docs                |
| -------------------- | ----------- | ------------- | ------------------- |
| `systemd.sysusers`   | `T1136.001` | per-directive | this doc, ADR-0014  |

The module collects systemd-sysusers configuration files. The
`systemd-sysusers` service runs at boot and declaratively
creates the users / groups / memberships listed in these files
WITHOUT editing `/etc/passwd` or `/etc/group` as the source of
truth. The passwd module sees the resulting entries on disk;
the directive that PUT them there lives in a separate locus
and is only visible if a collector reads it.

A directive that creates a **second uid-0 user** under a name
other than `root` is a known persistence pattern: a defender
auditing `/etc/passwd` sees a normal-looking line; the
fingerprint of the implant lives in `/etc/sysusers.d/`
instead. The module is read-only, side-effect-free, and emits
one record per non-comment, non-blank line.

## Loci

- `/etc/sysusers.d/` -- admin overrides.
- `/usr/lib/sysusers.d/` -- vendor-shipped baseline.

Only files with extension `.conf` are processed; files with a
leading `.` are skipped (dotfile filter). Files larger than
`MaxFileSize` (default 64 KiB) emit a single envelope record
with `errors[0]={field:content_sha256, code:SIZE_LIMIT}`.

## Format

Per `sysusers.d(5)`, each non-comment, non-blank line is:

```
type name id "gecos" home shell
```

Type letters:

- `u` -- user.
- `g` -- group.
- `m` -- group membership.
- `r` -- uid / gid range reservation.

Field `id` carries the uid (for `u`) or gid (for `g`); a literal
`-` means "let systemd pick a free value". Field `gecos` may
contain whitespace if double-quoted. Fields `home` and `shell`
default to systemd's policy if unset (`-`).

## Canonical form (content_norm_sha256)

`canonicalDirective(raw)` applies the same idempotent rules
as tmpfiles:

1. `TrimSpace` leading and trailing whitespace.
2. Collapse runs of space / tab outside quoted segments to a
   single space.
3. Preserve double-quoted segments verbatim.

Two semantically-equivalent directives (differing only in
whitespace or comment density) stack to the same
`content_norm_sha256`.

## ExecTarget category

`marker-only` (ADR-0014). A sysusers directive does not invoke
a binary -- it declares a user / group. `ExecTarget` is NOT
populated. The directive remains visible via `content_snippet`.

The classic implant correlation is *between* this module's
records and the `passwd` module's records: a sysusers `u` line
declaring uid 0 with a non-root name AND a corresponding
`/etc/passwd` entry on the same host is the redundant
double-write pattern. The backend joins them on host_id +
username.

## Signals

Module-specific:

| signal                 | fires when                                                          |
| ---------------------- | ------------------------------------------------------------------- |
| `sysusers_uid_zero`    | type `u`, id field literally `0`, name field anything other than `root` |
| `empty_file`           | source contains only comments / blank lines (envelope record)        |

The signal does not fire on:

- The canonical `u root 0 ...` baseline (would generate a critical
  alert on every host).
- `g` / `m` / `r` directives, regardless of any `0` fields they
  carry (gid 0 is `root` group, expected on every host).
- Type `u` with id `-` (let systemd pick) -- systemd will not
  pick uid 0; this would be a configuration error not a
  persistence vector.

Inherited from `core`:

| signal              | fires when                              |
| ------------------- | --------------------------------------- |
| `recent_mtime_7d`   | source file mtime within the last 7 days |
| `recent_mtime_30d`  | source file mtime within 7-30 days       |
| `world_writable`    | source file has mode bit `0o002`        |
| `non_root_owner`    | source under a system path, uid != 0     |

## Known false-positive patterns

- **Vendor-shipped `u <daemon> 0 ...` lines DO NOT EXIST in
  any stock distro as of May 2026.** The signal is intended to
  fire LOUD; a true positive in production is almost certainly
  worth investigating.
- **Container images that "graft" a non-root admin onto uid 0**
  via sysusers (rare but documented in some CI pipelines for
  rootless container substitutes) will trigger correctly. The
  fix is to use a regular uid for the admin or to drop the
  sysusers shim entirely; do not silence the signal.

## What this module deliberately does NOT do

- Resolve the directive against `/etc/passwd` / `/etc/group`
  at collection time. Cross-correlation lives in the backend
  (`Q4 implant_fingerprint` clauses).
- Execute `systemd-sysusers --dry-run`.
- Parse the gecos field beyond preserving its bytes. The
  hidden-in-plain-sight implant in the wild has so far been
  in the `name` / `id` fields, not gecos.
- Walk `/etc/passwd` source bytes for the corresponding entry
  -- that is the `passwd` module's job.

## References

- `sysusers.d(5)`, `systemd-sysusers(8)`.
- MITRE ATT&CK `T1136.001` (Local Account creation; parent
  technique shared with the `passwd` module).
- ADR-0014 (systemd structural-family modules).
- PANIX (Aegrah/PANIX) Local Account persistence catalog --
  the inverse view of what this module detects.
