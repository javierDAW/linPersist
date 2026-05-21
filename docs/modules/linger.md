# Module: `linger`

| site_class       | MITRE   | granularity | docs                |
| ---------------- | ------- | ----------- | ------------------- |
| `systemd.linger` | `T1546` | per-file    | this doc, ADR-0014  |

The module collects systemd user-lingering markers from
`/var/lib/systemd/linger/`. A zero-byte file in that directory
named after a user enables `systemd --user` units for that user
to keep running after the user logs out -- effectively detaching
their user-mode systemd instance from interactive session
lifetime. It is read-only, side-effect-free, and emits one
record per marker file. See ADR-0014 for the family-level
design rationale.

## Loci

System-mode only:

- `/var/lib/systemd/linger/`

Subdirectories under this locus are NOT documented by systemd
and are not produced by `loginctl enable-linger`; the walker
skips any subdirectory at the top level rather than recursing.
Files starting with `.` are NOT filtered (linger usernames are
not bound by leading-dot conventions, though such names are
operationally unusual).

## Artifact format

Each marker file is **empty by contract**. systemd checks for
the file's presence, not its contents. The username is the only
semantic content carried by the artifact, so the agent uses the
filename verbatim as both `content_sha256` and
`content_norm_sha256` inputs (`HashHexString(username)`).

A direct consequence: two hosts where the same username has
linger enabled stack to a single Q1 / Q3 row regardless of file
mtime, owner, or any other ambient variable.

## ExecTarget category

`marker-only` (ADR-0014). The artifact does not invoke a binary
-- it merely flags a permission the systemd-logind daemon
consumes at session-teardown time. `exec_target` is NOT
populated. The dossier still surfaces this record via locus +
content_snippet.

## Signals

Module-specific:

| signal                       | fires when                                  |
| ---------------------------- | ------------------------------------------- |
| `systemd_linger_non_root`    | filename (username) is anything other than `root` |

The signal does not fire for `root` because root sessions never
time out the way regular user sessions do; `linger` on root is
a no-op rather than a persistence vector.

Inherited from `core`:

| signal              | fires when                              |
| ------------------- | --------------------------------------- |
| `recent_mtime_7d`   | marker file mtime within the last 7 days |
| `recent_mtime_30d`  | marker file mtime within 7-30 days       |
| `world_writable`    | marker file has mode bit `0o002`        |
| `non_root_owner`    | marker file uid != 0                     |

## Known false-positive patterns

- **Developer workstations with `loginctl enable-linger`** for
  a single human user (e.g. for desktop notification daemons,
  background sync agents). The signal fires correctly but is
  not a verdict; pair with the host's role tag (`role:dev`,
  pending v0.3.1-fleet) or with cross-host LFA to dismiss.
- **CI worker images** that linger a service account for
  long-running background jobs. Same triage: peer-group LFA by
  os_id + tag collapses the singletons to a single fleet row.

## Documented in-the-wild use

- PANIX (Aegrah/PANIX) catalog entry: `enable-linger` on a
  low-privilege user paired with a malicious unit under
  `~/.config/systemd/user/`, persisting across logout without
  any root-level write.
- Mandiant Linux IR reporting: lingering a service account
  whose `~/.config/systemd/user/` directory carries the
  payload, evading audits that focus on `/etc/systemd/system/`.

## What this module deliberately does NOT do

- Walk `~/.config/systemd/user/` -- that is the `systemd`
  module's responsibility. linger only emits the enablement
  marker; correlation with the actual user units happens in
  the backend on hostname + username.
- Resolve `<username>` against `/etc/passwd` or NSS. A linger
  file for a username that does not exist in passwd is still
  meaningful (race, stale config, deliberate ghost).
- Report systemctl runtime state. The agent only reads the
  filesystem.

## References

- `loginctl(1)`, `systemd-logind.service(8)`.
- MITRE ATT&CK `T1546` (Event Triggered Execution -- parent;
  no Linux-specific sub-technique for systemd linger as of
  May 2026).
- ADR-0014 (systemd structural-family modules).
