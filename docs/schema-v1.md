# Schema v1

`linpersist` emits newline-delimited JSON (NDJSON). One JSON object per
line, one persistence artifact per object. This document describes the
canonical shape of a v1 record. It is the contract between the agent
and the downstream stacking pipeline; breaking changes bump the major
version and require a migration note in this directory.

## Versioning policy

- **Bump `schema_v` major** on: renaming a field, changing the semantics
  of a field, removing a field, changing the hash input for
  `content_norm_sha256`, changing the canonical signal name.
- **No bump required** on: adding a new optional field, adding a new
  signal name to `signals[]` (the signal name itself is documented but
  the array is open-ended), adding a new value to
  `exec_target_pkg_status`.

Downstream consumers MUST tolerate unknown optional fields without
erroring out.

## Required fields

Every record carries these. If a value cannot be determined the record
is still emitted; the `errors[]` array carries the field-scoped failure.

| Field | Type | Description |
| --- | --- | --- |
| `schema_v` | int | Always `1` in this version. |
| `host_id` | string | Stable per-host identifier. Source order: `/etc/machine-id` → `/var/lib/dbus/machine-id` → `sha256(hostname)`. |
| `host_meta` | object | See [Host meta](#host-meta). |
| `collected_at` | string (RFC 3339, UTC) | When the runner stamped the record. |
| `agent_version` | string | e.g. `linpersist-0.1.0`. |
| `module` | string | The collecting module's `Name()`. |
| `site_class` | string | One of the `site_class` values in `matrix.yaml`. |
| `mitre` | array of strings | MITRE ATT&CK sub-technique IDs, e.g. `["T1053.003"]`. |
| `locus` | string | Absolute path to the artifact on the host. |

## Optional core fields

| Field | Type | Notes |
| --- | --- | --- |
| `agent_commit` | string | Short git SHA stamped at build time. |
| `owner_uid`, `owner_gid` | int | Unix ownership of `locus`. |
| `mode` | string | Four-digit octal, e.g. `"0644"`. |
| `mtime`, `ctime`, `atime` | string (RFC 3339, UTC) | File timestamps. |
| `size` | int | Bytes. |
| `content_sha256` | string | sha256 over raw bytes. |
| `content_norm_sha256` | string | sha256 over the module's normalized form. **Stacking key.** |
| `content_snippet` | string | First 256 bytes of the normalized form, base64-safe. |
| `exec_target` | string | The executable referenced by the artifact (e.g. cron command, ExecStart, RUN+= path). |
| `exec_target_sha256` | string | sha256 of `exec_target` bytes if it exists on disk. |
| `exec_target_pkg` | string | Package name owning `exec_target`. |
| `exec_target_pkg_status` | string | One of `unknown`, `owned`, `orphan`, `error`. |
| `exec_target_signed` | bool | Reserved for future signature checks; absent in v0.1.0. |
| `signals` | array of strings | See [Signals](#signals). |
| `errors` | array of objects | See [Errors](#errors). |

## Host meta

```json
{
  "hostname_hash": "sha256:...",     // always present
  "hostname": "host.example.com",    // only with --include-hostname
  "os_id": "ubuntu",
  "os_version": "22.04",
  "kernel": "5.15.0-91-generic",
  "arch": "amd64",
  "boot_id": "uuid",
  "tags": ["staging", "web"]
}
```

`hostname_hash` is `"sha256:" + hex(sha256(hostname))`. The prefix is
mandatory so consumers can distinguish from other digest forms in the
future.

## Signals

Cheap, deterministic flags that downstream pipelines combine into
scores. The agent does NOT compute scores. Canonical names:

| Name | When set |
| --- | --- |
| `recent_mtime_7d` | mtime within 7 days of `collected_at`. |
| `recent_mtime_30d` | mtime within 30 days but outside the 7-day window. |
| `world_writable` | `0o002` bit set on mode. |
| `non_package_path` | `exec_target_pkg_status == "orphan"`. |
| `interpreter_in_tmp` | `exec_target` under `/tmp`, `/var/tmp`, `/dev/shm`, `/run/shm`. |
| `ld_preload_set` | `/etc/ld.so.preload` non-empty. |
| `exec_target_orphan` | `exec_target` does not exist on disk. |
| `non_root_owner` | system-path artifact owned by uid != 0. |
| `shell_indirect` | exec_target is `bash`, `sh`, `dash`, `zsh`, `ash`, `python`, `python3`, `perl`, `ruby`, `php`, `node`. |
| `unqualified_exec_target` | exec_target is a bare name (no leading slash); the agent did not resolve against PATH. |
| `cron_var_assignment` | Record represents a cron variable assignment (`MAILTO=`, `PATH=`, `SHELL=`, `RANDOM_DELAY=`, ...). |
| `at_reboot` | Cron schedule uses the `@reboot` shorthand. |
| `empty_file` | Envelope record emitted for an empty file when its mere existence matters (e.g. `cron.daily/` script of size 0). |

New signal names require updating `internal/core/signals.go` AND this
table.

## Errors

```json
{
  "field": "content_sha256",
  "code": "EACCES",
  "msg": "open /root/.ssh/authorized_keys: permission denied"
}
```

`code` is a POSIX errno when applicable (`EACCES`, `ENOENT`, `EPERM`),
otherwise an upper-snake identifier (`PARSE_ERROR`, `TIMEOUT`,
`SIZE_LIMIT`). `msg` is optional and never contains user-controlled
content verbatim above debug log level.

## Example record

```json
{
  "schema_v": 1,
  "host_id": "9c8a8f7e3b4c4f9b8d6a1e2f3c4b5a67",
  "host_meta": {
    "hostname_hash": "sha256:6c2a3e...",
    "os_id": "ubuntu",
    "os_version": "22.04",
    "kernel": "5.15.0-91-generic",
    "arch": "amd64",
    "boot_id": "b3f8..."
  },
  "collected_at": "2026-05-12T10:00:00Z",
  "agent_version": "linpersist-0.1.0",
  "agent_commit": "abc1234",
  "module": "cron",
  "site_class": "cron.d",
  "mitre": ["T1053.003"],
  "locus": "/etc/cron.d/backup",
  "owner_uid": 0,
  "owner_gid": 0,
  "mode": "0644",
  "mtime": "2026-05-10T03:14:00Z",
  "size": 412,
  "content_sha256": "ab12...",
  "content_norm_sha256": "cd34...",
  "exec_target": "/opt/backup.sh",
  "exec_target_sha256": "ef56...",
  "exec_target_pkg_status": "orphan",
  "signals": ["non_package_path", "recent_mtime_7d"]
}
```
