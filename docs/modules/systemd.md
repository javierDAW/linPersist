# Module: `systemd`

| site_class      | MITRE       | granularity | docs              |
| --------------- | ----------- | ----------- | ----------------- |
| `systemd.unit`  | `T1543.002` | per-file    | this doc, ADR-0007 |
| `systemd.timer` | `T1053.006` | per-file    | this doc, ADR-0007 |

The module collects systemd unit and timer files (plus their drop-in
fragments and external-symlink enablement points) from system- and
user-mode loci. It is read-only, side-effect-free, and emits one
record per file. See `docs/adr/0007-systemd-canonical-form.md` for the
binding canonical-form and granularity decisions.

## Loci

System-mode (every record):

- `/etc/systemd/system/`
- `/usr/lib/systemd/system/`
- `/lib/systemd/system/`
- `/run/systemd/system/`

User-mode (records carry the `systemd_user_unit` signal):

- `/etc/systemd/user/`
- `/usr/lib/systemd/user/`
- `/root/.config/systemd/user/`
- `/home/<user>/.config/systemd/user/` (walked per `/home/<user>`)

Inside each locus the walker recognizes three sub-directory shapes:

- `<unit>.<ext>.d/` -- drop-in directory. The module recurses one
  level deep and emits each `*.conf` fragment as its own record with
  the `systemd_dropin` signal. The base unit and its drop-ins are
  correlated by the backend on locus prefix.
- `<unit>.<ext>.wants/`, `<unit>.<ext>.requires/`,
  `<unit>.<ext>.wants.d/`, `<unit>.<ext>.requires.d/` -- enablement
  directories. The walker inspects each entry and treats symlinks
  separately: a symlink whose target resolves inside any walked locus
  is skipped (the target's own walk pass emits it); a symlink whose
  target resolves outside the walked loci emits a record with the
  `systemd_external_unit_symlink` signal.
- Anything else is skipped.

## Extensions

In scope: `.service`, `.socket`, `.path`, `.mount`, `.automount`,
`.swap`, `.target`, `.timer`.

Explicitly excluded for v0.1.0 (ADR-0007 §4):

- `.slice` and `.scope` -- noisy in interactive sessions, rarely a
  persistence vector. Re-evaluate in v0.2.0.
- `.device`, `.snapshot`, `.busname` -- kernel-managed or vestigial.

## Canonical form (content_norm_sha256)

`Normalize(raw)` applies, in order:

1. Join backslash line continuations.
2. Drop `#` and `;` full-line comments.
3. Drop blank lines and trailing whitespace.
4. Canonicalize section names (`[unit]` -> `[Unit]`, …) for the
   known systemd section types.
5. Reorder sections: `[Unit]` -> type-specific
   (`[Service]`/`[Socket]`/…/`[Timer]`) -> `[Install]` -> any other
   section in alphabetical order.
6. Reorder keys within each section alphabetically (case-insensitive
   on the key). The `Exec*=` family (`ExecStart`, `ExecStartPre`,
   `ExecStartPost`, `ExecStop`, `ExecStopPost`, `ExecReload`,
   `ExecCondition`) preserves source order at its alphabetical
   position.
7. Canonicalize key capitalization for ~50 well-known keys; others
   keep their on-disk capitalization.
8. For set-semantic keys (`Wants=`, `After=`, `Before=`, `Requires=`,
   `Requisite=`, `BindsTo=`, `PartOf=`, `Conflicts=`, `OnFailure=`,
   `OnSuccess=`, `PropagatesReloadTo=`, `ReloadPropagatedFrom=`,
   `JoinsNamespaceOf=`, `Also=`, `WantedBy=`, `RequiredBy=`,
   `Upholds=`, `UpheldBy=`) accumulate all values across multiple
   lines, honor the empty-value reset idiom, then sort and
   deduplicate the final token set; emit a single line.
9. For `Exec*=` family multi-line entries, honor the empty-value
   reset; preserve source order of survivors; preserve `@-:!+`
   prefixes verbatim.
10. All other multi-line same-key cases preserve source order
    verbatim (no deduplication, no last-wins resolution).

The pipeline is idempotent: `Normalize(Normalize(x)) == Normalize(x)`.

## exec_target

The module captures the first surviving `ExecStart=` directive after
empty-reset resolution:

- Strip leading prefix characters (`@`, `-`, `:`, `!`, `+`) and any
  whitespace.
- Take `argv[0]` (the first whitespace-separated token).
- If absolute (`/...`) -- `exec_target` is that path.
- If relative -- search the documented systemd default PATH
  (`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`,
  per `systemd.exec(5)`). On a hit, `exec_target` is the absolute
  path of the hit. On a miss, `exec_target` is left empty and the
  record carries `systemd_exec_unresolved`.

When `exec_target` is set and the file exists, `exec_target_sha256`
is filled by streaming the binary through SHA-256.

## Signals

Module-specific:

| signal                              | fires when |
| ----------------------------------- | ---------- |
| `systemd_user_unit`                 | locus is under a user-mode locus |
| `systemd_dropin`                    | locus is `*.d/*.conf` |
| `systemd_template_unit`             | filename matches `<stem>@.<ext>` |
| `systemd_external_unit_symlink`    | symlink resolves outside walked loci |
| `systemd_multi_execstart`          | more than one surviving `ExecStart=` |
| `systemd_exec_unresolved`          | relative `ExecStart=` not in default PATH |
| `systemd_install_alias_external`   | `[Install] Alias=` lists an absolute path outside walked loci |

Inherited from `core`:

| signal                       | fires when |
| ---------------------------- | ---------- |
| `recent_mtime_7d`           | locus file mtime within last 7 days |
| `recent_mtime_30d`          | locus file mtime within 7-30 days |
| `recent_target_mtime_7d`    | `exec_target` mtime within last 7 days |
| `world_writable`            | locus has mode bit `0o002` |
| `non_root_owner`            | locus under a system path, uid != 0 |
| `exec_target_orphan`        | `exec_target` does not exist on disk |
| `interpreter_in_tmp`        | `exec_target` lives under `/tmp`, `/var/tmp`, `/dev/shm`, `/run/shm` |
| `shell_indirect`            | `exec_target` is a shell or scripting interpreter |
| `unqualified_exec_target`   | `exec_target` is a bare command (no leading slash) |

## Known false-positive patterns

- `systemd_multi_execstart` fires on every `Type=oneshot` unit that
  chains setup commands. Legitimate config-mgmt patterns
  (cloud-init, kubelet pre-pull) hit this regularly. Pair with
  `systemd_user_unit` or `non_package_path` for triage.
- `systemd_external_unit_symlink` will fire on operator-curated
  systems that keep payloads under `/opt/<vendor>/` and symlink them
  from `/etc/systemd/system/*.wants/`. Expected on many appliances.
- `systemd_user_unit` on a host with `loginctl enable-linger` set is
  not a verdict; user units are a legitimate mechanism.

## What this module deliberately does NOT do

- Call `systemctl` / `systemd-analyze` or any external binary.
- Read the journal.
- Resolve dependency graphs (`After=`, `Wants=` → other units).
- Detect enabled / active / failed state.
- Parse `Environment=` to discover embedded commands.
- Merge drop-ins with their base unit in memory. The agent emits each
  fragment separately; the backend can JOIN on locus prefix if it
  wants the resolved view.

## References

- `systemd.unit(5)`, `systemd.service(5)`, `systemd.timer(5)`,
  `systemd.exec(5)`, `systemd.syntax(5)`.
- MITRE ATT&CK `T1543.002` (systemd service), `T1053.006` (systemd
  timer).
- ADR-0007 (this module's canonical-form decisions).
- ADR-0002 (cron module's granularity decision, contrasted for
  reference).
