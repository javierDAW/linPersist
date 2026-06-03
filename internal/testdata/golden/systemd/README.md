# Golden test fixtures: systemd

Per-file record granularity per ADR-0007. The runner mirrors the
other modules: it copies each case's `rootfs/` into a temp directory,
applies any `symlinks.txt` manifest, stamps mtimes to a fixed value,
then runs `systemd.Module.Collect` against that root.

`expected.ndjson` is bootstrapped with `go test -update
./internal/modules/systemd` once the rootfs is in place. Re-run with
`-update` whenever the canonical-form rules change.

## Canonical form rules

For every unit/timer/drop-in file:

- `content_sha256` is over the raw file bytes.
- `content_norm_sha256` is over the canonical form produced by
  `Normalize(raw)`, which:
  - joins backslash line continuations,
  - drops `#` and `;` full-line comments,
  - drops blank lines and trailing whitespace,
  - canonicalizes section names + order (`[Unit]` → type-specific →
    `[Install]` → others alphabetical),
  - canonicalizes key names + order (alphabetical case-insensitive,
    with the `Exec*=` family preserving source order at its
    alphabetical position),
  - sorts and deduplicates set-semantic key values (`Wants=`,
    `After=`, `Requires=`, …),
  - applies the empty-value reset idiom for both set-semantic keys
    and the `Exec*=` family,
  - preserves `ExecStart=` prefix characters (`@-:!+`) verbatim.
- `content_snippet` shows the first 256 chars of the canonical form.

See `docs/adr/0007-systemd-canonical-form.md`.

## Cases

### `unit_basic_service`

`/etc/systemd/system/borg-backup.service`. Plain `.service` with
`[Unit]`, `[Service]`, `[Install]` sections. One absolute
`ExecStart=/usr/local/bin/borg-backup`. No module-specific signals
expected.

### `unit_line_continuation`

`/etc/systemd/system/long-cmd.service` whose `ExecStart=` spans four
physical lines via backslash continuations. The canonical form joins
them into a single logical entry; `content_sha256` differs from
`content_norm_sha256` because of the join.

### `dropin_overrides_exec`

Base unit `/etc/systemd/system/nginx.service` plus a drop-in at
`/etc/systemd/system/nginx.service.d/override.conf` that adds an
`ExecStartPost=/opt/payload/beacon.sh` line. Two records emitted:
the base unit (no `systemd_dropin` signal) and the drop-in (with the
`systemd_dropin` signal). This is the textbook offensive pattern of
appending behavior to a legitimate unit via the drop-in mechanism
without touching the base file.

### `template_instance_unit`

`/etc/systemd/system/worker@.service`. Template form (the basename
ends in `@.service`). One record emitted with the
`systemd_template_unit` signal. The agent does NOT enumerate runtime
instances (`worker@1.service`, `worker@2.service`) -- those are
managed state, not files on disk.

### `user_unit_alice`

`/home/alice/.config/systemd/user/poll.service`. User-mode locus.
One record with the `systemd_user_unit` signal. `ExecStart=` is
absolute and lives in `/home/alice/bin/`, which the host does not
package-own; if dpkg/rpm provenance were wired the
`non_package_path` signal would fire too (v0.2.0 work).

### `external_wants_symlink`

`/etc/systemd/system/multi-user.target.wants/poll.service` is a
symlink to `/tmp/.cache/poll.service`. The walker treats the symlink
itself as the locus, reads the target's content for hashing, and
emits with the `systemd_external_unit_symlink` signal. The symlink is
created at test time via `symlinks.txt` rather than checked into git;
the payload file itself is committed under `rootfs/tmp/.cache/`.

### `timer_basic`

Two files:

- `/etc/systemd/system/backup.timer` (`OnCalendar=*-*-* 03:14:00`,
  `Unit=backup.service`).
- `/etc/systemd/system/backup.service` (the unit the timer activates).

Two records, both at the same locus prefix; backend correlates the
pair by the timer's `Unit=` directive.

### `unit_malformed`

`/etc/systemd/system/broken.service` carrying a key outside any
section, an unclosed `[BadSection`, a line without `=`, and an empty
key. The module emits one record with multiple `PARSE_ERROR` entries
in `errors[]` and a canonical form that contains only the parseable
content (the `[Service]` and `[Install]` sections plus the valid
keys). Verifies the "never panic on malformed input" robustness
contract.

### `path_trigger_and_onfailure`

A `.path` unit (`watcher.path`) arming `PathModified=/tmp/.trigger` with an
explicit `Unit=payload.service`, and a service (`healthcheck.service`) with
`OnFailure=payload.service` plus `Wants=`/`Requires=` deps. Exercises the
relationship-edge extraction (duel-2 backlog #4): `relations` captures the
trigger→payload edges and `systemd_path_trigger` / `systemd_has_onfailure`
mark the trigger arms for backend/Q12 correlation. NOT a Q7 verdict — the
payload service is flagged on its own by the exec/orphan rules.
