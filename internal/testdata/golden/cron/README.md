# Golden test fixtures: cron

Each subdirectory under this folder is one test case. Layout:

```
<case>/
├── rootfs/                    # filesystem tree the module reads
│   └── etc/...                # mirrors absolute paths under a synthetic root
└── expected.ndjson            # frozen output (generated via -update, reviewed, committed)
```

The test runner:

1. Copies `rootfs/` into a fresh `t.TempDir()`.
2. `chtimes` every regular file to a deterministic timestamp
   (`2026-05-12T10:00:00Z`) so signals like `recent_mtime_7d` evaluate
   reproducibly given the injected `Now()`.
3. Constructs the `cron` module with `Root = tempdir`,
   `Now = func() time.Time { return fixedTime }`,
   and a 1 MiB max-file-size.
4. Invokes `Collect`, captures every emitted `Record`, drops envelope
   fields populated by `main.go` (`schema_v`, `host_id`, `host_meta`,
   `collected_at`, `agent_version`, `agent_commit`), sorts the
   remaining records by `(locus, content_norm_sha256)`, marshals to
   NDJSON.
5. Compares against `expected.ndjson` byte-for-byte. On mismatch,
   prints a unified diff. With `-update`, overwrites `expected.ndjson`
   instead of failing.

## Cases

### `etc_crontab_happy`

Stock Debian-flavored `/etc/crontab` with header comments, three
variable assignments (`SHELL`, `PATH`, `MAILTO`), two scheduled
entries running `run-parts`, and a `@reboot` entry calling
`/usr/local/sbin/boot-hook.sh`.

Expected records: **6**, all `module=cron`, `site_class=cron.d`,
`locus=/etc/crontab`.

| # | Kind                                            | exec_target                       | Notable signals                                       |
|---|-------------------------------------------------|-----------------------------------|-------------------------------------------------------|
| 1 | var assignment `SHELL=/bin/sh`                  | —                                 | `cron_var_assignment`                                 |
| 2 | var assignment `PATH=...`                       | —                                 | `cron_var_assignment`                                 |
| 3 | var assignment `MAILTO=root`                    | —                                 | `cron_var_assignment`                                 |
| 4 | entry `17 * * * * root cd / && run-parts...`    | `cd`                              | `unqualified_exec_target`                             |
| 5 | entry `25 6 * * * root test -x ...`             | `test`                            | `unqualified_exec_target`                             |
| 6 | entry `@reboot root /usr/local/sbin/boot-hook.sh` | `/usr/local/sbin/boot-hook.sh`  | `at_reboot`, `exec_target_orphan`                     |

`content_norm_sha256` differs between the six records because each is
a distinct normalized line. `content_sha256` is computed over the
exact line bytes after CRLF stripping and trailing-space trimming.

### `etc_crond_oneliner`

A single `/etc/cron.d/backup` file with one comment and one schedule
line invoking `/opt/backup.sh`.

Expected records: **1**, `module=cron`, `site_class=cron.d`,
`locus=/etc/cron.d/backup`, `exec_target=/opt/backup.sh`, signal
`exec_target_orphan` (no `/opt/backup.sh` in rootfs).

### `cron_daily_script`

An executable script at `/etc/cron.daily/logrotate` (mode 0755) with
shebang and three lines.

Expected records: **1**, `module=cron`, `site_class=cron.periodic`,
`locus=/etc/cron.daily/logrotate`. No `exec_target` field (the locus
itself IS the executable; equivalence is `locus == exec_target`).
`content_norm_sha256` is computed over the raw script body — the
`cron.periodic` site_class does NOT apply crontab-style normalization
because the file is a script, not a crontab. Mode 0755, owner uid=0
(set by chown in the runner).

## Test runner notes on volatile fields

Three Record fields have ambient values that cannot be reproduced
across machines without privileges, so the runner handles them
explicitly before comparing against `expected.ndjson`:

- **`mode`**: the runner applies `os.Chmod` to every file in the
  fixture rootfs immediately after copying. Permissions in
  `expected.ndjson` reflect what the runner chmodded, NOT whatever
  the filesystem returned on the developer's box. Default 0644,
  overridable by an optional per-case `modes.json` file listing
  `{"path/under/rootfs": octal}` (executable scripts under
  `cron.{hourly,daily,weekly,monthly}/` get 0755 by default).
- **`mtime` / `ctime` / `atime`**: `chtimes`-stamped to
  `2026-05-12T10:00:00Z` (the project's reference fixed time).
  `ctime` cannot be set by `os.Chtimes` so the runner drops it from
  comparison; this is documented in the module doc.
- **`owner_uid` / `owner_gid`**: cannot be set without root. The
  runner replaces both with `0` in captured records before comparing,
  matching the production reality that /etc/* artifacts are uid 0.
  The module code itself reports whatever `os.Stat` returns; the
  rewrite is purely test-side.
