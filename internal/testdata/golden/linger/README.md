# Golden test fixtures: linger

Each subdirectory under this folder is one test case. Layout:

```
<case>/
├── rootfs/                                # filesystem tree the module reads
│   └── var/lib/systemd/linger/<user>      # one empty marker file per linger-enabled user
└── expected.ndjson                        # frozen output (generated via -update, reviewed, committed)
```

The `systemd.linger` artifact is a zero-byte marker file under
`/var/lib/systemd/linger/`. Its mere presence enables
`systemd --user` units for `<user>` to keep running across logout
sessions. The username is the only semantic content; the file body
is empty by contract.

## Test runner

See `internal/modules/linger/linger_test.go`. Identical contract to
`cron`'s runner:

1. Copies `rootfs/` into `t.TempDir()`.
2. `chmod 0755` directories and `0644` files (the systemd default
   for these marker files).
3. `chtimes` every regular file to `2026-04-01T00:00:00Z`
   (`fixedMtime`) — ~6 weeks before `fixedNow` (`2026-05-12T10:00:00Z`)
   so neither `recent_mtime_7d` nor `recent_mtime_30d` fires for
   stock fixtures.
4. Constructs the module with `New(Options{Root, Now})` and
   `Collect`s synchronously.
5. Redacts volatile fields (`owner_uid`/`owner_gid` to 0, drops
   `ctime`/`atime` and the derived `non_root_owner` signal), sorts
   by `(locus, content_norm_sha256)`, marshals to NDJSON.
6. Compares byte-for-byte. With `-update`, regenerates instead.

## Cases

### `root_only`

Single marker file `/var/lib/systemd/linger/root`. Baseline case:
linger is enabled for `root`, which has no persistence value
(root sessions never time out the way regular users do), so the
module-specific signal `systemd_linger_non_root` must NOT fire.

Expected: **1 record**, no module-specific signals.

### `non_root_user_alice`

Single marker file `/var/lib/systemd/linger/alice`. The canonical
positive case the module exists to surface: a non-root user with
linger enabled, whose `systemd --user` units survive logout.

Expected: **1 record**, signal `systemd_linger_non_root` fires.

### `multiple_users`

Three marker files: `root`, `alice`, `service-account`. Verifies
per-user granularity: each file emits its own record, two of which
carry the module-specific signal (alice and service-account); root
does not.

Expected: **3 records**, two with `systemd_linger_non_root`.

### `with_subdir`

`/var/lib/systemd/linger/alice` plus a stray subdirectory
`/var/lib/systemd/linger/somedir/`. systemd does not create
subdirectories under this path; an attacker (or a misuse) might.
The module must skip directories at the top level rather than
descend into them. Verifies the `if e.IsDir() { continue }` guard.

Expected: **1 record** (alice only).

### `numeric_username`

`/var/lib/systemd/linger/1001`. Purely-numeric usernames are
allowed by Linux passwd databases (especially with NSS modules
backing onto LDAP or AD). The module must not special-case the
shape of the username — anything that is not literally `"root"`
fires the signal.

Expected: **1 record**, signal `systemd_linger_non_root`.

## Notes on volatile fields

Same redactions as the `cron` module: `owner_uid`/`owner_gid`
forced to 0 (the test runner cannot chown root), `ctime` dropped
(`os.Chtimes` does not control it), `atime` dropped (volatile),
`non_root_owner` signal dropped because it is derived from the
live uid the runner could not set.
