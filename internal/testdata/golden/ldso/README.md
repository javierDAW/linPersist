# Golden test fixtures: ldso

Each subdirectory under this folder is one test case for the `ldso`
module. Layout mirrors `internal/testdata/golden/cron/`:

```
<case>/
├── rootfs/                    # filesystem tree the module reads
│   └── etc/...                # mirrors absolute paths under a synthetic root
└── expected.ndjson            # frozen output (regenerate with -update, review, commit)
```

The test runner:

1. Copies `rootfs/` into a fresh `t.TempDir()`.
2. Normalizes permissions: 0644 for regular files, 0755 for
   directories. There are no executable scripts among ldso loci so the
   periodic-style chmod from the cron runner does not apply.
3. `chtimes` every file and directory to the project's reference fixed
   time (`2026-04-01T00:00:00Z`), six weeks before the reference
   `fixedNow` so neither `recent_mtime_*` nor `recent_target_mtime_7d`
   fire by default.
4. Constructs the `ldso` module with `Root = tempdir`,
   `Now = func() time.Time { return fixedNow }`, and the default
   1 MiB max-file-size.
5. Invokes `Collect`, captures every `Record`, redacts volatile envelope
   fields (uid/gid forced to 0, ctime/atime dropped, `non_root_owner`
   signal dropped), sorts by `(locus, content_norm_sha256, exec_target)`,
   marshals to NDJSON and compares against `expected.ndjson` byte for
   byte. `-update` overwrites `expected.ndjson` instead of failing.

## Cases

### `preload_simple_lib`

A single `/etc/ld.so.preload` line pointing to an existing library at
`/usr/lib/libdebug.so` (regular file, 0644, deterministic ASCII
content).

Expected records: **1**, `site_class=ldso.preload`,
`locus=/etc/ld.so.preload`, `exec_target=/usr/lib/libdebug.so`,
`exec_target_sha256` populated, signals `[ld_preload_set]`. No
orphan/in-tmp/recent signals.

### `preload_orphan_tmp_multi`

A single line `/lib/legit.so /tmp/evil.so` exercising the multi-path
split (glibc honors that form even though `man 8 ld.so` documents one
path per line). One target exists in the fixture, the other does not
and lives under `/tmp/`.

Expected records: **2**, both `site_class=ldso.preload`,
`locus=/etc/ld.so.preload`. They share `content_sha256` (same raw
line) but differ in `content_norm_sha256`. Signals:

| exec_target      | signals                                                              |
|------------------|----------------------------------------------------------------------|
| `/lib/legit.so`  | `[ld_preload_set]`                                                   |
| `/tmp/evil.so`   | `[ld_preload_set, interpreter_in_tmp, exec_target_orphan]`           |

### `conf_with_include`

`/etc/ld.so.conf` with a leading comment, an `include
/etc/ld.so.conf.d/*.conf` directive and one bare search-path line
`/usr/local/lib`. The directive's `exec_target` contains glob
metacharacters; orphan detection is skipped for glob targets.

Expected records: **2**, `site_class=ldso.conf`,
`locus=/etc/ld.so.conf`. Neither fires `exec_target_orphan` (glob for
the include, directory present for the search path) nor
`interpreter_in_tmp`. Signal slice is empty (`omitempty` so the field
is absent from the JSON).

### `confd_drop_in`

A drop-in file `/etc/ld.so.conf.d/x86_64-linux-gnu.conf` with one
comment and three multiarch search-path lines.

Expected records: **3**, `site_class=ldso.confd`,
`locus=/etc/ld.so.conf.d/x86_64-linux-gnu.conf`. All targets are
present as directories in the fixture; no signals.

## Test runner notes on volatile fields

Same conventions as the cron runner:

- `mode`: applied by the runner, not whatever the filesystem returned
  on the developer's box (0644 for files, 0755 for directories).
- `mtime`: `chtimes`-stamped to `2026-04-01T00:00:00Z`. The runner
  drops `ctime` and `atime` from comparison.
- `owner_uid` / `owner_gid`: rewritten to `0` in captured records
  before comparing, matching the production reality that /etc/* is
  owned by uid 0. The `non_root_owner` signal is stripped from
  captured records because it derives from the live uid.
