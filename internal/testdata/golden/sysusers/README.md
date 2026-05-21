# Golden test fixtures: sysusers

Each subdirectory under this folder is one test case. Layout:

```
<case>/
├── rootfs/                                 # filesystem tree the module reads
│   ├── etc/sysusers.d/*.conf               # primary locus
│   └── usr/lib/sysusers.d/*.conf           # secondary (vendor) locus
└── expected.ndjson                         # frozen output (generated via -update)
```

The `systemd.sysusers` site_class emits **one record per directive
line** (per `sysusers.d(5)`), so a file with three directives produces
three records that differ in `content_norm_sha256` and `content_snippet`
but share `locus`. A file with only comments / blank lines emits a
single envelope record carrying the `empty_file` signal.

## Test runner

See `internal/modules/sysusers/sysusers_test.go`. Same contract as
the `cron` and `linger` runners: copy `rootfs/` into `t.TempDir()`,
`chmod 0644` regular files and `0755` directories, `chtimes` to
`2026-04-01T00:00:00Z`, construct the module with
`New(Options{Root, Now})`, collect, redact volatile fields, sort by
`(locus, content_norm_sha256)`, encode NDJSON, compare byte-for-byte.

## Cases

### `etc_sysusers_happy`

Stock distro `basic.conf` with two `u` directives (systemd service
accounts with non-zero uids) and one `g` directive. None of these
fires the module-specific signal `sysusers_uid_zero`. This is the
LFA baseline: hundreds of hosts ship this exact file and the records
must stack to a single Q1 / Q3 row.

Expected: **3 records**, no module-specific signals.

### `uid_zero_implant`

The canonical implant fingerprint this module exists to surface:
`u backdoor 0 "System Maintenance" /root /bin/bash`. Type `u`, uid
`0`, name not `root` -- this is a second root account declared via
sysusers.d, which (unlike a direct `/etc/passwd` edit) bypasses the
`passwd` module's view of `/etc/passwd` source bytes.

Expected: **1 record**, signal `sysusers_uid_zero` fires.

### `quoted_gecos`

`u svcacct 999 "Service Account, Inc." /var/lib/svcacct /sbin/nologin`.
Tests the parser's handling of double-quoted segments: whitespace
INSIDE the quoted gecos field is preserved verbatim, whitespace
OUTSIDE is collapsed to a single space. The directive itself is
benign (uid 999 != 0) so no module-specific signal fires.

Expected: **1 record**, no module-specific signals.

### `comments_and_blanks`

`with_comments.conf` has a mix of comments, blank lines, indented
comments, and two real directives with irregular whitespace. The
parser must:

- Skip lines starting with `#` (including indented `#`).
- Skip blank lines.
- Collapse whitespace between fields of a real directive.

Two directives (`u alice 1001 ...` and `u bob 1002 ...`) survive
the filter. Their `content_norm_sha256` must match the form a
similar host would produce regardless of comment density -- this
is the comment-density-independence guarantee for LFA.

Expected: **2 records**, no module-specific signals.

### `empty_file_envelope`

`only_comments.conf` contains only `#`-prefixed lines. Exercises the
envelope path in `processFile`: when the parser sees zero non-comment
non-blank lines, it must still emit one record so the analyst sees
the file existed in the dataset. That record carries the
`empty_file` signal.

Expected: **1 record**, signal `empty_file`.

### `usr_lib_alt_loci`

A directive file under `/usr/lib/sysusers.d/` (vendor-shipped path)
rather than `/etc/sysusers.d/`. Verifies both loci are walked.
Records emitted with `locus=/usr/lib/sysusers.d/vendor.conf`.

Expected: **2 records** (one `u`, one `g`), no module-specific
signals.

### `non_conf_skip`

Two negative cases in one fixture: a file with the wrong extension
(`readme.txt`) containing a uid-0-non-root directive that LOOKS like
an implant, and a dotfile (`.hidden.conf`). The walker must skip
both -- the extension filter rejects `.txt`, the dotfile filter
rejects names starting with `.`. The implant-looking directive must
NOT surface in the records.

Expected: **0 records** (envelope-empty case: no walkable files at all).

## Notes on volatile fields

Same redactions as `cron` and `linger`: `owner_uid` / `owner_gid`
forced to 0 (cannot chown root in tests), `ctime` dropped
(`os.Chtimes` cannot set it), `atime` dropped (volatile),
`non_root_owner` signal dropped (it would be inconsistent with the
forced uid=0).
