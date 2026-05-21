# Golden test fixtures: tmpfiles

Each subdirectory under this folder is one test case. Layout:

```
<case>/
├── rootfs/                                  # filesystem tree the module reads
│   ├── etc/tmpfiles.d/*.conf                # admin overrides (highest precedence)
│   ├── run/tmpfiles.d/*.conf                # runtime drop-ins
│   └── usr/lib/tmpfiles.d/*.conf            # vendor-shipped baseline
└── expected.ndjson                          # frozen output
```

The `systemd.tmpfiles` site_class emits **one record per directive
line** (per `tmpfiles.d(5)`). A file with three directives produces
three records; a file with only comments emits a single envelope
record with `empty_file`.

## Calibration under test (ADR-0014)

The module-specific signal `tmpfiles_creates_under_tmp` fires when
ALL of the following hold:

1. Type letter starts with `f`, `F` or `w` (file create / write).
   `d`, `D`, `L`, `C`, `c`, `b`, `p` (dirs, links, copies, dev, fifo)
   do NOT fire.
2. Path contains NO tmpfiles.d glob / template metacharacter
   (`*`, `?`, `%`, `[`, `]`).
3. Path is NOT in the X11 socket-dir allow-list
   (`/tmp/.X11-unix`, `/tmp/.ICE-unix`, `/tmp/.XIM-unix`,
   `/tmp/.font-unix`, `/tmp/.Test-unix`).
4. Path is prefixed by `/tmp/`, `/var/tmp/`, `/dev/shm/`, or
   `/run/shm/`.

Each case below isolates one or more of these axes.

## Test runner

See `internal/modules/tmpfiles/tmpfiles_test.go`. Identical contract
to the `cron`, `linger`, `sysusers` runners: copy `rootfs/` into
`t.TempDir()`, normalize perms (`0755` dirs, `0644` files), stamp
mtimes to `2026-04-01T00:00:00Z`, construct with
`New(Options{Root, Now})`, collect, redact volatile fields, sort by
`(locus, content_norm_sha256)`, encode NDJSON, compare byte-for-byte.

## Cases

### `etc_tmpfiles_happy`

Stock distro `legacy.conf`: directory under `/var/lib`, journal
directory, wtmp file under `/var/log`. None of these match the
calibrated trigger (the f-directive targets `/var/log/wtmp`, not a
tmp-class path). The LFA baseline.

Expected: **3 records**, no module-specific signals.

### `creates_payload_at_boot`

The canonical implant fingerprint: `f /tmp/.cache/payload 0755 root root - /opt/.implant/agent`.
Type `f`, path `/tmp/.cache/payload` (fixed, no glob, not in X11
allow-list, under `/tmp/`). The implant restores its payload at
every boot via systemd-tmpfiles. This is what the v0.3.0-coverage
detection rule `tmpfiles_creates_payload_at_boot` (critical) keys on.

Expected: **1 record**, signal `tmpfiles_creates_under_tmp` fires.

### `x11_allowlist_baseline`

The five X11 socket directories declared by `xorg-libs` across every
distro that ships X11. Type `d`, paths in the X11 allow-list. Two
gates reject them independently (type letter AND allow-list). The
signal must NOT fire on any.

Expected: **5 records**, no module-specific signals.

### `glob_template_skipped`

Three globbed / templated paths: `/tmp/systemd-private-%b-*` (boot-
id template, systemd's own sandbox), `/var/tmp/sess[0-9].id`
(character class), `/tmp/queue-?.tmp` (single-char wildcard). Each
contains a tmpfiles.d metacharacter; the calibration must reject
them. The v1 implementation flagged 108 false positives across the
75-host lab fleet because it lacked this filter.

Expected: **3 records**, no module-specific signals.

### `non_create_types`

Three directives targeting tmp-class paths but with non-create type
letters: `d /tmp/scratch`, `L /tmp/link`, `C /tmp/copy`. None fire
the signal; the type-letter gate rejects them all. Vendor-shipped
patterns frequently use `d` for scratch dirs under `/tmp`.

Expected: **3 records**, no module-specific signals.

### `multi_loci`

One directive in each of the three tmpfiles.d directories the
module walks: `/etc/tmpfiles.d/admin.conf`, `/usr/lib/tmpfiles.d/vendor.conf`,
`/run/tmpfiles.d/runtime.conf`. Verifies all three loci are
processed and recorded with the correct `locus` field.

Expected: **3 records**, each with the appropriate `locus`, no
module-specific signals.

### `empty_file_envelope`

`only_comments.conf` with only `#`-prefixed lines. Exercises the
envelope path: one record with the `empty_file` signal and no
content hashes.

Expected: **1 record**, signal `empty_file`.

## Notes on volatile fields

Same redactions as the other modules.
