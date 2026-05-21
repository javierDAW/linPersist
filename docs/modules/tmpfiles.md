# Module: `tmpfiles`

| site_class          | MITRE       | granularity   | docs                |
| ------------------- | ----------- | ------------- | ------------------- |
| `systemd.tmpfiles`  | `T1543.002` | per-directive | this doc, ADR-0014  |

The module collects systemd-tmpfiles configuration files. The
`systemd-tmpfiles` service runs at boot (and on demand) and
applies the directives in these files: creating, modifying,
copying, or removing files / directories / symlinks / FIFOs
according to a declarative spec.

A directive that **creates an executable under a tmp-class
directory at every boot** is a known persistence pattern: the
dropped binary lives across reboots because tmpfiles restores
it on every boot, even if a defender deletes it manually.
The module is read-only, side-effect-free, and emits one
record per non-comment, non-blank line.

## Loci

The walker scans, in this order:

- `/etc/tmpfiles.d/` -- admin overrides (highest precedence at
  runtime).
- `/run/tmpfiles.d/` -- runtime drop-ins.
- `/usr/lib/tmpfiles.d/` -- vendor-shipped baseline.

Only files with extension `.conf` are processed; files with a
leading `.` are skipped (dotfile filter). Files larger than
`MaxFileSize` (default 256 KiB) emit a single envelope record
with `errors[0]={field:content_sha256, code:SIZE_LIMIT}`.

## Format

Per `tmpfiles.d(5)`, each non-comment, non-blank line is:

```
type path mode user group age argument
```

Fields beyond `path` may be `-` to inherit the systemd default.
Whitespace between fields is collapsed by the canonical form;
whitespace **inside** double-quoted segments (the `argument`
field for `w`/`w+` directives) is preserved verbatim. Line
continuations are NOT joined (tmpfiles.d does not support
backslash continuations per the manpage).

## Canonical form (content_norm_sha256)

`canonicalDirective(raw)` applies:

1. `TrimSpace` leading and trailing whitespace.
2. Collapse runs of space / tab outside quoted segments to a
   single space.
3. Preserve double-quoted segments verbatim (whitespace inside
   stays as-is).

The pipeline is idempotent and order-stable; two semantically
equivalent directives stack to the same `content_norm_sha256`
regardless of source indentation.

## ExecTarget category

`touch-this-path-but-no-exec` (ADR-0014). tmpfiles does NOT
invoke a binary -- it manipulates a path. Mapping `fields[1]`
(the target path) to `ExecTarget` was the v1 implementation
and it polluted Q9 (`exec_targets_in_tmp`) with 341 baseline
rows across the 75-host lab fleet: X11 socket dirs,
systemd-private sandbox dirs, dnf locks, etc. The current
implementation explicitly leaves `ExecTarget` empty; the
target path remains visible via `content_snippet`.

## Signals

Module-specific:

| signal                          | fires when                                                              |
| ------------------------------- | ----------------------------------------------------------------------- |
| `tmpfiles_creates_under_tmp`    | type letter `f`/`F`/`w` AND path under `/tmp/`, `/var/tmp/`, `/dev/shm/`, `/run/shm/` AND path is NOT in the X11 socket allow-list AND path contains no glob metacharacters (`*`, `?`, `%`, `[`, `]`) |
| `empty_file`                    | source contains only comments / blank lines (envelope record)            |

Inherited from `core`:

| signal              | fires when                              |
| ------------------- | --------------------------------------- |
| `recent_mtime_7d`   | source file mtime within the last 7 days |
| `recent_mtime_30d`  | source file mtime within 7-30 days       |
| `world_writable`    | source file has mode bit `0o002`        |
| `non_root_owner`    | source under a system path, uid != 0     |

### Calibration history (ADR-0014, v0.3.0-coverage)

The v1 signal flagged any create-class type letter targeting
any tmp-class path. That over-fired by 108 hits across the
75-host lab fleet:

- **Directory type letters (`d`, `D`)** match X11 socket dirs
  (`/tmp/.X11-unix`), systemd-private sandbox roots
  (`/tmp/systemd-private-*`), dnf lock dirs (`/var/tmp/dnf-*`).
- **Symlink / copy type letters (`L`, `C`, `c`, `b`, `p`)**
  cover vendor-baseline patterns that touch but do not implant.
- **Glob / template paths** (`%b`, `%I`, `*`, `?`, `[...]`)
  are templated by design; an attacker plants a fixed path
  instead.
- **The X11 socket-dir allow-list** (`/tmp/.X11-unix`,
  `/tmp/.ICE-unix`, `/tmp/.XIM-unix`, `/tmp/.font-unix`,
  `/tmp/.Test-unix`) is baseline-of-baseline: any host with
  xorg libs has them, including containers that link X11
  transitively.

The refined gate (type letter `f`/`F`/`w` + path under
tmp-class + no glob + not in X11 allow-list) produces ZERO
false positives on the lab fleet's stock vendor configs while
still catching the implant pattern.

## Known false-positive patterns

- Operator-curated `f /var/log/<custom>` directives that
  preallocate log files at boot. NOT flagged by the signal
  (path is not under tmp-class) but visible in Q1 / Q3 stacking
  if the directive is unique to one host.
- Hand-rolled developer scripts dropped in `/etc/tmpfiles.d/`
  on workstations. These may legitimately match the signal;
  pair with role-tag triage (`role:dev`, v0.3.1-fleet) or with
  cross-host LFA: a tmpfiles directive that fires the signal
  AND appears on a single host is the implant fingerprint.

## What this module deliberately does NOT do

- Execute `systemd-tmpfiles --dry-run` or any external binary.
- Resolve `%`-templated paths (`%b` boot-id, `%H` hostname,
  `%t` runtime dir). The agent emits the raw template; the
  backend can resolve if needed.
- Detect filesystem state (does the target file exist? is it
  the byte sequence the argument suggests?). The agent only
  reads tmpfiles.d itself.
- Cross-correlate with `/etc/passwd` for the user / group
  fields. Stacking by `content_norm_sha256` handles the LFA
  case.

## References

- `tmpfiles.d(5)`, `systemd-tmpfiles(8)`.
- MITRE ATT&CK `T1543.002` (parent; ATT&CK has no dedicated
  sub-technique for tmpfiles-based persistence as of May 2026).
- ADR-0014 (systemd structural-family modules), including the
  ExecTarget category and the signal calibration history.
