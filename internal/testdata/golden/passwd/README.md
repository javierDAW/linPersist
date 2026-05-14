# Golden test fixtures: passwd

Layout convention as the other modules. Same fixedMtime / fixedNow
reference timestamps.

## Canonical form rules

| site_class | canonical | notes |
|---|---|---|
| `passwd.user` | the source line verbatim | uid=0 OR shell !∈ {nologin, false} filter applied |
| `passwd.shadow` | `<user>:<status>:<lastchg>:<min>:<max>:<warn>:<inactive>:<expire>:<flag>` | hash replaced by enum (set/locked/disabled/empty/unknown). ADR-0005. |
| `passwd.group` | `<name>:<pwfield>:<gid>:<members-sorted-comma-joined>` | empty members preserved as empty. |
| `passwd.gshadow` | `<name>:<status>:<admins-sorted>:<members-sorted>` | hash replaced by enum per ADR-0005. |

## Signal rules

- `passwd_uid_zero`: fires on passwd.user records where uid == 0 AND
  username != "root".
- `passwd_no_password`: fires on passwd.shadow records where the
  resolved status is "empty".
- Standard core signals apply: `exec_target_orphan` fires on
  passwd.user when the shell path does not exist on disk;
  `interpreter_in_tmp` fires when the shell lives under /tmp etc.

## Cases

### `passwd_user_with_uid_zero`

`/etc/passwd` carrying root, daemon (filtered: shell=nologin),
mail (passes: shell=/bin/sh), and `ali` (uid=0, anomalous).
Expected: 3 records (root, mail, ali). The ali record fires
`passwd_uid_zero`.

### `shadow_status_variants`

`/etc/passwd` + `/etc/shadow` together. Three accounts (root,
alice, emptypw) exercising the three observed status values:
- `root`: `$y$...` → status=set
- `alice`: `!$y$...` → status=locked
- `emptypw`: empty field → status=empty (fires
  `passwd_no_password`)

Expected: 3 passwd.user records + 3 passwd.shadow records = 6.

### `group_and_gshadow`

`/etc/group` + `/etc/gshadow` together. Demonstrates member
sorting in canonical forms: `wheel:x:10:carol,bob,alice` and
`docker:x:999:bob,alice` both have unsorted member lists in the
source. Their `content_norm_sha256` is computed over the sorted
form; their `content_sha256` is computed over the raw source
line (so byte-level changes still produce different `content_sha256`
even when the canonical stacks identically).

Expected: 3 passwd.group records + 3 passwd.gshadow records = 6.
