# Golden test fixtures: polkit

Per-file record granularity over `*.rules` files in two locus
families:

- `/etc/polkit-1/rules.d/`         (admin / local rules)
- `/usr/share/polkit-1/rules.d/`   (distro-shipped rules)

Polkit's JS rule engine evaluates these in lexical order; later
files override earlier ones. The agent emits one record per file
regardless of priority because the backend correlates by basename.

Canonical form rules (`normalize.go`):

- `//` line comments and the rest of their line are dropped.
- `/* ... */` block comments are dropped, even across multiple lines.
- Blank/whitespace-only lines are dropped.
- Trailing whitespace per line is stripped.
- Comment-recognition is suppressed inside `"..."`, `'...'`, and
  `` `...` `` string literals so `"http://example.org"` stays
  content, not a comment.

`exec_target` is intentionally NOT populated: polkit rules evaluate
policy decisions, they do not execute binaries.

Two module-specific signals fire when the canonical form contains
the corresponding token literal:

- `polkit_admin_rule` — the file contains `addAdminRule(`. Polkit's
  addAdminRule callback decides which principals can authenticate as
  admin for a given action; a malicious rule granting admin to an
  attacker-controlled account is a textbook polkit backdoor.
- `polkit_yes_constant` — the file contains `polkit.Result.YES` or
  `Result.YES`. The constant is the polkit equivalent of "allow
  unconditionally"; informational on its own (legitimate rules use
  it for networkmanager / console actions) but high-precision when
  paired with `addAdminRule` or with a file owned by a non-root uid.

MITRE T1548 (Abuse Elevation Control Mechanism, parent technique).
ATT&CK has no Linux-polkit sub-technique as of May 2026.

## Cases

### `stock_polkit`

`/etc/polkit-1/rules.d/50-default.rules` and
`/usr/share/polkit-1/rules.d/49-polkit-pkla-compat.rules` — two
legitimate baseline files. Two records. Neither carries the
`polkit_admin_rule` signal; both carry `polkit_yes_constant` since
they use `polkit.Result.YES` for console-user grants.

### `admin_backdoor`

`/etc/polkit-1/rules.d/49-admin-backdoor.rules` granting
addAdminRule for user `alice`. One record. The
`polkit_admin_rule` AND `polkit_yes_constant` signals BOTH fire.
This is the load-bearing test for the two module-specific signals.

### `string_with_slashes`

`/etc/polkit-1/rules.d/50-with-strings.rules` containing
`"http://example.org/path"` and `"/usr/local/bin/foo"` as string
values. One record. The `//` and the path-with-comment-marker must
NOT be stripped — they are string content, not comments. Confirms
the parser respects string-literal boundaries.
