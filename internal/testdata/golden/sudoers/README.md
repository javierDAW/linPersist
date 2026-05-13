# Golden test fixtures: sudoers

Layout convention as cron/ldso/ssh. Test runner copies rootfs into
t.TempDir(), chmods to canonical sudoers perms (0440 for sudoers
files, 0755 for directories), stamps mtimes to fixedMtime, runs
the module with fixedNow, compares emitted NDJSON against
expected.ndjson.

Canonical form rules (must match `internal/modules/sudoers`
implementation byte-for-byte):

- Strip leading and trailing whitespace.
- Quote-aware whitespace collapse (runs of space/tab outside double
  quotes become a single space; whitespace inside double quotes
  preserved).
- Strip whitespace immediately around `=` (when outside quotes).
- `#include path` -> canonical `include path` (drop the leading `#`).
- `#includedir path` -> canonical `includedir path`.
- Other `#`-comments and blank lines: skipped, no record.
- `<Kind>_Alias NAME = a, b, c`: members are split on commas (trim
  each, sort alphabetically) and rejoined with `, ` (comma + space).
  Keyword case preserved (sudoers requires `User_Alias`,
  `Cmnd_Alias`, etc. with that exact case).
- User specs and Defaults: no further structural sorting in v0.1.0.

Signal rules (must match the implementation):

- `sudoers_nopasswd`: the canonical line contains the literal
  `NOPASSWD:` (case-sensitive per sudoers convention).
- `sudoers_all_commands`: after `=` and any `(runas)` section, the
  remaining command list (after stripping `TAG:` tokens) contains
  the standalone token `ALL`.
- `sudoers_include_directive`: line is `#include` or `#includedir`.

## Cases

### `sudoers_main_with_include`

`/etc/sudoers` carrying three Defaults, three admin user-specs
(root, %admin, %sudo), and an `#includedir /etc/sudoers.d`
directive. Six records expected.

### `sudoers_nopasswd_implant`

`/etc/sudoers.d/zz_helper` with a single user-spec
`cibot ALL=(ALL) NOPASSWD: ALL`. One record expected with the
canonical NOPASSWD + ALL combination -- the textbook sudo
backdoor pattern.

### `sudoers_aliases`

`/etc/sudoers` carrying a `User_Alias`, a `Cmnd_Alias`, and a
user-spec that references both. Demonstrates member sorting
inside aliases.
