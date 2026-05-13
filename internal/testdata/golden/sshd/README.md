# Golden test fixtures: sshd

Same layout as cron / ldso / ssh / sudoers. Test runner copies
rootfs into t.TempDir(), chmods to 0644 (sshd_config is
world-readable, root-owned in production), stamps mtimes to
fixedMtime, runs module with fixedNow.

Canonical form rules (must match `internal/modules/sshd`):

- Strip leading and trailing whitespace.
- Lowercase the directive keyword. Preserve the value verbatim
  after a single space.
- For lines inside a `Match` block: prepend the canonical Match
  line followed by ` : ` (space-colon-space) to the directive's
  canonical form. See ADR-0004.
- The `Match` line itself: lowercase the `Match` keyword AND each
  criterion keyword (`User`, `Group`, `Host`, etc.). Preserve
  criterion values (usernames, group names, IPs) verbatim.
- Blank lines and `#`-comments are skipped, no record.

## Cases

### `sshd_classic`

`/etc/ssh/sshd_config` with three plain directives: Port 22,
PermitRootLogin no, PasswordAuthentication yes. No Match. No
signals fire (none of these are in the project's curated set of
sshd policy signals).

### `sshd_with_match_block`

`/etc/ssh/sshd_config` with two top-level directives followed by
a `Match User alice` block that overrides PermitRootLogin and
adds AuthorizedKeysFile. Demonstrates the Match-scoping in
canonical forms per ADR-0004. The `PermitRootLogin yes` inside
Match fires both `sshd_permit_root_login_yes` and
`sshd_match_block_directive`; the top-level `PermitRootLogin no`
fires neither.

### `sshd_authorized_keys_command`

`/etc/ssh/sshd_config` with PermitRootLogin no,
AuthorizedKeysCommand /usr/local/bin/fetch-keys, and
AuthorizedKeysCommandUser nobody. The AuthorizedKeysCommand
record fires `sshd_authorized_keys_command` and (because the
target binary does not exist in the fixture) `exec_target_orphan`.
`exec_target` is populated with the command path.
