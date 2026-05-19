# Golden test fixtures: netdispatch

Per-file record granularity over network-event dispatcher scripts in
four daemon families:

- **NetworkManager**: `/etc/NetworkManager/dispatcher.d/*` plus the
  `pre-up.d/`, `pre-down.d/`, `no-wait.d/` subdirectories.
- **dhclient**: `/etc/dhcp/dhclient-{enter,exit}-hooks.d/*`.
- **dhcpcd**: `/etc/dhcpcd.enter.hook` and `/etc/dhcpcd.exit.hook`
  (single-file hooks, not directories).
- **ifupdown** (Debian classic): `/etc/network/if-{pre-up,up,down,
  post-down}.d/*`.

`exec_target` is set to the script file path itself (same pattern
as `cron.periodic`): the dispatcher daemon executes the file as a
shell script on network events.

Canonical form rules (`normalize.go`):

- `#` comments and the rest of their line are dropped (including
  the shebang line — a script's shebang is cosmetic for stacking).
- Blank lines are dropped.
- Trailing whitespace per line is stripped.

Two scripts that differ only in shebang or comment noise produce
the same `content_norm_sha256`.

MITRE T1546 (Event Triggered Execution, parent technique). ATT&CK
has no Linux-network-dispatcher sub-technique as of May 2026.

## Cases

### `nm_dispatcher_clean`

Two NetworkManager dispatcher scripts under
`/etc/NetworkManager/dispatcher.d/` plus one ifupdown hook under
`/etc/network/if-up.d/`. Three records. All three are stock
distro-shipped scripts; canonical forms differ but each is
deterministic.

### `dhclient_implant`

`/etc/dhcp/dhclient-enter-hooks.d/zz-update` — an attacker-supplied
script that fetches and runs a payload on every DHCP lease
renewal. One record. The script is owned by a non-root uid in the
fixture (the redactor drops the resulting `non_root_owner` signal
so the test stays deterministic across CI environments).

### `dhcpcd_single_files`

`/etc/dhcpcd.enter.hook` and `/etc/dhcpcd.exit.hook` — covers the
single-file path that does NOT use a `*.d/` directory. Two records.
