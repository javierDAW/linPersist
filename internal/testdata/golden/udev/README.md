# Golden test fixtures: udev

Per-rule (per-logical-line) record granularity. Each non-comment
non-blank line in a *.rules file -- after joining `\` continuations --
is one rule and one record.

Canonical form (`normalizeRule`):

- Trim leading and trailing whitespace.
- Collapse runs of whitespace OUTSIDE quoted values to a single space.
- Normalize spacing around `,` outside quotes to `, ` (comma + one
  space, no whitespace before).
- Whitespace inside `"..."` quoted values is preserved verbatim.
- Key-op-value triples retain source order.

`exec_target` is the first whitespace-separated token of the FIRST
`RUN+="..."` or `RUN="..."` value found in the rule. PROGRAM= rules
do not populate exec_target but do fire `udev_program_directive`.

## Cases

### `udev_legit_rule`

`/etc/udev/rules.d/99-com.rules` with a vendor-rule for an FTDI USB
dongle (`MODE`, `GROUP`). One record, no module-specific signals.

### `udev_run_implant`

`/etc/udev/rules.d/99-x.rules` with `ACTION=="add", SUBSYSTEM=="block",
RUN+="/tmp/.cache/poll.sh"`. One record carrying `udev_run_directive`,
`interpreter_in_tmp`, and `exec_target_orphan` (the payload is not
present in the fixture rootfs by design).

### `udev_multikey_continuation`

`/etc/udev/rules.d/70-network.rules` with a single rule spread across
four physical lines via `\` continuation. After parsing the rule is
ONE logical line and the record's `content_norm_sha256` is over the
joined+canonicalized form. `RUN+="/usr/local/bin/notify-link-up lan0"`
produces `exec_target=/usr/local/bin/notify-link-up` with the
`udev_run_directive` signal.
