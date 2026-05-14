# Golden test fixtures: pam

Same layout convention as the other modules.

## Canonical form rules

Two file formats coexist for PAM:

| Path | Fields per line | Canonical |
|---|---|---|
| `/etc/pam.d/<service>` | `<type> <control> <module> [args]` | `<type-lc> <control> <module> [args]` (whitespace-collapsed) |
| `/etc/pam.conf` | `<service> <type> <control> <module> [args]` | `<service> <type-lc> <control> <module> [args]` |

Tokenizer respects `[bracket=control]` syntax (a control of the
form `[success=ok default=die]` is ONE token, not many).
`@include` directives are emitted as records with canonical
`@include <target>`.

`exec_target` is set to the module path (third token in pam.d
files, fourth in pam.conf). Standard core signals fire on it:
`exec_target_orphan` when the path is absolute and missing;
`interpreter_in_tmp` when it starts with /tmp / /var/tmp /
/dev/shm / /run/shm.

No pam-specific signals added in v0.1.0.

## Cases

### `pam_sshd_classic`

`/etc/pam.d/sshd` with a typical baseline: 2 auth, 1 account, 1
session lines, all referencing standard modules (`pam_unix.so`,
`pam_nologin.so`). Expected: 4 records, no signals.

### `pam_with_implant_so`

`/etc/pam.d/sudo` with one anomalous line:
`auth sufficient /tmp/.x/pam_evil.so debug`. The implant module
lives under /tmp and does not exist in the fixture. Expected: 4
records; the implant record fires `exec_target_orphan` +
`interpreter_in_tmp` and lands in Query 7 (cross-module) of the
lab.

### `pam_legacy_conf`

`/etc/pam.conf` (the old single-file format, predates pam.d).
Three lines: two for sudo, one for sshd. Demonstrates that the
module handles both file formats without splitting site_classes.
