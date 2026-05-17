# Golden test fixtures: sysv

Per-file record granularity. Runner conventions match the other
modules (copyTree, applySymlinkManifest, stampMtimes, redactVolatile).

## Canonical form

`Normalize(raw)` is the same shape used by `profile`: strip `#`
comments (including shebangs and LSB `### BEGIN/END INIT INFO`
blocks), strip blank lines, strip trailing whitespace, join surviving
lines with `\n`. The body of an init script is what stacks; cosmetic
header drift does not.

## Cases

### `sysv_initd_happy`

`/etc/init.d/borg-backup` with LSB headers and standard start/stop
case dispatch. One record, no module-specific signals.

### `sysv_runlevel_internal_symlink`

`/etc/init.d/myapp` plus a `symlinks.txt` that creates
`/etc/rc2.d/S99myapp` -> `/etc/init.d/myapp`. The symlink target is
INSIDE the walked init.d locus; the walker should skip it and emit
only one record (for `/etc/init.d/myapp`). Verifies the internal-
symlink skip rule.

### `sysv_runlevel_external_symlink`

`/etc/rc2.d/S99payload` -> `/tmp/.cache/poll.sh` (external target,
not in init.d). One record emitted with the
`sysv_external_init_symlink` signal and `interpreter_in_tmp` signal.
This is the textbook offensive pattern of enabling a payload via
the rc?.d/ symlink without touching `/etc/init.d/`.

### `sysv_rhel_rcd`

`/etc/rc.d/init.d/foo` -- RHEL/CentOS variant of the init.d
location. Carries chkconfig-style header (`# chkconfig: 2345 99 01`)
instead of LSB. One record. Verifies the RHEL locus is walked.
