# Golden test fixtures: kmod

Per-directive (per-line) record granularity. Each non-comment
non-blank logical line in any loci file is one record. Canonical
form lowercases the first whitespace-token (directive verb for
modprobe.d, module name for /etc/modules-style) and collapses
internal whitespace to single space.

## Cases

### `kmod_etc_modules`

`/etc/modules` with three lines (`loop`, `nf_tables`, `nbd max_part=8`)
plus header comments that get stripped. Three records emitted.

### `kmod_modulesload_d`

`/etc/modules-load.d/myapp.conf` with two module names. Two records.

### `kmod_modprobed_blacklist`

`/etc/modprobe.d/blacklist.conf` with five blacklist directives and
one alias directive. Six records emitted; the five blacklist records
carry the `kmod_blacklist_directive` signal.

### `kmod_install_implant`

`/etc/modprobe.d/zz_implant.conf` with the textbook install-replacement
attack: `install ip_tables /bin/sh -c '/tmp/.cache/x.sh ...'`. The
record carries `kmod_install_directive`, `interpreter_in_tmp` (target
is `/bin/sh` but the script being launched lives under /tmp -- a
heuristic the agent records via the exec_target chain), and
`shell_indirect` (target IS the shell). Line continuation is
preserved through the parser's continuation join.
