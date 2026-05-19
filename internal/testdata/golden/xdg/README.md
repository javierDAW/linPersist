# Golden test fixtures: xdg

Per-file record granularity over `*.desktop` files in three locus
families:

- `/etc/xdg/autostart/*.desktop`         (system-wide, all users)
- `/root/.config/autostart/*.desktop`    (per-user, root)
- `/home/<user>/.config/autostart/*.desktop` (per-user, regular)

Canonical form rules (`normalize.go`):

- Lines starting with `#` are comments and are dropped.
- Blank lines are dropped.
- Section headers `[name]` are preserved in source order; first
  `[Desktop Entry]` always comes first if present.
- Within each section, keys are sorted alphabetically.
- Locale-suffixed keys (`Name[en]`, `Comment[de]`, ...) are dropped:
  the unlocalized variant carries the same semantic content for
  stacking.
- Trailing whitespace per value is stripped.

`exec_target` is set to `argv[0]` of the `Exec=` line in
`[Desktop Entry]`, with FreeDesktop field codes (`%U`, `%f`, `%i`,
...) stripped and surrounding double quotes removed.

MITRE T1547.013 (Boot or Logon Autostart Execution: XDG Autostart
Entries).

## Cases

### `system_autostart_clean`

Three baseline `.desktop` files under `/etc/xdg/autostart/` that
ship on a stock Ubuntu desktop. Three records expected. Each entry
gets `exec_target` populated from `Exec=`; the three targets exist
under `/usr/bin/` so no `interpreter_in_tmp` or `non_package_path`
signals fire (the latter requires a wired provenance resolver,
which is not part of golden tests).

### `user_autostart_implant`

`/home/alice/.config/autostart/innocent-name.desktop` whose `Exec=`
points to `/tmp/.cache/x/run`. One record. Expected signals
include `interpreter_in_tmp` and `exec_target_orphan` (the target
does not exist on disk under the fixture rootfs).

### `locale_keys_normalize`

A single `.desktop` under `/etc/xdg/autostart/` with `Name[en]`,
`Name[de]`, `Comment[es]`. One record. The canonical form must
contain only `Name=` and `Comment=` (unlocalized keys); the
locale variants are dropped at parse time.

### `root_autostart`

`/root/.config/autostart/admin-helper.desktop` covering the root
home autostart locus. One record. Confirms the walker reaches
`/root/.config/autostart/` even when `/home/` is empty.
