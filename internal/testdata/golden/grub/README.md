# Golden test fixtures: grub

Two site_classes covering complementary GRUB persistence vectors:

- `kernel.grub.config`  — per-line records from `/etc/default/grub`.
  Each `KEY=VALUE` assignment is one record. The high-precision
  signal is `grub_cmdline_init`: a GRUB_CMDLINE_LINUX* value
  containing `init=<path>` overrides the kernel pid-1 binary at
  boot.
- `kernel.grub.dropin`  — per-file records from `/etc/grub.d/*`.
  Each script is invoked by `grub-mkconfig` at grub.cfg
  regeneration time as the user invoking it (typically root). A
  hostile drop-in yields both write-time code execution AND a
  custom boot entry that runs at the next boot.

Canonical form rules (`normalize.go`):

- `kernel.grub.config`: per-line; `export ` prefix dropped; trailing
  whitespace stripped; surrounding quotes around values preserved
  verbatim (they affect how grub-mkconfig parses embedded
  whitespace).
- `kernel.grub.dropin`: per-file; `#` comments (including shebang)
  stripped; blank lines dropped; trailing whitespace per line
  stripped.

`exec_target` is populated on:

- `kernel.grub.config` records whose value carries `init=<path>` —
  the override target.
- `kernel.grub.dropin` records — the script file itself.

MITRE T1542.003 (Pre-OS Boot: Bootkit). Cmdline injection alone is
technically a sub-case of T1547 but T1542.003 is the broader
pre-OS-tampering family the community uses for this technique.

## Cases

### `ubuntu_baseline`

`/etc/default/grub` from a stock Ubuntu 22.04 host plus two
`/etc/grub.d/*` drop-ins (`10_linux`, `40_custom`). Multiple
records: one per config line plus one per drop-in script. None
carry `grub_cmdline_init`; the GRUB_CMDLINE_LINUX_DEFAULT value
is `"quiet splash"`.

### `cmdline_init_implant`

`/etc/default/grub` with
`GRUB_CMDLINE_LINUX_DEFAULT="quiet splash init=/tmp/.x/bd"` — the
textbook attack. One implant record carries the
`grub_cmdline_init` signal AND populates `exec_target` with
`/tmp/.x/bd`, plus `interpreter_in_tmp` and `exec_target_orphan`
because the target does not exist in the fixture rootfs.

### `dropin_backdoor`

`/etc/grub.d/45_implant` — a drop-in that pipes a remote payload
through `/bin/sh` at every `grub-mkconfig` invocation. One record.
`exec_target` is the script path itself; canonical form has the
shebang and surrounding comments stripped so two semantically
equivalent backdoors collapse for LFA.
