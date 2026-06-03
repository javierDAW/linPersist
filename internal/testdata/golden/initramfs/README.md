# Golden test fixtures: initramfs

Generator-agnostic early-boot hook collector. One record per regular
file in any of the hook/script dirs of the three major Linux initramfs
generators (initramfs-tools, dracut, mkinitcpio), walked recursively.

## Canonical form rules

- `content_sha256` and `content_norm_sha256` are both over the raw file
  bytes (hook scripts have no structured canonical form; raw bytes are
  deterministic and stack identical hooks fleet-wide).
- `content_snippet` is the first 256 chars of the raw body.
- `exec_target` is the file itself (the generator runs/sources it at
  boot); `exec_target_sha256` therefore equals `content_sha256`.
- Records carry no signals under the golden harness (NoopProvenance, so
  no `non_package_path`; mtime stamped 41 days old, so no
  `recent_mtime_*`; `non_root_owner` is redacted like every module's
  golden). The provenance-driven `non_package_path` / `package_file_tampered`
  co-indicators that drive the Q7 rule are validated by the detections
  matcher unit test and the nspawn lab instead.

## Cases

### `multi_generator_hooks`

One planted hook per generator at varying nesting depths, proving the
recursive walk and the host-absolute locus across all three:

- `/etc/initramfs-tools/hooks/zz-evil` (initramfs-tools, flat hooks dir)
- `/etc/initramfs-tools/scripts/local-top/payload` (initramfs-tools,
  per-stage subdir)
- `/usr/lib/dracut/modules.d/99evil/module-setup.sh` (dracut, nested
  module dir)
- `/etc/initcpio/install/evil` (mkinitcpio install hook)

Four `boot.initramfs.hook` records, each with `exec_target` = self.

### `clean_empty`

The initramfs-tools hooks dir and per-stage script subdirs exist but are
empty (`.gitkeep` only, which the walker skips as a dotfile) — the stock
host shape. Zero records emitted (empty `expected.ndjson`): no file in a
local dir means no FP by construction.
