# Golden test fixtures: motd

Per-file record granularity. Two canonical-form rules per locus:

- `/etc/motd`, `/etc/motd.d/*`  -> `NormalizeText`: strip trailing
  whitespace + blank lines only. `#` is NOT a comment here (it's
  banner content).
- `/etc/update-motd.d/*`        -> `NormalizeShell`: strip `#`
  comments + blank lines + trailing whitespace (same as `profile`,
  `sysv`).

`exec_target` is set only for `update-motd.d/*` records (the script
is invoked by `pam_motd` at login). Static-text loci leave it empty.

## Cases

### `motd_static`

`/etc/motd` with a plain three-line banner including a blank line in
the middle. One record. `content_norm_sha256` should be over the
non-blank lines, preserving any `#` that might appear in a banner.

### `motd_update_dir_clean`

`/etc/update-motd.d/00-header` and `/etc/update-motd.d/10-help-text`
-- legitimate Ubuntu defaults. Two records. Each carries
`exec_target` equal to its own path; canonical form strips the
shebang and `#` comments, leaving only the executable body.

### `motd_update_dir_implant`

`/etc/update-motd.d/99-x` with a textbook `curl | sh` implant. One
record. No module-specific signal is required to surface this: the
file's `content_norm_sha256` will be byte-unique across the fleet,
and the standard `recent_mtime_*` signal fires when the fixture's
mtime is rebased near a recent date.
