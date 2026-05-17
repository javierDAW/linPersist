# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (linpersist-report)
- `cmd/linpersist-report` — a second static binary that turns a
  directory of agent NDJSON output into a report. Same build
  discipline as the agent: `CGO_ENABLED=0`, build tags
  `osusergo netgo`, vendored CSS and JS embedded via `embed.FS`,
  zero network fetches at view time. Cross-compiled alongside
  `linpersist` by `make build-all`.
- **Two output formats** controlled by `-format`: `html` (default,
  self-contained, shareable) and `text` (terminal-friendly,
  jump-host friendly, ANSI-color-on-TTY). Both formats consume the
  same `Report` data structure; the trade-off is interaction vs.
  portability. See ADR-0008 for the rendering policy and
  `docs/report.md` for the when-to-use-which matrix.
- Text mode uses `text/tabwriter` for column alignment and gates
  ANSI escapes via `-color auto|on|off` (auto = TTY and not
  redirected). Three color uses, mirrored from the HTML accent
  palette: bold section headings, red `Q4 implant hits` count
  when > 0, orange LFA-singletons histogram bar. Everything else
  stays plain text so the analyst can `grep`/`awk` cleanly.
- `docs/adr/0008-report-dual-rendering.md` ADR documenting the
  decision to ship dual rendering rather than HTML-only or
  Markdown-only.
- The report covers all six cookbook queries (Q1-Q6) plus a fleet
  overview: per-module / per-site_class / per-os_id counts, LFA
  stacking histogram (singletons highlighted), signal distribution
  bar chart. Each table is sortable by header click and filterable
  via a live search input. Dark and light themes auto-switch via
  `prefers-color-scheme`.
- `docs/report.md` documents what each tab shows and the empirical
  performance envelope (6k records ≈ 50 ms; 600k records ≈ 2.5 s).
- `Makefile` now drives a `BINARIES := linpersist linpersist-report`
  variable so the build/verify targets iterate over both binaries
  without duplication.

## [0.1.0-alpha] - 2026-05-17

First publicly tagged snapshot. The v0.1.0 critical set of persistence
modules (13 modules, 23 site_classes, 14 MITRE ATT&CK techniques) is
implemented and golden-tested. NDJSON schema is at v1 and considered
frozen for the v0.1.x line; any breaking change ships under v0.2.x
with a documented migration. Static cross-compilation, multi-distro
lab, and an LFA stacking cookbook accompany the agent.

### Added
- Repository skeleton: layout, Makefile, Apache-2.0 LICENSE, .gitignore.
- `matrix.yaml` source of truth for MITRE ATT&CK coverage (15 site_classes
  planned for v0.1.0).
- `internal/core` skeleton: `Module` interface, `Record` struct with NDJSON
  tags, runner stub with per-module timeout, NDJSON emitter, hashing and
  normalization helpers, host metadata collector stub, signal helpers,
  provenance stub.
- `cmd/linpersist/main.go` CLI entry point with `--output`,
  `--include-hostname`, `--module-timeout`, and `--version` flags.
- `tools/verify_static.sh` portability gate (`ldd` + `file` checks).
- `docs/schema-v1.md` canonical NDJSON record description.
- `docs/adr/0001-module-interface.md` ADR for the `Module` interface.
- `cron` module: collects `cron.d`, `cron.user`, `cron.periodic`,
  `cron.anacron` (MITRE T1053.003). Per-line record granularity for
  crontab-format files; per-file for run-parts scripts. Golden tests
  for the happy path plus drop-in and periodic-script cases.
- `docs/adr/0002-record-granularity.md` ADR justifying per-line
  granularity for the cron module.
- `ldso` module: collects `ldso.preload`, `ldso.conf`, `ldso.confd`
  (MITRE T1574.006). Per-path-token record granularity for
  /etc/ld.so.preload (glibc's multi-path-per-line form honored);
  per-line for /etc/ld.so.conf and /etc/ld.so.conf.d/*.conf;
  include directives emitted verbatim without glob expansion.
  Four golden cases: simple-lib, orphan-in-tmp multi-path,
  conf-with-include, confd-drop-in.
- `core.SignalRecentTargetMtime7d` signal flagging an exec_target
  whose mtime falls within the last 7 days; complements the
  existing `recent_mtime_7d` on the locus file. Emitted by both
  the `ldso` and `cron` modules: `cron.execTargetSignals` reuses
  its `os.Stat` call so the new signal costs zero extra syscalls.
- `ssh` module: collects `ssh.authkeys` (MITRE T1098.004) from
  /etc/ssh/authorized_keys, /etc/ssh/authorized_keys.d/*,
  /root/.ssh/authorized_keys{,2}, and /home/*/.ssh/authorized_keys{,2}.
  Per-key record granularity. The public-key blob is NEVER emitted
  raw -- only its sha256 lands in `exec_target_sha256` and a 12-char
  prefix appears in `content_snippet`. `exec_target` is populated
  only when the line carries a `command="..."` option (path being
  forced on every login). Four golden cases: simple ed25519+rsa,
  options-with-no-command, forced-command (legit + implant in /tmp),
  per-user homes (alice + bob).
- `docs/adr/0003-ssh-key-blob-handling.md` ADR documenting the
  never-emit-raw-blob privacy policy and the comment-exclusion
  rule for `content_norm_sha256`.
- Two new core signals for the `ssh` module:
  `ssh_options_present` (any options list before the keytype) and
  `ssh_forced_command` (specifically `command="..."` is present).
- `sudoers` module: collects `sudoers` (MITRE T1548.003) from
  /etc/sudoers and /etc/sudoers.d/*. Per-line granularity covering
  five line kinds: aliases, Defaults, user-specs, #include,
  #includedir. Alias members are sorted alphabetically in the
  canonical form to maximize stacking. Three module-specific
  signals: `sudoers_nopasswd`, `sudoers_all_commands`,
  `sudoers_include_directive`. Three golden cases (main with
  include, NOPASSWD implant, aliases).
- `sshd` module: collects `sshd.config` (MITRE T1098.004 + T1556)
  from /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/*.conf.
  Per-directive granularity. Match blocks are scoped into
  content_norm_sha256 by prepending the canonical Match line to
  every directive inside the block (see ADR-0004). Three
  module-specific signals: `sshd_permit_root_login_yes`,
  `sshd_authorized_keys_command`, `sshd_match_block_directive`.
  Three golden cases (classic, with Match block, with
  AuthorizedKeysCommand). exec_target populated for
  AuthorizedKeysCommand and ForceCommand directives.
- `docs/adr/0004-sshd-match-block-canonical.md` ADR documenting
  the Match-block canonical-form decision.
- `passwd` module: collects `passwd.user`, `passwd.shadow`,
  `passwd.group`, `passwd.gshadow` (MITRE T1136.001) from
  /etc/passwd, /etc/shadow, /etc/group, /etc/gshadow. Per-line
  granularity. Passwd users filtered by `uid=0 OR shell not in
  {nologin, false}`; shadow records filtered to the same set.
  Password hashes from /etc/shadow and /etc/gshadow are NEVER
  emitted -- only a status enum (set/locked/disabled/empty/unknown)
  per ADR-0005. Group and gshadow members sorted alphabetically
  in canonical forms. Two module-specific signals:
  `passwd_uid_zero` (uid=0 with username != root) and
  `passwd_no_password` (shadow status == empty).
- `pam` module: collects `pam` site_class (MITRE T1556.003) from
  /etc/pam.conf and /etc/pam.d/*. Per-line granularity. exec_target
  is the module path; standard core signals (exec_target_orphan,
  interpreter_in_tmp, recent_target_mtime_7d) cover the textbook
  implant pattern of a malicious .so referenced from /etc/pam.d/.
  Three golden cases (classic, with /tmp implant, legacy pam.conf).
- `docs/adr/0005-password-hash-never-emitted.md` ADR documenting
  the never-emit-raw-hash policy for /etc/shadow and /etc/gshadow.
- Two new core signals: `passwd_uid_zero`, `passwd_no_password`.
- `profile` module: collects `profile.system` and `profile.user`
  (MITRE T1546.004) from /etc/profile, /etc/profile.d/*,
  /etc/bash.bashrc, /etc/zsh/zshenv, /etc/zsh/zprofile,
  /etc/environment, /root/.{bashrc,bash_profile,bash_login,profile,
  zshrc,zshenv}, and /home/*/.{bashrc,bash_profile,bash_login,
  profile,zshrc,zshenv}. Per-file record granularity (pattern
  from cron.periodic). Canonical form strips comments (including
  shebangs since these files are sourced not executed), blank
  lines, and per-line trailing whitespace; content_sha256 is over
  the raw file bytes. No module-specific signals; standard core
  signals (recent_mtime_*, world_writable, non_root_owner) apply.
  Three golden cases (system clean, user implant with curl|bash
  line, root bashrc).
- `docs/adr/0006-hostname-policy.md` ADR pinning the hostname
  representation contract: lowercase + short normalization before
  hashing, no salt in v1, machine-id emitted in plaintext,
  `--include-hostname` opt-in, container workloads via
  `host_meta.tags`.
- `internal/core/hostmeta_test.go` first unit tests in
  `internal/core/`: cover `normalizeHostname`, `hashHostname`
  (cosmetic-variant collapse, distinct hosts differ, prefix shape),
  `readOSRelease` against Ubuntu/RHEL/Alpine/Debian/Arch fixtures,
  `readFirstLine` edge cases, and `FormatMode` including high mode
  bits and setuid/setgid/sticky.

### Changed
- `core.hashHostname` now normalizes its input (lowercase, trim, strip
  domain suffix) before hashing. **Breaking** for any host whose
  hostname contained uppercase letters or a domain suffix: its
  `host_meta.hostname_hash` digest changes. Done intentionally before
  v0.1.0 is tagged so the canonical digest never changes for an
  external consumer. See ADR-0006.
- `docs/schema-v1.md` host_meta section now spells out the
  normalization rule next to `hostname_hash` and clarifies that the
  opt-in plaintext `hostname` field is NOT normalized.
- `Makefile`: new `audit` target; the default `all` target now runs
  it between `test` and `build` so a local `make` catches matrix
  drift before producing a binary.

### Added (internal/core coverage)
- `internal/core/hashutil_test.go`: known-vector sha256 digests
  (`""` and `"abc"`), digest shape (64 lowercase hex chars),
  HashHex/HashHexString equivalence, HashReader matching HashHex for
  small and 1 MiB payloads, error propagation when the underlying
  Reader fails immediately or mid-stream, EOF treated as normal
  termination.
- `internal/core/normalize_test.go`: `StripLineComments` with `#`
  and `;` prefixes, inline comment stripping, trailing whitespace
  trim, CRLF normalization, blank-line drop, single-trailing-newline
  contract, idempotence, empty input, all-comments yields empty.
  `CollapseWhitespace` collapses runs of spaces and tabs to one
  space, preserves newlines, respects newline boundaries, leaves
  comment-free / whitespace-free input unchanged, handles UTF-8
  multibyte, is idempotent. Composition test pins the canonical
  `CollapseWhitespace(StripLineComments(...))` pipeline against four
  cosmetic variants of the same cron line.
- `internal/core/emit_test.go`: one-record-one-line contract,
  multiple records each on their own line and individually JSON-
  parseable, HTML escaping confirmed disabled, Close flushes,
  goroutine-safe under 12 goroutines × 200 records (no interleaving,
  every line is a valid Record), error propagation on Close when
  the buffer flushes, error propagation on the Emit fast-path when
  the encoded record exceeds bufio's buffer, wrapped error message
  identifies the offending module / site_class.

### Added (cron golden coverage)
- `internal/testdata/golden/cron/cron_user_alice/`: per-user crontab
  fixture under `/var/spool/cron/crontabs/alice`. Exercises the
  cron.user site_class with six records — two variable assignments
  (MAILTO, PATH), three normal schedule entries, and the textbook
  implant pattern (a `/tmp/.cache/poll.sh` line that fires
  `interpreter_in_tmp` + `exec_target_orphan`). Also covers the
  `@reboot` shorthand on a per-user crontab (no USER column).
- `internal/testdata/golden/cron/etc_anacrontab/`: /etc/anacrontab
  fixture with eight records — five variable assignments (SHELL,
  PATH, MAILTO, RANDOM_DELAY, START_HOURS_RANGE) and three schedule
  entries including `@monthly` shorthand. Whitespace in the source
  (multi-space / tab-separated fields) differs from the canonical
  form, so each schedule's `content_sha256` differs from its
  `content_norm_sha256` — demonstrating that normalization collapses
  the cosmetic variants.
- `matrix.yaml`: `cron.user` and `cron.anacron` upgraded from
  `test_coverage: none` to `golden` now that they have dedicated
  fixtures.

### Added (systemd module)
- `systemd` module: collects `systemd.unit` (MITRE T1543.002) and
  `systemd.timer` (MITRE T1053.006) from system-mode loci
  (`/etc/systemd/system`, `/usr/lib/systemd/system`,
  `/lib/systemd/system`, `/run/systemd/system`), system-installed
  user loci (`/etc/systemd/user`, `/usr/lib/systemd/user`), and
  per-user loci (`/root/.config/systemd/user`,
  `/home/*/.config/systemd/user`). Per-file record granularity per
  ADR-0007. Extensions in scope: `.service`, `.socket`, `.path`,
  `.mount`, `.automount`, `.swap`, `.target`, `.timer`. `.slice` and
  `.scope` deliberately excluded for v0.1.0 (noisy, rarely a
  persistence vector). Drop-ins under `*.d/*.conf` emit as
  independent records with the `systemd_dropin` signal; the agent
  does NOT merge drop-ins with their base unit in memory.
- `internal/modules/systemd/inifile.go` hand-rolled parser:
  backslash line-continuation join, comment + blank-line skip,
  malformed-input tolerance (PARSE_ERROR entries surface via
  `Record.Errors`, never panic).
- `internal/modules/systemd/normalize.go` canonical-form pipeline:
  section names + order canonicalized (`[Unit]` -> type-specific ->
  `[Install]` -> others alphabetical); key names + order
  canonicalized (alphabetical case-insensitive, with the `Exec*=`
  family exempted from sort and preserving source order); ~50
  well-known keys get conventional capitalization; set-semantic
  keys (`Wants=`, `After=`, `Requires=`, ...) accumulate across
  lines, honor the empty-value reset, then sort+dedupe; `Exec*=`
  family honors the empty-value reset and preserves `@-:!+`
  prefixes verbatim. Pipeline is idempotent.
- Symlink classification per ADR-0007 §6: internal symlinks
  (target inside any walked locus) are skipped to avoid
  double-counting; external symlinks (target outside walked loci)
  emit a record carrying the resolved target's content hashes and
  the `systemd_external_unit_symlink` signal. The `/home` walked
  locus is matched by path shape (`/.config/systemd/user/...`)
  rather than by prefix, so a symlink to an unrelated file under a
  user's home still classifies as external.
- ExecStart resolution: strips `@-:!+` prefixes, takes `argv[0]`,
  resolves absolute paths directly and relative commands against
  the documented systemd.exec(5) default PATH
  (`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`).
  Honors the empty-value reset idiom. `exec_target_sha256` is
  streamed against the resolved binary.
- Seven new core signals: `systemd_user_unit`, `systemd_dropin`,
  `systemd_template_unit`, `systemd_external_unit_symlink`,
  `systemd_multi_execstart`, `systemd_exec_unresolved`,
  `systemd_install_alias_external`.
- `docs/adr/0007-systemd-canonical-form.md` ADR documenting the
  granularity (per-file), drop-in policy (independent records),
  canonical-form pipeline, scope (`.slice` / `.scope` excluded),
  symlink rules, and template-instance handling.
- `docs/modules/systemd.md` first per-module reference doc in the
  project (loci, canonical form, signals, false-positive patterns,
  out-of-scope items). The other modules still owe the equivalent
  doc; tracked as debt rather than blocking the v0.1.0 tag.
- Eight golden fixture cases covering happy path
  (`unit_basic_service`), line continuations
  (`unit_line_continuation`), drop-ins (`dropin_overrides_exec`),
  template units (`template_instance_unit`), user units
  (`user_unit_alice`), external `.wants/` symlink
  (`external_wants_symlink`, with `symlinks.txt` manifest so the
  symlink is created at test time rather than checked into git),
  timers (`timer_basic` with cross-referenced `.service`), and
  parser robustness (`unit_malformed`).
- Module unit tests cover Normalize (line continuations, comment
  stripping, section + key reorder, set-semantic sort+dedupe,
  empty-reset for both set-semantic and Exec* families,
  equivalent-inputs collapse, idempotence, empty input), ParseUnitFile
  (sections, continuations, malformed-line tolerance), helpers
  (`stripExecPrefixes`, `isTemplateUnit`, `classifyExtension`,
  `siteClassForDropinDir`), `resolveExecTarget` (absolute,
  multi-ExecStart, no-ExecStart, unresolved-relative), and
  `targetInsideWalkedLoci` (including the `/home` path-shape rule).
- `cmd/linpersist` and `cmd/matrix-audit` updated to register the
  new module; `matrix-audit` continues to pass.

### Changed (matrix coverage)
- `matrix.yaml`: `systemd.unit` and `systemd.timer` flipped from
  `planned` to `implemented`. The `systemd.timer` entry's loci were
  corrected to include the user-mode directories
  (`/etc/systemd/user`, `/usr/lib/systemd/user`,
  `/home/*/.config/systemd/user`, `/root/.config/systemd/user`);
  the original entry only covered system-mode dirs which would have
  missed user timers (a documented vector when
  `loginctl enable-linger` is set on the user).

### Added (sysv module)
- `sysv` module: collects `sysv.init` (MITRE T1037.004) from
  `/etc/init.d/*`, `/etc/rc.d/init.d/*` (RHEL variant),
  `/etc/rc.local`, `/etc/rc.d/rc.local`, plus
  external-target symlinks under `/etc/rc[0-6].d/`, `/etc/rcS.d/`,
  and `/etc/rc.d/rc[0-6].d/`. Per-file record granularity.
- Canonical form mirrors `profile`/`motd-shell`: strips `#`
  comments (including shebangs and LSB `### BEGIN/END INIT INFO`
  blocks), blank lines, and per-line trailing whitespace. The
  executable body is what stacks; cosmetic header drift collapses.
- Symlink classification analogous to `systemd`: internal symlinks
  (target inside `init.d/`) are skipped to avoid double-counting;
  external symlinks (target outside walked loci) emit a record
  carrying the resolved target's content hashes and the
  `sysv_external_init_symlink` signal. Captures the offensive
  pattern of enabling a payload from `/tmp` or `/opt` via an
  `rc2.d/S99payload -> /tmp/.cache/x.sh` symlink without touching
  `/etc/init.d/`.
- New core signal: `sysv_external_init_symlink`.
- Four golden fixture cases covering happy path
  (`sysv_initd_happy`), internal symlink that should be skipped
  (`sysv_runlevel_internal_symlink`), external symlink to a
  `/tmp` payload (`sysv_runlevel_external_symlink`), and the
  RHEL `/etc/rc.d/init.d/` location (`sysv_rhel_rcd`).
- Module unit tests cover `Normalize` (LSB-header strip,
  equivalent-bodies collapse, trailing-whitespace strip, empty
  inputs) and `targetInsideInitdLoci`.

### Added (motd module)
- `motd` module: collects `motd` (MITRE T1037, parent technique
  -- ATT&CK has no sub-technique specific to motd-via-PAM as of
  May 2026) from `/etc/motd`, `/etc/motd.d/*`, and
  `/etc/update-motd.d/*`. Per-file record granularity.
- Two canonical-form rules per locus: `NormalizeText` for
  plain-text loci (only strip trailing whitespace + blank lines;
  `#` is content, not a comment); `NormalizeShell` for
  `/etc/update-motd.d/*` shell scripts (strip `#` comments +
  blank lines + trailing whitespace, same as `profile` and
  `sysv`). The walker picks the normalizer by path.
- `exec_target` is set only on `update-motd.d/*` records; those
  scripts are invoked by `pam_motd` at login, so the script
  itself is the persistence target. Static-text loci leave
  `exec_target` empty.
- Three golden fixture cases: `motd_static` (legitimate
  `/etc/motd` banner with `#` content preserved),
  `motd_update_dir_clean` (Ubuntu defaults at 00-header and
  10-help-text), `motd_update_dir_implant` (textbook
  `curl|sh` line in 99-x).
- Module unit tests verify `NormalizeText` preserves `#` lines
  (banner content), `NormalizeShell` strips `#` lines (shell
  semantics), equivalent shell bodies collapse to the same
  canonical hash, and both normalizers handle empty input.
- `/etc/issue` and `/etc/issue.net` deliberately out of scope:
  those are pre-login banners, not a PAM-mediated persistence
  vector. Re-evaluate if reporting from PANIX or DFIR Report
  shows in-the-wild use.

### Changed (matrix coverage)
- `matrix.yaml`: `sysv.init` flipped from `planned` to
  `implemented`. Loci expanded to include `/etc/rc.d/init.d/`,
  `/etc/rc.d/rc.local`, and the RHEL `/etc/rc.d/rc[0-6].d/`
  family alongside the existing `/etc/rc[0-6].d/` set. Notes
  document the internal/external symlink classification policy.
- `matrix.yaml`: `motd` flipped from `planned` to
  `implemented`. MITRE changed from `T1037.004` (RC Scripts --
  incorrect, that is sysv.init's technique) to `T1037` (parent,
  no Linux-motd sub-technique exists yet). Loci trimmed to
  `/etc/motd`, `/etc/motd.d/`, `/etc/update-motd.d/` -- removed
  `/etc/issue` and `/etc/issue.net` from scope per the spec
  discussion.

### Added (kmod module)
- `kmod` module: collects `kmod` (MITRE T1547.006) from
  `/etc/modules`, `/etc/modules-load.d/*.conf`,
  `/usr/lib/modules-load.d/*.conf`, `/run/modules-load.d/*.conf`,
  `/etc/modprobe.d/*.conf`, `/lib/modprobe.d/*.conf`,
  `/usr/lib/modprobe.d/*.conf`, `/run/modprobe.d/*.conf`.
- Per-directive (per-line) record granularity. Each non-comment
  non-blank logical line is one record. Backslash line continuations
  are joined before parsing.
- Canonical form: trim, collapse runs of whitespace to single space,
  lowercase the first whitespace-token (directive verb for modprobe,
  module name for /etc/modules-style). Values keep their source
  case. Idempotent.
- `install` directives fire `kmod_install_directive` and populate
  `exec_target` with argv[0] of the replacement command -- the
  textbook modprobe.d persistence vector
  (`install X /bin/sh -c '...'`). `blacklist` directives fire
  `kmod_blacklist_directive`. Standard core signals
  (`recent_mtime_*`, `world_writable`, `non_root_owner`,
  `exec_target_orphan`, `interpreter_in_tmp`, `shell_indirect`)
  apply.
- Two new core signals: `kmod_install_directive`,
  `kmod_blacklist_directive`.
- Four golden cases: `kmod_etc_modules` (three module names with
  optional kernel-arg on one line), `kmod_modulesload_d`
  (`/etc/modules-load.d/myapp.conf`), `kmod_modprobed_blacklist`
  (six directives across blacklist + alias),
  `kmod_install_implant` (textbook `install ip_tables /bin/sh -c`
  pattern with line continuation).
- Module unit tests cover `normalizeLine` (whitespace collapse,
  verb lowercase, value-case preservation, idempotence, empty
  input), `parseLogicalLines` (continuation join, comment + blank
  drop), and `splitFirstToken`.

### Added (udev module)
- `udev` module: collects `udev` (MITRE T1546 parent -- ATT&CK has
  no Linux-udev sub-technique as of May 2026) from
  `/etc/udev/rules.d/*.rules`, `/lib/udev/rules.d/*.rules`,
  `/usr/lib/udev/rules.d/*.rules`, `/run/udev/rules.d/*.rules`.
- Per-rule (per-logical-line) record granularity. Backslash line
  continuations are joined into a single logical rule before parsing.
- Canonical form (`normalizeRule`): trim, collapse runs of
  whitespace OUTSIDE quoted values to a single space, normalize
  spacing around `,` to `, ` (comma followed by exactly one space).
  Whitespace INSIDE `"..."` quoted values is preserved verbatim.
  Key-op-value triples retain source order (assignment-side
  operators like RUN+= are order-sensitive in udev semantics).
- `extractAssignmentValue` is a stateful parser that finds the
  first triple with a given key (case-insensitive) and operator
  `=`/`+=`/`:=`. Matches are anchored on word boundaries so a key
  like `PRERUN_HOOK` does not match a search for `RUN`. Supports
  the curly-brace-qualified form `RUN{program}+=`.
- `RUN+=` and `RUN=` rules fire `udev_run_directive` and populate
  `exec_target` with the first whitespace-separated token of the
  value. `PROGRAM=` fires `udev_program_directive` (no
  `exec_target` populated; it is a matcher-side directive). Standard
  core signals apply.
- Two new core signals: `udev_run_directive`,
  `udev_program_directive`.
- Three golden cases: `udev_legit_rule` (vendor-rule for an FTDI
  USB dongle, MODE+GROUP only), `udev_run_implant`
  (`RUN+="/tmp/.cache/poll.sh"`), `udev_multikey_continuation`
  (single rule across four physical lines via `\`).
- Module unit tests cover `parseRules` (continuation join, comment
  + blank drop), `normalizeRule` (whitespace collapse outside
  quotes, comma spacing, quoted-whitespace preservation,
  idempotence, empty input), `extractAssignmentValue` (RUN, PROGRAM,
  brace-qualified RUN{program}+=, not-present, word-boundary),
  and the file-level `Normalize`.

### Changed (matrix coverage)
- `matrix.yaml`: `kmod` flipped from `planned` to `implemented`.
  Loci expanded to include `/usr/lib/modules-load.d/` and
  `/run/modules-load.d/` alongside the existing
  `/etc/modules-load.d/` (parity with the modprobe.d family).
  Notes document the per-directive granularity decision, the
  canonical-form rules, and the install/blacklist signal logic.
- `matrix.yaml`: `udev` flipped from `planned` to `implemented`.
  Notes document the per-rule (per-logical-line) granularity
  decision (over per-file), the quote-aware canonical-form rules,
  and the RUN+= / PROGRAM= exec_target / signal contract.
- **v0.1.0 critical set is now complete.** All 13 site_classes
  across 11 modules from the original v0.1.0 plan are implemented
  with golden + unit tests.

### Added (matrix-audit)
- `cmd/matrix-audit/main.go` release gate per ADR-0001. Loads
  `matrix.yaml`, instantiates the same modules `cmd/linpersist`
  registers, and reports four classes of drift:
  `code-without-matrix`, `matrix-lying`, `planned-with-code`,
  `module-name-mismatch`. Also rejects invalid status values,
  duplicate site_class entries, and two modules emitting the same
  site_class. Exit 1 on any drift, exit 0 with a one-line summary
  on stderr otherwise.
- `cmd/matrix-audit/main_test.go` covering happy path plus every
  drift class on the pure `audit()` function, parser error path,
  status-summary counts, and stable alphabetical ordering of drift
  messages.
- New build-time dependency: `gopkg.in/yaml.v3` (pure-Go, on the
  project's approved list).
