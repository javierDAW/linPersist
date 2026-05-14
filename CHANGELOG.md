# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
