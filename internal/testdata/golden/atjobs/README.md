# Golden test fixtures: atjobs

Per-file record granularity over `at(1)` spool entries under:

- `/var/spool/at/`           (Debian/Ubuntu/RHEL/AmazonLinux)
- `/var/spool/cron/atjobs/`  (alternate path on some distros)

Each file is a shell script that `atd` executes when its scheduled
time arrives. The script body atd writes follows a strict layout:

```
#!/bin/sh
# atrun uid=<u> gid=<g>
umask 22
HOME=...; export HOME
PATH=...; export PATH
LOGNAME=...; export LOGNAME
USER=...; export USER
SHELL=...; export SHELL
TERM=...; export TERM
cd <home> || { echo 'Execution directory inaccessible' >&2; exit 1; }
${SHELL:-/bin/sh} << 'MARKER'
<user job body>
MARKER
```

`normalize.go` extracts the heredoc body (everything between
`${SHELL:-/bin/sh} << 'MARKER'` and the closing `MARKER` on its own
line) and applies the standard shell normalizer: strip `#` comments,
blank lines, and trailing whitespace per line. The atd header
(HOME/PATH/LOGNAME/USER...) is intentionally NOT part of
`content_norm_sha256` because it is volatile per user and would
defeat stacking.

`exec_target` is set to the spool file path itself (same pattern as
`cron.periodic`): atd executes the file as a shell script.

MITRE T1053.001 (Scheduled Task/Job: At).

## Cases

### `basic_alice_job`

Single Alice job under `/var/spool/at/a000158e6c01`. One record.
Canonical form is the inner body (`echo "hello from at"
/usr/local/bin/check-mail`) with the atd header stripped.

### `equivalent_users_collapse`

Two jobs — one from Alice (uid 1000) under `/var/spool/at/`, one
from Bob (uid 2001) under `/var/spool/cron/atjobs/` — both scheduling
the same `/usr/local/bin/check-mail --once` command. Two records,
**same `content_norm_sha256`**. This is the load-bearing
test for the normalize policy: per-user header noise must not
prevent two semantically-identical jobs from stacking.

### `hand_edited_spool`

A spool file under `/var/spool/at/` that does NOT follow the atd
layout (no heredoc opener). One record. The canonical form falls
back to the raw input with shell-style comment + blank-line strip;
content_norm_sha256 still deterministic, just lower yield for
stacking against atd-generated jobs.
