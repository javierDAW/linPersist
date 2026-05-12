# ADR-0002: Record granularity for the cron module

- Status: Accepted
- Date: 2026-05-12
- Related: ADR-0001 (module interface), `internal/modules/cron`,
  `docs/schema-v1.md`.

## Context

The `cron` module covers four site_classes:

- `cron.d` — `/etc/crontab` and `/etc/cron.d/*` (crontab format with
  USER column).
- `cron.user` — `/var/spool/cron/{crontabs,}/*` (crontab format
  without USER column; the user is the file name).
- `cron.periodic` — executable scripts under `/etc/cron.{hourly,
  daily,weekly,monthly}/` invoked by `run-parts`.
- `cron.anacron` — `/etc/anacrontab` (period/delay/jobid/command).

Two granularity options were on the table for the crontab-format
site_classes (`cron.d`, `cron.user`, `cron.anacron`):

1. **One record per file.** `content_norm_sha256` covers the whole
   normalized file.
2. **One record per non-blank, non-comment line.** Each schedule
   entry (or variable assignment) becomes its own record.

For `cron.periodic` the unit is a discrete executable; per-file is the
only sensible choice there.

## Decision

- **Crontab-format site_classes (`cron.d`, `cron.user`, `cron.anacron`)
  emit one record per non-blank, non-comment line.** Variable
  assignments (`MAILTO=`, `PATH=`, `SHELL=`, `RANDOM_DELAY=`, ...) get
  their own records with signal `cron_var_assignment`.
- **`cron.periodic` emits one record per file.** Each run-parts script
  is the atomic unit.
- The `locus` field always contains the absolute file path. For
  per-line records it does NOT include the line number; the
  `content_norm_sha256` is the per-line identifier.

## Rationale

`linpersist`'s downstream value is frequency stacking (LFA). The
fundamental insight: if an attacker appends one malicious line to
`/etc/crontab`, the five legitimate lines that were already there
remain byte-identical across the fleet and stack into the "common"
bucket. Only the new line is rare.

Per-file granularity loses that property. Any modification to a
crontab — adding a benign line, fixing a typo, a package post-install
hook rewriting the file — changes the whole-file hash. Stacking
collapses to "every host has its own version of `/etc/crontab`," which
is true and useless.

Per-line granularity also matches DFIR practice. Investigators look at
cron entries one at a time, not at file diffs. Output that mirrors how
the artifact is reasoned about reduces friction at the analyst's end.

`cron.periodic` is different because each script is a self-contained
program. There is no analogue to "line N out of M" inside a script;
the script is either present or it isn't, either modified or it isn't.
Hashing the script body as one unit is the right join key.

## Consequences

- **Volume.** A host with 30 cron entries across `/etc/crontab` and
  `/etc/cron.d/*` produces ~30 records from the cron module instead of
  ~5 (one per file). Multiplied across a fleet of 5,000 hosts that is
  150k records vs 25k. Both are tractable on DuckDB / ClickHouse; the
  former produces materially better stacking.
- **Per-line records do not carry an explicit line number.** Order
  inside a crontab is not semantic (cron does not honor order), and
  the normalized content is what we want to stack on. Including a line
  number would make two hosts with the same entry in different
  positions look different, defeating the point.
- **Variable assignments stack together.** A `MAILTO=root` line
  appears once per system crontab on most hosts; it stacks to "very
  common." A `MAILTO=attacker@example.com` is a singleton and surfaces
  immediately. This is the cleanest signal we can give the backend at
  zero analysis cost.
- **Edge case: an attacker that adds a benign-looking line at the
  END of `/etc/crontab` no longer hides behind the file's hash. The
  per-line hash isolates the addition.

## Alternatives rejected

- **Per-file only.** Loses stacking resolution. Rejected.
- **Per-file PLUS per-line (envelope + entries).** Doubles record
  count and complicates the schema. The per-file envelope adds nothing
  the backend cannot reconstruct via GROUP BY `locus`. Rejected as
  unnecessary.
- **Per-entry but with line number in `locus`.** Locus would become
  `/etc/crontab:7`, breaking stacking across hosts whose line numbers
  differ. Rejected.

## References

- `man 5 crontab`, `man 5 anacrontab`.
- MITRE ATT&CK T1053.003 (Scheduled Task/Job: Cron):
  https://attack.mitre.org/techniques/T1053/003/
- Public IR write-ups (The DFIR Report, Mandiant, Red Canary)
  repeatedly document cron persistence introduced as a single appended
  line under `/etc/crontab` or `/etc/cron.d/`. Per-line stacking is
  the cheapest way to surface that pattern. Specific case references
  to be added to `docs/modules/cron.md` as we curate them.
