# ADR-0007: systemd unit/timer canonical form and granularity

- Status: Accepted
- Date: 2026-05-16
- Related: `matrix.yaml` (systemd.unit, systemd.timer),
  `internal/modules/systemd/`, `docs/normalization-rules.md`,
  ADR-0002 (record granularity).

## Context

The `systemd` module covers two site_classes — `systemd.unit`
(`T1543.002`) and `systemd.timer` (`T1053.006`) — from the same set
of loci, using the same INI parser, and emitting through the same
canonical-form pipeline. Modern Linux persistence is dominated by
systemd; getting this module's record contract right matters more
than any other v0.1.0 module.

Before writing code, four design questions needed to be pinned down,
all of which have downstream consequences on the stacking workload
and on later additions to the matrix:

1. **Granularity.** One record per unit file (`profile`-style), or
   one record per directive (`sshd`-style)?
2. **Drop-ins.** A drop-in `<unit>.d/<name>.conf` is itself a
   persistence site. Do we merge it in memory against the base unit
   and emit one resolved record, or do we emit it as an independent
   record?
3. **Canonical form.** What transformations does the normalizer
   apply so that two cosmetically-different unit files collapse to
   the same `content_norm_sha256`?
4. **Scope.** Which unit-file extensions are in scope, and what does
   the module explicitly NOT do?

This ADR pins all four. It is binding for v1 of the schema.

## Decision

### 1. Granularity: per-file

Each unit file produces exactly one record. The file's raw bytes feed
`content_sha256`; the canonical form feeds `content_norm_sha256`. A
drop-in file is its own record (see §2 below) — the per-file rule
applies to it too.

Rationale:

- A unit file is a coherent semantic entity ("the borg-backup
  service"). Stacking at unit-file granularity answers the question
  the analyst actually asks: *which hosts carry a service with
  identical canonical content X?*
- Per-directive granularity would produce 10–30 records per typical
  service, diluting the LFA signal and exploding storage cost on a
  fleet of thousands.
- Directive-level findings are not lost: they surface as flags in the
  per-file record's `signals[]` array (`systemd_multi_execstart`,
  `systemd_exec_unresolved`, `systemd_external_unit_symlink`, etc.).
- The pattern matches what the `profile` module already does and
  contrasts deliberately with `sshd`, where each directive in
  `sshd_config` *does* describe an independent policy choice worth
  stacking on its own.

`exec_target` is the resolved path of the **first** `ExecStart=`
directive in the unit (after stripping prefixes, see §3). Additional
`ExecStart=` lines (legal under `Type=oneshot`) are captured by the
content hashes; the presence of more than one fires
`systemd_multi_execstart`.

### 2. Drop-ins: independent records, no in-memory merge

A drop-in file at `<locus>/<unit>.<ext>.d/<name>.conf` is emitted as
its own record. The agent does NOT merge it into the base unit before
emitting.

- The `site_class` of the drop-in record inherits from the base
  unit's extension: `*.service.d/*.conf` → `systemd.unit`,
  `*.timer.d/*.conf` → `systemd.timer`.
- The drop-in's `locus` is the path of the `.conf` file itself, not
  the base unit's path. The base unit's path is recoverable by the
  backend as the locus's containing directory minus the `.d` suffix.
- Every drop-in record carries the `systemd_dropin` signal.

Rationale:

- A real-world ofensive pattern is dropping *only* the override file
  while the base unit stays untouched (e.g. an `override.conf` that
  appends an `ExecStartPost=curl ... | bash`). If we merged in memory,
  that record would be indistinguishable from "the base unit was
  modified". Keeping them separate preserves provenance.
- Faithfully reproducing systemd's drop-in merge semantics — which
  keys reset their list (`ExecStart=` does, with the empty-value
  reset idiom), which keys accumulate (`Environment=`, `After=`),
  which order applies — is non-trivial code that effectively
  re-implements a chunk of systemd. Per the "the agent collects, the
  backend decides" tenet, this work belongs downstream if it ever
  needs to happen.
- The backend correlates base ↔ drop-ins by `locus` prefix matching,
  which is one trivial SQL `LIKE` clause.

### 3. Canonical form

`Normalize(raw []byte) []byte` applies, in order:

1. **Line continuations joined.** Backslash-at-end-of-line joins the
   next line, recursively. A multi-line `ExecStart=/bin/sh -c '...\\\n
   ...'` hashes identically to its single-line form.
2. **Comments stripped.** Lines whose first non-whitespace character
   is `#` or `;` are dropped. Inline comments are *not* stripped —
   systemd does not parse inline comments, and a `#` inside a value
   is part of the value.
3. **Blank lines dropped.**
4. **Trailing whitespace per line trimmed.**
5. **Section names canonicalized.** `[Section]` headers are emitted
   with their canonical capitalization: `[Unit]`, `[Install]`,
   `[Service]`, `[Socket]`, `[Timer]`, `[Path]`, `[Mount]`,
   `[Automount]`, `[Swap]`, `[Target]`. systemd treats section names
   case-insensitively for parsing but conventionally capitalizes
   them; we canonicalize to that convention.
6. **Section order canonicalized.** `[Unit]` first, then the
   type-specific section (`[Service]`/`[Timer]`/etc.), then
   `[Install]`. Any other (non-standard) section follows in
   alphabetical order. systemd itself is order-insensitive, so we
   strip the cosmetic variation.
7. **Key order canonicalized — with exceptions.** Within each
   section, keys are emitted in alphabetical order, with one
   exception: the `Exec*=` family (`ExecStart`, `ExecStartPre`,
   `ExecStartPost`, `ExecStop`, `ExecStopPost`, `ExecReload`) is
   semantically order-sensitive (Pre runs before Start which runs
   before Post). Each `Exec*=` family appears in its canonical
   position by alphabetical key name, but multiple lines of the
   *same* `Exec*=` key preserve their source order verbatim.
8. **Key names lowercased for sort, preserved for emission.** Sort
   is case-insensitive; the emitted form keeps the systemd
   conventional casing (`ExecStart`, not `execstart`).
9. **Multi-value keys with set semantics sorted.** For
   `Wants=`, `After=`, `Before=`, `Requires=`, `Requisite=`,
   `BindsTo=`, `PartOf=`, `Conflicts=`, `ReloadPropagatedFrom=`,
   `PropagatesReloadTo=`, `JoinsNamespaceOf=`, `Also=` — values are
   whitespace-separated tokens with set semantics; we split, sort
   alphabetically, deduplicate, and re-emit joined by a single
   space. Same idiom used in `sudoers` aliases.
10. **`Environment=` and `EnvironmentFile=` preserved verbatim.**
    These carry ordered, often shell-quoted values where token order
    can change semantics (`PATH=$PATH:/x` depends on what `$PATH`
    expanded to a moment earlier). No reordering.
11. **`ExecStart=` value preserved verbatim including prefixes.**
    The `@`, `-`, `:`, `!`, `!!`, `+` prefixes carry behavioral
    meaning (`-` ignores failure, `@` overrides argv[0], `+`
    bypasses User=). Preserve in canonical form. Prefixes are
    stripped only when computing `exec_target` (§4).

A trailing newline terminates the canonical form. Idempotent:
`Normalize(Normalize(x)) == Normalize(x)`.

Drop-in files run through the same normalizer. Their canonical form
is just whatever sections + keys the drop-in contains, sorted by the
same rules. We do not synthesize a `[Service]` section that wasn't
present.

### 4. Scope: which extensions, what's out

**In scope** for `systemd.unit`:
`.service`, `.socket`, `.path`, `.mount`, `.automount`, `.swap`,
`.target`.

**In scope** for `systemd.timer`: `.timer`.

**Out of scope** for v0.1.0:
- `.slice` and `.scope`. Rarely a persistence site; the
  auto-generated `session-*.scope` and `user-*.slice` units add
  noise on every interactive host. Re-evaluate in v0.2.0 if
  reporting from PANIX or DFIR Report shows in-the-wild use.
- `.device`, `.snapshot`, `.busname` (deprecated). Either kernel-
  managed or vestigial; not persistence sites.

**Out of scope** for the agent generally, regardless of version:
- Calling `systemctl`, `systemd-analyze`, or any external binary.
  The agent is read-only and side-effect-free.
- Resolving the unit dependency graph (`After=`, `Wants=`, `Requires=`
  → other units). That is a relation across records, computable on
  the backend.
- Detecting whether a unit is enabled, active, or failed. Runtime
  state is not a persistence-site property.
- Parsing `Environment=` or `EnvironmentFile=` to discover embedded
  commands. Too heuristic; backend territory.
- Reading the journal (`journalctl`, `/var/log/journal/`). Logs are
  not persistence sites.

### 5. User-mode loci and timers

`systemd.timer` matrix entry is corrected to include the same
user-mode loci as `systemd.unit`: `/etc/systemd/user/`,
`/usr/lib/systemd/user/`, `/home/*/.config/systemd/user/`,
`/root/.config/systemd/user/`. User timers are a documented
persistence vector (cron-replacement use case; survives reboot when
`loginctl enable-linger <user>` has been set).

### 6. Symlinks

When walking a locus, the runner classifies each file:

- **Regular unit file** → emit a record. `locus` is the file path.
- **Symlink whose target resolves inside a walked locus** → skip.
  The target will be visited and emitted in its own walk pass; we do
  not double-count.
- **Symlink whose target resolves outside the walked loci** (e.g.
  `multi-user.target.wants/foo.service -> /opt/payload/foo.service`)
  → emit a record. `locus` is the symlink path itself; the file
  content read for hashing is the resolved target's content; signal
  `systemd_external_unit_symlink` fires.

`.wants/` and `.requires/` directories are walked the same as their
parent. Their typical contents are symlinks pointing back into the
loci, which the second rule above skips. The third rule catches the
ofensive pattern of an external-payload symlink dropped into one of
these directories.

### 7. Template instances

A file named `foo@.service` is a template. The agent emits one record
per template file, locus = the template path itself, with the
`systemd_template_unit` signal. The agent does NOT enumerate
runtime instances (`foo@bar.service`) — those are systemd-managed
state, not files on disk in the loci.

## Consequences

- **Drop-in records appear under the same site_class as their base
  unit.** Backends that filter by site_class get both base units and
  drop-ins in the same bucket; backends that want only base units
  filter on the `systemd_dropin` signal absence.
- **No external dependencies added.** The INI parser is hand-rolled
  in `internal/modules/systemd/`; it is small (sections, key=value,
  line continuations, comments) and depending on `go-ini` or similar
  would introduce a transitive surface for no real gain.
- **Section-order canonicalization changes hash digests for any
  hand-written unit that ordered sections non-conventionally.** This
  is a one-time event before v0.1.0 tags; after the tag, the
  canonical form is locked.
- **Per-file granularity caps record count.** A worst-case host with
  600 unit files emits 600 records from this module. A pathological
  fleet with 5000 hosts × 600 units = 3M records is a few hundred MB
  of NDJSON — tractable for DuckDB on a single laptop, which is the
  stacking-cookbook target.
- **Multi-`ExecStart=` units (`Type=oneshot`) emit one record.**
  `exec_target` carries the first executable; the others surface
  through `systemd_multi_execstart` and the content hashes. The
  backend can re-extract individual `ExecStart=` lines from the
  raw record if it cares.

## Alternatives rejected

- **Per-directive granularity (`sshd`-style).** Rejected because
  every reasonable LFA query begins with "group by unit file", which
  would mean joining ~20 records back together on every query.
- **In-memory drop-in merge.** Rejected: replicates systemd's merge
  semantics inside the agent, loses provenance of which override
  contributed which directive, and the analytic gain (one resolved
  view per unit) is exactly the join the backend can do trivially.
- **Strip `ExecStart=` prefixes from the canonical form.** Rejected:
  `-` (ignore failure) and `+` (bypass `User=`) are exactly the
  prefixes an attacker would use; canonicalizing them away erases
  the signal.
- **Include `.slice` and `.scope` in v0.1.0.** Rejected: every
  active session generates a transient scope/slice, dwarfing the
  signal in records-per-host without a documented ofensive use.
- **Resolve `ExecStart=` with the agent's `$PATH`.** Rejected: the
  agent's environment is irrelevant to the target host's unit-run
  context. systemd uses a documented static default PATH for units
  unless overridden; we follow that.

## References

- `systemd.unit(5)`, `systemd.service(5)`, `systemd.timer(5)`,
  `systemd.exec(5)` — authoritative grammar and semantics.
- `systemd.unit(5)` "TOP-LEVEL DROP-IN DIRECTORIES" — drop-in
  resolution order. We do not implement the resolution; we cite it
  so a backend implementer can.
- MITRE ATT&CK `T1543.002` (Create or Modify System Process:
  Systemd Service), `T1053.006` (Scheduled Task/Job: Systemd Timers).
- ADR-0002 — record granularity for `cron`. Different decision
  (per-line) for different grammar (one schedule entry per line);
  the framing here cites that explicitly so future readers see the
  pattern was deliberate.
