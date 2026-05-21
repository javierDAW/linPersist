# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-05-21

### Added (v0.3.0 release closure — coverage of v0.3.0-coverage modules)
- **Golden test suites for the three v0.3.0-coverage modules**
  (`linger`, `tmpfiles`, `sysusers`). Per-module:
  - `internal/modules/<name>/<name>_test.go` follows the existing
    `cron`-style harness: `TestGolden` walks
    `internal/testdata/golden/<name>/<case>/rootfs/`, normalizes
    perms, stamps mtimes to the project-wide `fixedMtime`
    (`2026-04-01T00:00:00Z`), runs `Collect` with
    `Now=2026-05-12T10:00:00Z`, redacts volatile fields
    (`owner_uid`/`owner_gid` to 0, drops `ctime`/`atime`/
    `non_root_owner`), sorts by `(locus, content_norm_sha256)`
    and compares NDJSON byte-for-byte. `-update` flag (and
    `LINPERSIST_UPDATE_GOLDEN=1`) regenerate frozen output.
  - Fixture coverage: linger 5 cases (root-only, non-root-user,
    multiple-users, with-subdir, numeric-username), sysusers 7
    cases (happy, uid-zero-implant, quoted-gecos,
    comments-and-blanks, empty-file-envelope, usr-lib-alt-loci,
    non-conf-skip), tmpfiles 7 cases (happy, creates-payload-at-
    boot, X11-allow-list, glob-template-skipped, non-create-
    types, multi-loci, empty-file-envelope).
  - Coverage results (`go test -race -coverprofile`): linger
    90.4 %, sysusers 86.0 %, tmpfiles 85.7 % -- all comfortably
    above the 70 % bar.
  - Includes the ADR-base-mandated normalization equivalence
    tests: two semantically-equivalent inputs produce identical
    `content_norm_sha256` (whitespace collapse for tmpfiles /
    sysusers; username identity for linger).
- **Module reference docs** under `docs/modules/`:
  `linger.md`, `tmpfiles.md`, `sysusers.md`. Each documents loci,
  format, canonical form, ExecTarget category, signals (module-
  specific + inherited), known false-positive patterns,
  documented in-the-wild use, and what the module deliberately
  does NOT do. Format mirrors the existing `docs/modules/systemd.md`.

### Documented
- **`docs/stacking-cookbook.md` Q9 section** now carries the
  ADR-0014 calibration explicitly. New "Calibration: what
  `exec_target` means" block under Q9 explains the three
  categories (`run-the-binary` populate, `touch-this-path-but-
  no-exec` skip, `marker-only` skip) and the heuristic question
  for module authors.
- **`cmd/linpersist-report/stats.go`** -- `ExecInTmpRow` struct
  doc and `computeQ9` header comment now mirror the cookbook
  text and cite ADR-0014. Operators reading the Go source land
  on the same rule the SQL operator does.

### Verified (v0.3.0 release gate against lab-realistic)
- 75-host fleet round-trip with the v0.3.0 HEAD binary:
  35,349 records (up 12.5 % from v0.2.0's 31,433), Q7 = 22
  (13 critical + 9 high), Q4 = 6, Q9 = 17, Q11 = 6 -- all
  byte-identical to the v0.2.0 baseline (the new modules emit
  records but the lab does not seed implants in their shapes,
  so no new rule fires; the lift is structural-coverage, not
  detection-envelope).
- Benchmark documented at `docs/benchmarks/v0.3.0-realistic.md`.
- 25 packages green under `-race`; `linger`, `sysusers`,
  `tmpfiles` no longer report `[no test files]`.
- `make audit` clean: 32 implemented, 0 drift.
- `make detgen-verify` clean: `tools/stack_demo.sql` matches
  `detections.yaml`.


### Added (v0.3.0-coverage — orphan-signal rules + systemd structural family)
- **10 new detection rules for previously-orphaned signals**. The
  catalog already emitted these signals from the agent side but no
  rule in `detections.yaml` was promoting them from Q5 visibility
  to Q7 actionability:
  - `ld_preload_set_with_non_package` — LD_PRELOAD injection from
    outside the package universe.
  - `polkit_admin_rule_implant`, `polkit_yes_constant_implant` —
    polkit policy edits recent or non-root-owned.
  - `sshd_root_login_enabled` — `PermitRootLogin yes` explicit.
  - `sshd_authorized_keys_command_external` — `AuthorizedKeysCommand`
    pointing at non-package or orphan binary.
  - `udev_run_with_non_package` — udev `RUN+=` launching unmanaged
    binary.
  - `sysv_external_init_symlink_implant` — `rcN.d/` symlink outside
    `init.d/`.
  - `systemd_install_alias_external_implant` — `[Install] Alias=`
    resolving outside walked loci.
  - `xdg_autostart_unmanaged` — XDG autostart pointing at
    non-package binary.
  - `passwd_empty_password_account` — `/etc/shadow` entry with
    empty password field.
- **Three new modules: systemd structural family (ADR-0014)**.
  - **`systemd.linger`** (~190 LOC). One record per
    `/var/lib/systemd/linger/<user>`. Signal
    `systemd_linger_non_root` for any username other than "root".
    MITRE T1546.
  - **`systemd.tmpfiles`** (~385 LOC). Per-directive granularity
    across `/etc/tmpfiles.d/`, `/usr/lib/tmpfiles.d/`,
    `/run/tmpfiles.d/`. Parser handles the
    `type path mode user group age argument` grammar with quoted
    segment support. Signal `tmpfiles_creates_under_tmp` for
    create-class type letters (f F w d D L C c b p) targeting
    tmp-class paths. MITRE T1543.002.
  - **`systemd.sysusers`** (~349 LOC). Per-directive granularity
    across `/etc/sysusers.d/`, `/usr/lib/sysusers.d/`. Parser
    handles `type name id "gecos" home shell`. Signal
    `sysusers_uid_zero` for u-type directives with id=0 and
    name!=root. MITRE T1136.001.
- **Three new detection rules** for the new signals:
  - `tmpfiles_creates_payload_at_boot` (critical)
  - `sysusers_second_uid_zero` (critical)
  - `systemd_linger_non_root_account` (high)
- **`matrix.yaml` extended** to 32 site_classes total
  (`+systemd.linger`, `+systemd.tmpfiles`, `+systemd.sysusers`);
  `make audit` reports `32 implemented, 0 drift`.
- **`tools/stack_demo.sql` Q7 block regenerated** to 23 disjuncts
  (10 pre-existing + 10 orphan-signal rules + 3 structural family);
  `make detgen-verify` clean.
- See [ADR-0014](docs/adr/0014-systemd-structural-family.md) for
  the design rationale of the three structural modules.

### Verified (v0.3.0-coverage against lab-realistic)
- 75-host fleet round-trip with the expanded rule set: Q1 / Q4 / Q7
  / Q8 / Q11 counts byte-identical to v0.2.x-tune. The new rules
  are pre-armed for real-fleet deployments; the lab containers do
  not exercise linger / tmpfiles / sysusers nor the orphan-signal
  scenarios.
- 22 packages green under `-race` including the new `linger`,
  `tmpfiles`, `sysusers` packages and the cross-source emission
  audit against the expanded signals catalog (43 signals total,
  up from 40).

### Added (v0.2.x-tune — FP calibration + new vectors + severity output)
- **`signals_none` predicate (schema v1 additive extension)**. The
  main FP-suppression knob: a detection now declares signals that
  must NOT be present for it to fire. Loader rejects signals that
  appear in both a positive predicate and `signals_none` (rule
  could never fire) and rejects detections populated only with
  `signals_none` (would be a blanket positive disguised as
  negative). Matcher short-circuits on it first; SQL generator
  emits `NOT list_contains(signals, 'x')` clauses. Wire format
  unchanged (`schema_version: 1`); rules that don't use the field
  parse identically. See ADR-0013 update.
- **Refined the four highest-FP detections** in
  `internal/detections/detections.yaml`:
  - `shell_init_remote_fetch` now requires *piped-to-shell* patterns
    (`| sh`, `| bash`, `|sh `, `|bash `, `curl | `, `wget | `)
    rather than raw `curl` or `wget` substrings. Drops the dotfile
    installer and rustup/homebrew/nvm FPs that flood real fleets.
  - `motd_remote_fetch` got the same patterns. Drops the
    `update-notifier`-on-Ubuntu FP and similar legitimate HTTP
    motds.
  - `sysv_init_tmp_reference` now requires *implant-style* /tmp
    references (`. /tmp/`, `exec /tmp/`, `bash /tmp/`, `sh /tmp/`,
    `/tmp/.` dot-prefixed hidden dir) instead of any mention of
    `/tmp/`. Drops mktemp / lock-file FPs in legacy sysv scripts.
  - `kmod_install_directive_implant` now requires the conjunction
    of `kmod_install_directive` with one of `interpreter_in_tmp`,
    `exec_target_orphan`, `non_package_path`, or `shell_indirect`.
    Drops the dist-alsa / nvidia / wireguard helpers that baseline
    every distro. The `shell_indirect` term keeps the lab-canonical
    implant pattern (`install foo /bin/sh -c '...'`) detected even
    when the shell is package-managed.
  - `sudoers_nopasswd_all_backdoor` left as-is on purpose. The real
    FP channel is CI service accounts (jenkins, gitlab-runner,
    ansible, terraform-runner) with legitimate `NOPASSWD: ALL`.
    Pure-signal calibration cannot disambiguate without role tags
    (peer-group LFA, v0.3.1) or cross-record correlation with
    `passwd.user` (shell != nologin). The detection description now
    documents the expected FP channel explicitly so the analyst
    knows what to ignore until v0.3.1 lands.
- **Three new detections** for signals that already existed in the
  catalog but had no corresponding rule:
  - `pam_module_in_tmp` — PAM stack loads a `.so` from a tmp-class
    directory (Volexity / DFIR Report implant pattern).
  - `systemd_external_unit_symlink_implant` — `.wants/.requires`
    symlink resolves outside the walked unit loci (payload kept
    under `/opt`, `/tmp`, `/var/tmp`, ...).
  - `grub_init_override` — GRUB cmdline carries an `init=` override
    that replaces pid-1 at next boot.
- **Severity-tiered output**. The Q7 `RollCallRow` now carries
  `MaxSeverity` (the worst severity across the detections that
  fired on the record), driven by the existing `severity` field in
  `detections.yaml`. The Overview gains `SeverityCounts` populated
  after Q7 is computed. Text mode prints per-severity counts in the
  Overview block (critical / high tinted red and orange when
  non-zero) and emits a `severity` column at the front of the Q7
  table. HTML mode shows a pill row in the Q7 section, a `severity`
  column with colour-coded pills (critical / high tail-class
  palette; medium / low / info softer), and the Q7 `colspan`
  fallback bumped from 8 to 9.
- **`cmd/detgen` default path moved to
  `internal/detections/detections.yaml`**. The repo-root copy was
  removed as part of the v0.2.x-tune cleanup; the canonical file
  lives in the package directory (the only place `go:embed` can
  reach).

### Verified (v0.2.x-tune calibration against lab-realistic)
- 75-host fleet round-trip with the refined rule set: Q7 = 22 hits
  unchanged in count, distribution shifted to **13 critical + 9
  high**. Per-detection: 10× `sudoers_nopasswd_all_backdoor`, 6×
  `payload_under_tmp_via_persistence`, 6× `pam_module_in_tmp` (new),
  3× `second_uid_zero_account`, 3× `kmod_install_directive_implant`.
  Total detection-id matches = 28 over 22 unique records (records
  matching more than one rule, e.g. PAM-in-/tmp triggering both
  `payload_under_tmp_via_persistence` and `pam_module_in_tmp`).
- Fleet Q1 / Q4 / Q8 / Q11 counts byte-identical to v0.2.0-polish.
- `go test ./... -count=1` green across 22 packages including 4 new
  test cases for `signals_none` (matcher, SQL generator, loader
  rejections) and 7 new cases for the refined / new detections.
- `make detgen-verify` clean after `make detgen` regenerates the Q7
  block with the 10 rules and their `signals_none` / `signals_any`
  combinations.

### Added (declarative detections — ADR-0013)
- **Q7 clauses externalised to `detections.yaml`**. The
  cross-cutting "implant roll-call" was duplicated between
  `cmd/linpersist-report/stats.go` `rollCallMatches` (Go) and
  `tools/stack_demo.sql` Q7 (DuckDB). `[Unreleased] D1` already
  documented one round of hand-syncing the two copies. The fix:
  promote the clauses to declarative data in
  `internal/detections/detections.yaml`, with two consumers reading
  the same file. The Go-native matcher is now ~1 line that calls
  the predicate engine; the SQL `WHERE` block is regenerated from
  the same YAML by `cmd/detgen`. See ADR-0013 for the schema and
  generator decisions.
- **Schema (v1) covers the 7 current clauses with 4 predicates**:
  `signals_all`, `signals_any`, `module_in`, `content_contains_any`.
  All AND-joined within a detection; OR across detections. Nothing
  more clever than what is needed today; new predicates added
  field-by-field when a clause demands. Each detection carries
  `id` (snake_case unique), `description`, `severity`
  (info|low|medium|high|critical), `mitre` (T#### or T####.###).
- **Loader rejects ill-formed input at parse time**. Unknown
  signal names (validated against `core.KnownSignalSet` from
  ADR-0011), duplicate ids, empty `when:` blocks, bad MITRE id
  shapes, unknown severities, SQL-unsafe characters in content
  substrings — all caught before the matcher or SQL generator
  sees them. 15 golden test cases cover the happy path and every
  failure mode.
- **`internal/detections/` package** (~750 LOC) — loader, matcher,
  SQL generator, embedded copy, tests. Stdlib + `gopkg.in/yaml.v3`
  (already in `go.sum`). No new dependencies.
- **`cmd/detgen` binary** (~150 LOC) — regenerates Q7 `WHERE`
  block in `tools/stack_demo.sql` from the YAML. Substitutes only
  between `-- BEGIN GENERATED Q7 detections` / `-- END GENERATED`
  markers; rest of the SQL untouched. Three modes: rewrite,
  `--dry-run` to stdout, `--verify` for the CI release gate.
- **`make detgen-verify`** release gate. Byte-compares the
  regenerated SQL against the committed file. Added to the
  `all` chain in the Makefile next to `audit` (matrix-audit, the
  precedent from ADR-0001). Catches the realistic failure mode of
  editing `detections.yaml` and forgetting to regenerate the SQL.

### Changed (Q7 row output gains `matched_detections` column)
- **Report Q7 now shows which rule fired, not just which signals**.
  `RollCallRow` carries a new `MatchedDetections []string` field
  alongside the existing `TriageSignals`. Text and HTML
  renderers emit a new `matched_detections` column. The analyst
  no longer has to map the signal set back to a clause in their
  head — the row says `sudoers_nopasswd_all_backdoor` or
  `payload_under_tmp_via_persistence` directly. `triage_signals`
  is preserved unchanged for operator scripts that parse Q7 text
  output.

### Verified (paridad y release gate)
- **Lab-realistic 75-host fleet round-trip**: Q7 still produces
  exactly 22 rows; Q1=22, Q4=6, Q8=42, Q11=6 byte-identical to the
  v0.2.0-polish snapshot. The migration changes the implementation,
  not the analytical output.
- **`go test ./... -count=1`** green across the 22 packages
  (15 existing modules + core + matrix-audit + new
  internal/detections).
- **`go vet ./...`** clean. **`gofmt -l .`** clean. **`make
  detgen-verify`** clean against the committed SQL.

### Added (per-host dossier mode — ADR-0012)
- **`linpersist-report --host <id>` produces a single-host
  dossier**. The fleet report (Q1..Q11) answers "what is going on
  across the fleet" but every operator hits the same follow-up
  question once they have a candidate host: "tell me everything
  about *this* host". Filtering the fleet view by hostname does not
  answer that — Q3/Q5/Q6/Q10 are aggregates that collapse or
  become meaningless restricted to one host, and the fleet view
  cannot surface *missing* modules (silent collection failures).
  The new mode forks the pipeline at `main()`: with `--host` set,
  `buildDossier()` runs instead of the fleet `build()`, and the
  output goes through dedicated renderers (`renderHost` for HTML,
  `renderHostText` for text). Same `--format` / `--color` / `-o`
  flags carry across both modes. See ADR-0012 for the layout
  decisions, the rationale for omitting Q3/Q5/Q6/Q10, and the
  scalability argument (per-host artefact scales with records-of-
  that-host, not fleet size).
- **Dossier layout, top to bottom**: host header (hostname,
  host_id, os+version, kernel, arch, boot_id, collected_at, tags);
  summary card (host vs fleet record counts, modules covered,
  per-Q counts, module-gap count); **signal panel** sorted by
  fleet rarity ascending so the host's rarest fleet-wide signal
  bubbles to the top (with descriptions sourced from the ADR-0011
  signals catalog, unknown signals surfaced as `(unknown)`); per-Q
  sub-tables for Q4, Q7, Q1 (records on this host whose
  content_norm appears on no other fleet host), Q2 (per-locus
  variant of Q1), Q9, Q11 (host-scoped, alphabetical sort), Q8
  (host-scoped, >=5-record threshold preserved); module coverage
  / gap detector flagging modules with `Records == 0 AND
  FleetMedian > 0`.
- **`--host` accepts exactly one value**. Multi-host runs use a
  shell loop. Match is against `host_meta.hostname` OR `host_id`.
  No match exits 1 with a friendly "known hosts in this dataset:
  ..." listing (top 20 + "... and N more" tail so stderr stays
  manageable on multi-thousand-host fleets).
- **HTML dossier shares `assets/style.css` with the fleet report
  but loads NO JavaScript**. Single view, no tabs, no sort/filter:
  Ctrl-F replaces the fleet report's interactive controls. Result
  is a ~20 KB self-contained HTML that renders in any browser,
  email preview pane, or sandboxed ticketing viewer.
- **Text dossier reuses `ansi`, `textSection`, `maybeRed`,
  `commaInt`, `snippetTrim` from `render_text.go`** so the ANSI
  policy in ADR-0008 (TTY gate; bold headings, red Q4-positive
  counts, orange tail bucket) carries over unchanged.
- **Validation against `lab-realistic` 75-host fleet**: fleet
  report unchanged byte-for-byte (Q1=22, Q4=6, Q7=22, Q8=42,
  Q11=6); dossiers for the three Q4 hosts surface their implant +
  orphan-outside-tmp records + module gaps; signal panel renders
  rarity ranking and pulls catalog descriptions correctly.

### Added (signals catalog — ADR-0011)
- **Iterable signals catalog backed by buildtime audit tests**.
  `internal/core/signals.go` carried 40 documented `Signal*`
  constants but nothing iterated them. Three concrete failure
  modes followed: string-literal drift inside a module (the
  preceding sshd polish surfaced one), cross-binary drift between
  `tools/stack_demo.sql` Q7 and `cmd/linpersist-report/stats.go`
  `rollCallSignals` (already flagged in `[Unreleased] D1`), and no
  way for the future `detections.yaml` loader to validate
  user-supplied rule names. New `internal/core/signals_catalog.go`
  (~360 LOC) exposes the catalog as an ordered `[]SignalDef` with
  per-entry `Name`, one-line `Description`, and a declared
  `EmittedBy []string` listing the modules / core helpers that emit
  it. Lookup helpers: `SignalByName`, `KnownSignal`,
  `KnownSignalSet`. See ADR-0011 for the shape decisions (slice not
  map; declared not inferred; regex audit not AST).
- **Five internal-consistency tests** in
  `internal/core/signals_test.go`: no duplicate names; description
  non-empty, 20–200 chars, no trailing period; non-empty
  `EmittedBy`; `EmittedBy` token shape (bare lowercase module name
  or `core/<file>`); lookup helpers agree on the universe.
- **Two cross-source audit tests** in
  `internal/core/signals_emission_test.go`: every `EmittedBy`
  entry is observed in the corresponding source file (catalog
  -> code); every Signal* identifier referenced by a module or
  core helper is in the catalog and listed under that emitter
  (code -> catalog). Regex-based scan; ~50 LOC of audit per
  direction, stdlib-only, no new dependencies.

### Changed (signals constants adopted across the report binary)
- **`cmd/linpersist-report/stats.go` rolls signal references
  through `core.Signal*` constants**. `rollCallSignals` (the Q7
  triage-pill list) used to be 12 string literals; it now
  references the constants. The clauses in `rollCallMatches` no
  longer use literal map keys (`sigs["exec_target_orphan"]`) and
  instead read `sigs[core.SignalExecTargetOrphan]`. Q4's
  `containsAll(...)` and Q9's `sigSet[...]` migrated likewise.
  Build now fails on a typo or rename rather than silently
  emitting an empty `triage_signals` column. Behavioural parity
  validated against the lab-realistic 75-host NDJSON: Q1=22,
  Q4=6, Q7=22, Q8=42, Q11=6 unchanged.

### Changed (sshd signal-emission consistency)
- **sshd module emits signals via the core catalog constants
  instead of string literals**. `internal/modules/sshd/normalize.go`
  `directiveSignals()` was emitting `"sshd_permit_root_login_yes"`
  and `"sshd_authorized_keys_command"` as raw string literals
  (and the test file compared against the same literals). The
  values matched `core.SignalSSHDPermitRootLoginYes` /
  `core.SignalSSHDAuthorizedKeysCommand` by convention but nothing
  enforced the link: renaming the constants would have left the
  module silently emitting the old strings, and renaming the
  emitted strings would have left every cross-cutting consumer
  (`cmd/linpersist-report` Q7 `rollCallSignals`, the planned
  signals catalog, future `detections.yaml`) broken. Both call
  sites now reference the constants. No behavioural change for
  downstream consumers; the catalog audit work that triggered
  this change is what surfaced the inconsistency.
- **Documented the `PermitRootLogin` signal policy inline**.
  `directiveSignals()` previously had no comment justifying why
  only the literal value `yes` fires the signal while
  `without-password` / `prohibit-password` / `forced-commands-only`
  do not. `prohibit-password` is the OpenSSH default since 7.0;
  flagging it would dirty LFA across every host in the fleet and
  obscure the rare actual `yes`. The reasoning is now a paragraph
  on the function so the next person who looks at it sees the
  trade-off and the future-extension hook (a separate
  `sshd_permit_root_login_keys` signal) without re-deriving it.
- **Test coverage extended with a `prohibit-password` negative
  case**. `TestDirectiveSignals` now asserts that
  `directiveSignals("PermitRootLogin", "prohibit-password")`
  returns no signal, pinning the documented policy against
  accidental broadening.

### Changed (v0.2.0 polish — D8 no-ellipsis report)
- **D8. Report text and HTML modes no longer truncate column
  content with "…"**. Operator feedback: an analyst running triage
  needs the full snippet / locus / exec_target / signal list for
  grep / awk / copy-paste / pasting into a ticket. Truncating with
  the ellipsis character was actively hostile to that workflow.
  Changed in `cmd/linpersist-report/render_text.go`: removed all
  `trimLen` calls (12 sites across Q1, Q2, Q3, Q4, Q6, Q7, Q9, Q11)
  and the `trimLen` helper itself. The text renderer now emits the
  full string and lets `text/tabwriter` align columns as wide as
  the content requires. Changed in `cmd/linpersist-report/stats.go`:
  `snippetTrim` keeps its signature (call-site stability across 8
  call sites) but now only normalizes embedded newlines and tabs
  to spaces — no truncation. Maximum-length argument is ignored.
  HTML mode is unchanged at the Go layer; the existing
  `.tbl-wrap { overflow-x: auto; }` CSS rule makes the table
  horizontally scrollable when content exceeds the viewport, which
  is the correct browser-side behavior for inspection.

### Changed (v0.2.0 polish — D1, D2, D6, D7)
- **D1. Q7 sudoers clause requires NOPASSWD AND ALL together**.
  The v0.2.0 lab-realistic Q7 returned 210 rows, ~175 of which were
  the stock `root ALL=(ALL) ALL` line from /etc/sudoers on every
  host (the `sudoers_all_commands` signal alone). The disjunction
  also caught NOPASSWD-on-a-specific-command sudoers.d/ drop-ins
  shipped by CI tooling (e.g. `gitlab-runner ALL=(ALL) NOPASSWD:
  /usr/bin/docker`). Q7 now requires the conjunction
  `sudoers_nopasswd AND sudoers_all_commands` — the textbook
  backdoor pattern. The standalone signals are still emitted by the
  agent (other downstream queries can use them); Q7 just no longer
  treats either alone as an implant indicator. Predicted yield on
  the lab fleet: 210 -> ~30-40 rows, all real implants. Applied to
  both `tools/stack_demo.sql` Q7 and `cmd/linpersist-report/stats.go`
  `rollCallMatches` so the SQL and Go-native paths stay in sync.
- **D2. kmod skips install directive when argv[0] is modprobe
  itself**. The distro-shipped `dist-alsa.conf` and similar files
  carry `install <module> /sbin/modprobe --ignore-install ...` —
  modprobe calling itself recursively as a hardware-alias shim.
  This is configuration baseline, not a persistence vector, and the
  v0.2.0 agent fired `kmod_install_directive` + `exec_target_orphan`
  on it across both build-server-{amzn,rhel}-01 hosts (the
  exec_target /sbin/modprobe doesn't exist in stripped container
  images). New helper `isModprobeSelfCall` recognizes both the
  historical /sbin/modprobe and the usr-merged /usr/sbin/modprobe
  forms; the signal and exec_target are suppressed for matches.
  The implant pattern — argv[0] being a shell, interpreter, or any
  other binary — continues to surface. **Breaking** for the kmod
  golden test if any fixture exercises the modprobe-self pattern;
  regenerate via `go test ./internal/modules/kmod/... -update`.
- **D6. Q11 adds a sample_host column**. The Q11 row now carries
  the lexicographically-first host that produced the record (the
  unique host for single-host singletons, an arbitrary deterministic
  pick otherwise). Visible in both the HTML report (new column in
  the Q11 pane) and the text renderer. Useful for the 1-host
  singletons like `/usr/local/sbin/sync-agent` where the analyst
  would otherwise need to grep the NDJSON to find which host
  carried it.
- **D7. Q6 ssh.authkeys rows display a sensible sample_target**.
  Q6 stacks records by `exec_target_sha256` to find polymorphic
  persistence, and validly groups SSH public keys re-authorized
  across hosts (the hash of the key blob is in
  `exec_target_sha256` even when `exec_target` is empty). The row
  display previously showed an empty string for those keys,
  confusing the analyst. Now substitutes `(ssh authorized key)`
  when the record is `ssh.authkeys` with an empty `exec_target`.
  Pure display polish; no semantic change to the stacking logic.

### Fixed (lab-realistic v0.2.0 deep dive — A + B + C)
- **A. rpm provenance switched to `rpm -qa --filesbypkg`**.
  The v0.2.0 queryformat
  `[%{FILENAMES}\t%{NAME}-%{VERSION}-%{RELEASE}\n]` produced silently
  incomplete bracket-iteration on rpm 4.16+ in minimized container
  images: the lab-realistic 75-host run surfaced this as a 27-host
  systemd false-positive flood (every RHEL + Amazon Linux host
  marked /usr/sbin/sshd, /usr/lib/systemd/systemd-*,
  /usr/bin/systemctl, etc. as `non_package_path`). `--filesbypkg`
  has been stable since rpm 4.4 (2005), uses a simpler line format
  (`<package-name>  <whitespace>  <path>`), and side-steps the
  queryformat ambiguities entirely. `--nosignature --nodigest` are
  added to suppress sig/digest verification chatter. Map values
  switch from NVR to bare package name; downstream
  `exec_target_pkg` records carry just the name (consistent with
  the dpkg backend's arch-suffix-stripped form). A defensive
  `trimNVRSuffix` helper survives a future rpm release that
  re-introduces NVR in the output. See ADR-0009 update for the
  full rationale. Q5 systemd-with-`non_package_path` is expected
  to drop from 3,330 records (34 hosts) to a couple of hundred
  (real non-package units only) after this fix.
- **B. ldso.conf / ldso.confd records no longer carry exec_target**.
  Search-path directives in `/etc/ld.so.conf` and
  `/etc/ld.so.conf.d/*.conf` reference directories (e.g.
  `/usr/local/lib`, `/usr/local/lib/x86_64-linux-gnu`), not binaries
  the loader runs. The directory itself is not a load target; the
  shared libraries inside are, and those are package-owned via
  their own dpkg/rpm manifests. Treating the directory as an
  exec_target fired `non_package_path` on every host that ships
  the libc.conf / x86_64-linux-gnu.conf drop-ins -- 43 hosts each
  in the lab-realistic Q11. The fix mirrors the earlier
  `include`-directive fix from the first lab pass: the record
  still emits (the line still stacks on `content_norm_sha256`) but
  without exec_target, so the orphan / non_package_path
  enrichments stay silent. `ldso.preload` records, which DO name
  actual .so files the loader pre-loads, continue to set
  exec_target as before.
- **C. sysv module skips documentation files**. The initscripts
  package on RHEL / CentOS / Amazon Linux drops a `README` file
  under `/etc/init.d/` and `/etc/rc.d/init.d/` describing the
  deprecation of sysv init. The file is not honored as a boot
  script by any init implementation -- it is documentation -- but
  the agent was emitting it as a `sysv.init` record (15 hosts in
  the lab-realistic Q11 as a non_package_path false positive).
  `sysv.skipName` now filters files whose lowercased name is
  `readme` or whose extension is `.md`, `.txt`, `.rst`, or
  `.html`. The filter is documentation-class only; legitimate
  init scripts use no extension and are unaffected.
- Together these three fixes target the residual Q11 noise after
  the first-pass v0.2.0 precision sweep. Expected Q11 row count
  on the same lab fleet: 78 -> ~10-15, dominated by the real
  unmanaged-payload patterns (`/usr/local/sbin/sync-agent`,
  `/usr/local/sbin/borg-wrapper`, the deploy-sync.* trio across
  three hosts).

### Fixed (precision triage from lab-realistic v0.2.0 run)
- `internal/core/provenance.go` — `Resolver.LookupPath` now returns
  `PkgStatusUnknown` for any non-absolute path. Records whose
  `exec_target` is a relative name (PAM module file like
  `pam_unix.so`, PAM `@include` filename like `system-auth`, bare
  crontab command token like `test`/`cd`/`runuser`) previously
  resolved to `PkgStatusOrphan` because the dpkg/rpm path manifest
  is keyed on absolute paths. The result was 8,472 PAM false
  positives (a third of all fleet records) carrying
  `non_package_path` in the lab-realistic 75-host capture. Treating
  relative names as Unknown is the honest semantics: the resolver
  cannot answer without PATH/LD_LIBRARY_PATH resolution.
- `internal/core/provenance.go` — `Resolver.LookupPath` now retries
  the usr-merge sibling form of a missed path before returning
  Orphan. On modern Debian/Ubuntu the dpkg manifest lists files in
  their pre-merge `/lib`, `/bin`, `/sbin` form, but systemd ExecStart
  directives reference the post-merge `/usr/lib/...`, `/usr/bin/...`,
  `/usr/sbin/...` paths. The pre-fix lookup missed both directions
  because EvalSymlinks resolves /usr/lib/X to itself (the symlink
  goes the OTHER way, /lib → /usr/lib). Hundreds of legitimate
  systemd baseline records (systemd-tmpfiles, systemd-journald,
  sshd, etc.) on 27 hosts each were marked `non_package_path`
  before this fix. The new helper `usrMergeAlternates` enumerates
  the bidirectional pairs and is tested for every prefix
  combination plus the negative cases.
- `internal/modules/ssh/ssh.go` — `exec_target` on `ssh.authkeys`
  records carrying a `command="..."` forced command now contains
  only argv[0] of that command, not the full string with all
  arguments. The lab-realistic Q6 / Q11 output had three records
  with `rsync --server --sender -vlogDtprze.iLsf . /var/...` as
  `exec_target`; provenance lookup on that string always misses
  because the dpkg manifest has `/usr/bin/rsync`, not the full
  invocation. New helper `firstCommandToken` mirrors the parsing
  minimalism of `xdg.normalize.firstArg`: strips surrounding double
  quotes, splits on whitespace. **BREAKING** for golden tests that
  exercised forced commands with arguments; regenerate with
  `LINPERSIST_UPDATE_GOLDEN=1 go test ./internal/modules/ssh/...`.
- `internal/modules/ldso/ldso.go` — `recordFromConfLine` no longer
  sets `exec_target` on records emitted from an `include` directive
  in `/etc/ld.so.conf`. The directive's argument is a glob
  (`/etc/ld.so.conf.d/*.conf`) that the loader expands, not a binary
  it executes. Pretending it is one pollutes Q11 stacking: the
  lab-realistic run surfaced `/etc/ld.so.conf.d/*.conf` and the
  bare-name variant `ld.so.conf.d/*.conf` on 43 + 27 hosts
  respectively as `non_package_path`. The record is still emitted
  (the include line itself stacks fine on `content_norm_sha256`);
  it just no longer drags the orphan / non-package-path signals
  with it.
- Together, these three fixes are expected to drop Q11 from 127
  rows (mostly false positives) to ~10-15 rows dominated by the
  true unmanaged-payload patterns (`/usr/local/sbin/sync-agent`,
  `/usr/local/sbin/borg-wrapper`, `/usr/local/lib/...` search paths).
  Re-run the lab via
  `LINPERSIST_HOST_BINARY="$PWD/dist/linpersist-linux-amd64" ./lab-realistic/collect.sh`
  to verify.

### Changed (lab-realistic iteration ergonomics)
- `lab-realistic/collect.sh` accepts a new opt-in env var
  `LINPERSIST_HOST_BINARY=<absolute or relative path>`. When set,
  the named binary is bind-mounted read-only over
  `/opt/linpersist/linpersist` in every container at run time. Lets
  the operator A/B-test a fresh agent against the existing fleet in
  the ~60 seconds the docker-run loop takes, instead of the ~60
  minutes a full `build.sh` rebuild costs.
- Default behavior is unchanged: an unset `LINPERSIST_HOST_BINARY`
  runs the binary baked into each image at build time, exactly as
  before. The new path is purely additive.

### Added (kernel.grub module — T1542.003)
- `internal/modules/grub/` — new module collecting GRUB bootloader
  persistence sites. Two site_classes emitted, each with its own
  granularity:
  - `kernel.grub.config` (per-line) from `/etc/default/grub`.
  - `kernel.grub.dropin` (per-file) from `/etc/grub.d/*`.
- `internal/modules/grub/normalize.go` — two normalizers in one
  package. The config normalizer strips an optional leading
  `export ` keyword and trailing whitespace while preserving the
  exact quoting around values (the quoting changes how
  grub-mkconfig parses embedded whitespace). The dropin normalizer
  is the standard shell-style strip pass (comments, blank lines,
  trailing whitespace per line) shared with motd-shell / profile /
  sysv / atjobs / netdispatch.
- New core signal `grub_cmdline_init`: set on `kernel.grub.config`
  records whose `GRUB_CMDLINE_LINUX*` value contains an `init=`
  token. The kernel honors `init=<path>` on its command line as
  the pid-1 binary, so an attacker who can edit `/etc/default/grub`
  can substitute the system init for an arbitrary binary at the
  next boot. When the signal fires, `exec_target` is populated
  with the override path and the standard `interpreter_in_tmp` /
  `exec_target_orphan` / `non_package_path` enrichments apply.
- `kernel.grub.dropin` records set `exec_target` to the script
  path itself (same model as `cron.periodic`): `grub-mkconfig`
  executes the file at grub.cfg regeneration time.
- Three golden test cases under `internal/testdata/golden/grub/`:
  `ubuntu_baseline` (stock `/etc/default/grub` plus `10_linux` and
  `40_custom` drop-ins — multiple records, no `grub_cmdline_init`
  hits), `cmdline_init_implant`
  (`GRUB_CMDLINE_LINUX_DEFAULT="quiet splash init=/tmp/.x/bd"` —
  the textbook attack, the `grub_cmdline_init` +
  `interpreter_in_tmp` + `exec_target_orphan` signals all fire on
  one record), `dropin_backdoor` (`/etc/grub.d/45_implant` piping
  a remote payload to `/bin/sh`).
- Five parser unit tests cover basic `KEY=VALUE` extraction, the
  `export ` keyword strip, `HasInitOverride` token detection,
  `ExtractInit` path extraction, and the dropin shell-normalizer.
- `matrix.yaml` updated with the two new site_classes.
  `cmd/linpersist/main.go` and `cmd/matrix-audit/main.go` register
  the new module.
- MITRE T1542.003 (Pre-OS Boot: Bootkit). Cmdline injection alone
  is technically a sub-case of T1547 but T1542.003 is the broader
  pre-OS-tampering family the community uses for the technique.

### Added (network.dispatchers module — T1546)
- `internal/modules/netdispatch/` — new module collecting
  network-event dispatcher scripts from four daemon families:
  NetworkManager (`/etc/NetworkManager/dispatcher.d/*` plus
  `pre-up.d/`, `pre-down.d/`, `no-wait.d/`), dhclient
  (`/etc/dhcp/dhclient-{enter,exit}-hooks.d/*`), dhcpcd
  (single-file hooks `/etc/dhcpcd.{enter,exit}.hook`), and ifupdown
  (`/etc/network/if-{pre-up,up,down,post-down}.d/*`). Per-file
  granularity.
- `exec_target` set to the script file path itself (same pattern
  as `cron.periodic`): the dispatcher daemon runs the file as a
  shell script on every matching network event, granting recurring
  code execution to anyone who can write the file.
- `internal/modules/netdispatch/normalize.go` — shell-style
  canonical form. Strips `#` comments (including the shebang line
  since it is cosmetic for stacking), blank lines, and trailing
  whitespace per line. Mirrors the `motd-shell` / `profile` /
  `sysv` / `atjobs` normalizers so two scripts that differ only in
  shebang or comment noise produce identical
  `content_norm_sha256`.
- Non-executable files emit a record carrying an `errors[]` entry
  of code `NOT_EXECUTABLE`: a non-executable dispatcher script is
  a dead drop (the daemon skips it at runtime) but still worth
  surfacing because an attacker who staged a payload may have
  forgotten the `chmod +x` step.
- Three golden test cases under
  `internal/testdata/golden/netdispatch/`:
  `nm_dispatcher_clean` (two stock NetworkManager scripts plus an
  ifupdown hook for cross-daemon coverage),
  `dhclient_implant` (a `zz-update` hook under
  `dhclient-enter-hooks.d/` that fetches and pipes a payload to
  `/bin/sh` on every DHCP renewal), `dhcpcd_single_files` (covers
  the single-file `dhcpcd.enter.hook` / `dhcpcd.exit.hook` path
  that does not use a `*.d/` directory).
- Two normalize unit tests cover the shebang+comment strip and the
  cross-shebang equivalent-script collapse.
- `matrix.yaml` updated with the new `network.dispatchers`
  site_class. `cmd/linpersist/main.go` and
  `cmd/matrix-audit/main.go` register the new module.
- MITRE T1546 (Event Triggered Execution, parent technique). ATT&CK
  has no Linux-network-dispatcher sub-technique as of May 2026 --
  documented in matrix.yaml notes. PANIX, Mandiant, and The DFIR
  Report have flagged this family in real campaigns.

### Added (polkit.rules module — T1548)
- `internal/modules/polkit/` — new module collecting polkit JS rule
  files. Loci: `/etc/polkit-1/rules.d/*.rules` (admin/local rules)
  and `/usr/share/polkit-1/rules.d/*.rules` (distro-shipped rules).
  Per-file record granularity.
- `internal/modules/polkit/normalize.go` — JS comment stripper
  implemented as a small state machine respecting string literal
  boundaries. `//` and `/* */` are stripped EXCEPT when they appear
  inside `"..."`, `'...'`, or `` `...` `` literals (so a
  `"http://example.org"` value is preserved as content). Newlines
  inside block comments are kept so downstream line-based passes
  see correct geometry.
- Two new core signals: `polkit_admin_rule` (set when canonical
  content contains the `addAdminRule(` token; polkit's admin
  callback decides who can authenticate as admin, a malicious rule
  granting it to an attacker-controlled account is a textbook
  polkit backdoor) and `polkit_yes_constant` (set when canonical
  content contains `polkit.Result.YES` or `Result.YES`;
  informational on its own, high-precision when paired with
  `polkit_admin_rule` or `non_root_owner`).
- Three golden test cases under `internal/testdata/golden/polkit/`:
  `stock_polkit` (two legitimate baseline files from
  `/etc/polkit-1/rules.d/` and `/usr/share/polkit-1/rules.d/`),
  `admin_backdoor` (the textbook `addAdminRule` returning a
  user-controlled account), `string_with_slashes` (verifies that
  `//` and `/*` inside string literals are NOT stripped as
  comments — the parser respects string boundaries).
- Five normalize unit tests cover: line-comment strip, block-comment
  strip, string-literal protection, equivalent-rules canonical
  collapse, and the token-search helpers used to derive the two
  new signals.
- `matrix.yaml` updated. `cmd/linpersist/main.go` and
  `cmd/matrix-audit/main.go` register the new module.
- MITRE T1548 (Abuse Elevation Control Mechanism). ATT&CK has no
  Linux-polkit sub-technique as of May 2026 -- documented in
  matrix.yaml notes.
- `exec_target` is intentionally NOT populated for polkit records:
  rules evaluate policy decisions, they do not execute binaries.
  The standard `non_package_path` / `live_process_attached`
  enrichments therefore do not fire on this site_class.

### Added (at.jobs module — T1053.001)
- `internal/modules/atjobs/` — new module collecting `at(1)` spool
  entries. Loci: `/var/spool/at/` (most distros) and
  `/var/spool/cron/atjobs/` (alternate path). Per-file granularity.
- `internal/modules/atjobs/normalize.go` — heredoc body extractor.
  The atd-prepended header (umask, HOME=, PATH=, LOGNAME=, USER=,
  SHELL=, TERM=, cd) is intentionally NOT part of
  content_norm_sha256: it is volatile per user and would prevent two
  semantically-identical jobs scheduled by different accounts from
  collapsing into one bucket. Canonical form is the heredoc body
  (between `${SHELL:-/bin/sh} << 'MARKER'` and the closing `MARKER`
  on its own line) with `#` comments and blank lines stripped.
  Heredoc marker quoting variants (single, double, unquoted) and
  the `<<-` tabs-form are all supported.
- Hand-edited spool files that do not follow the atd layout fall
  back to hashing the raw input with the same shell-style strip
  pass. Deterministic but lower stacking yield against
  atd-generated jobs.
- `exec_target` set to the spool file path itself (same model as
  `cron.periodic`): atd executes the spool entry as a shell script.
- Three golden test cases under `internal/testdata/golden/atjobs/`:
  `basic_alice_job` (single Alice job under `/var/spool/at/`),
  `equivalent_users_collapse` (Alice job and Bob job at different
  loci with different headers but identical inner body — must
  produce the same `content_norm_sha256`), `hand_edited_spool`
  (unstructured fallback path).
- Four parser unit tests cover structured-job body extraction, the
  unstructured fallback, the cross-user collapse property
  (load-bearing for the normalize policy), and the heredoc-marker
  quoting variants.
- `matrix.yaml` updated. `cmd/linpersist/main.go` and
  `cmd/matrix-audit/main.go` register the new module.
- MITRE T1053.001 (Scheduled Task/Job: At).

### Added (xdg.autostart module — T1547.013)
- `internal/modules/xdg/` — new module collecting FreeDesktop
  `.desktop` autostart entries. Loci: `/etc/xdg/autostart/*.desktop`
  (system-wide), `/root/.config/autostart/*.desktop` and
  `/home/*/.config/autostart/*.desktop` (per-user). Per-file record
  granularity.
- `internal/modules/xdg/normalize.go` — pure-Go INI parser for the
  Desktop Entry Specification. Canonical form: sections in source
  order, keys sorted alphabetically within each section, comments
  and blank lines dropped, locale-suffixed keys
  (`Name[en]`, `Comment[de]`, ...) filtered, trailing whitespace
  stripped per value. Two semantically-equivalent `.desktop` files
  collapse to the same `content_norm_sha256`.
- `exec_target` set to argv[0] of the `Exec=` line in
  `[Desktop Entry]` with FreeDesktop field codes (`%U`, `%f`, `%i`,
  ...) stripped and surrounding double quotes removed. Field code
  `%%` is preserved as a literal `%`.
- Standard core signals fire on xdg records: `interpreter_in_tmp`,
  `exec_target_orphan`, `shell_indirect`, `unqualified_exec_target`,
  `recent_mtime_*`, `world_writable`, `non_root_owner` (gated to
  system paths so `/home/*/.config/autostart/` does not fire it for
  user-owned files), `non_package_path` and `live_process_attached`
  via the resolver + scanner from earlier phases.
- Four golden test cases under `internal/testdata/golden/xdg/`:
  `system_autostart_clean` (three stock Ubuntu entries),
  `user_autostart_implant` (single `/tmp/.cache/x/run` payload under
  `/home/alice/.config/autostart/`), `locale_keys_normalize`
  (entry with `Name[en]`, `Name[de]`, `Comment[es]`, ...; canonical
  form must contain only unlocalized keys), `root_autostart`
  (`/root/.config/autostart/admin-helper.desktop`).
- Six parser unit tests in `xdg_test.go` cover: basic section
  parsing, locale-key drop, equivalent-input canonical collapse,
  Exec= field-code stripping, no-Exec case (Type=Link), and the
  `%%` literal escape.
- `matrix.yaml` updated with the new `xdg.autostart` site_class
  entry. `cmd/linpersist/main.go` and `cmd/matrix-audit/main.go`
  register the new module.
- MITRE ATT&CK T1547.013 (Boot or Logon Autostart Execution: XDG
  Autostart Entries).

### Added (proc.live — live-process correlation)
- `internal/core/proclive.go` — new `LiveProcessSet` interface
  (`Warmup(ctx) / Has(path) bool`) with two implementations:
  `NoopLiveProcessSet` (default, returns false) and `ProcLiveScanner`
  (production, walks `/proc/[0-9]+/exe`). One-shot snapshot at agent
  startup; the set is frozen for the remainder of the run so NDJSON
  output stays deterministic.
- New core signal `live_process_attached`: emitted on records whose
  `exec_target` matches a path in the live-process set. Pair with
  `non_package_path` for the high-precision "unmanaged binary,
  currently running" pattern that characterizes an active implant.
- `core.AnnotateLiveProcess(rec, lps, target)` helper. Every module
  calls it immediately after `core.AnnotateExecTargetProvenance` at
  every record emit site (15 call sites total across the 13 modules,
  paired 1:1 with the provenance annotator).
- Resolver lifecycle parallels provenance: graceful degrade on
  hidepid (EACCES on `/proc/<pid>/exe`), ESRCH during walk, dangling
  symlinks, and the literal `" (deleted)"` suffix Linux appends when
  the underlying binary has been unlinked while the process holds
  it open. Container namespace semantics documented in ADR-0010
  (agent sees only what its PID namespace sees).
- `cmd/linpersist`: new flags `--live-process-timeout` (default
  `core.DefaultProcLiveBuildTimeout`, 5 s) and `--no-live-process`
  (skip the snapshot; no `live_process_attached` ever emitted).
  Warmup runs in `main` before the runner starts with its own
  bounded context, identical pattern to provenance.
- All 13 module Options structs carry a `LiveProcessSet
  core.LiveProcessSet` field. Nil defaults to `core.NoopLiveProcessSet{}`
  in `New()`, preserving byte-for-byte golden test compatibility.
- Fifteen fresh unit tests in `internal/core/proclive_test.go`
  cover: happy path with fake /proc fixtures, missing /proc root,
  pre-warmup lookups, the deleted-suffix strip, non-PID directory
  filter, dangling symlink tolerance, missing-exe-link degrade
  (hidepid mirror), idempotent Warmup, concurrent Has under race,
  bounded build timeout, AnnotateLiveProcess match/no-match/nil-safe
  paths, and the isPIDDirName digit-only filter edge cases.
- ADR-0010 added: `docs/adr/0010-proc-live-correlation.md`
  documenting the snapshot semantics, the hidepid degrade policy,
  the symlink-at-lookup rule, and the rejected alternatives
  (continuous polling, eBPF, ps shell-out, deferral to v0.3.0).

### Added (Q11 — orphan outside tmp-class dirs)
- New cookbook query Q11 in `tools/stack_demo.sql`. Surfaces every
  `exec_target` flagged `non_package_path` AND NOT under any of the
  four tmp-class prefixes (`/tmp/`, `/var/tmp/`, `/dev/shm/`,
  `/run/shm/`). Catches the disciplined-attacker pattern that drops
  the payload under `/opt/`, `/var/lib/`, `/srv/`, `/usr/local/` —
  which Q4 and Q9 miss entirely. LFA-sorted: single-host targets
  bubble to the top.
- Q11 implemented row-for-row in `cmd/linpersist-report/stats.go`
  (`computeQ11`, `OrphanOutsideTmpRow`). Surfaces as a new overview
  card "Q11 orphan outside /tmp" alongside Q4/Q7 in the HTML report
  and the text renderer, plus a dedicated Q11 tab pane with the
  standard sort/filter widgets.
- `docs/stacking-cookbook.md` updated from "ten" to "eleven canonical
  queries"; new "Query 11" section documents the predicate, the
  Q9 ∪ Q11 partitioning, and the three expected false-positive
  classes (vendor-installed software, operator deploys, provenance
  build failure). The "Recommended workflow" section reorders triage
  to insert Q11 between Q9 and per-module deep dives.
- `docs/schema-v1.md` refreshed: the `exec_target_pkg` and
  `exec_target_pkg_status` rows now spell out that the resolver is
  live, `unknown` is never serialized (its absence is the signal),
  and `error` is distinct from `unknown`. Cross-references ADR-0009.

### Added (provenance, v0.2.0 cycle)
- `internal/core/provenance.go` — real dpkg + rpm provenance resolver,
  replacing the v0.1.0 stub. Detection of the host package manager
  reads `/etc/os-release` ID and ID_LIKE plus the presence of
  `/var/lib/dpkg/info/` or `/var/lib/rpm/`. The detection rules are
  documented in `docs/adr/0009-provenance-dpkg-rpm.md`.
- dpkg backend: pure-Go walker over `/var/lib/dpkg/info/*.list`. Builds
  a path → package map in one pass; first-wins on file conflicts; the
  `:amd64` arch suffix in package names is stripped; the conventional
  `/.` entry is filtered.
- rpm backend: bounded shell-out to `/usr/bin/rpm` (or `/bin/rpm`) via
  `exec.CommandContext` with the queryformat
  `[%{FILENAMES}\t%{NAME}-%{VERSION}-%{RELEASE}\n]`. ADR-0009 explains
  why pure-Go RPM DB parsing was rejected (BDB + SQLite + ndb dep
  cost vs. shell-out's reliability and triviality on every rpm host).
- `core.Provenance` interface (small read API consumed by modules)
  with `Warmup(ctx) / LookupPath(path) (pkg, status)` methods.
- `core.NoopProvenance` zero-value implementation: every lookup
  returns `PkgStatusUnknown`. Used as the default value when
  `Options.Provenance` is left nil (preserves byte-for-byte golden
  test compatibility from v0.1.0).
- `core.AnnotateExecTargetProvenance(rec, prov, target)` helper —
  every module calls it once per emit, immediately after setting
  `rec.Signals`. Populates `Record.ExecTargetPkg` and
  `Record.ExecTargetPkgStatus` when the lookup is informative;
  appends `SignalNonPackagePath` when the target is `orphan`.
  `Unknown` is treated as "resolver had nothing to say" and produces
  no on-wire fields, so existing goldens stay identical.
- Resolver lifecycle: `Warmup` is idempotent, runs in `main` before
  the runner starts, and is bounded by `--provenance-timeout` (default
  30 s). After warmup, `LookupPath` is a lock-free map read. A failed
  build records the error once and every subsequent lookup degrades
  to `PkgStatusError` (distinct from `Unknown`).
- `cmd/linpersist`: new flags `--provenance-timeout` (caps the warmup
  phase, default `core.DefaultProvenanceBuildTimeout`) and
  `--no-provenance` (skip the resolver entirely; every exec_target
  reports as `Unknown`). Warmup is charged against its own deadline,
  outside the per-module timeout, so a slow dpkg/rpm build can never
  eat into a module's 30 s budget.
- All 13 modules (`cron`, `ldso`, `ssh`, `sshd`, `sudoers`, `pam`,
  `passwd`, `profile`, `systemd`, `sysv`, `motd`, `kmod`, `udev`)
  carry a uniform `Options.Provenance core.Provenance` field. The
  field defaults to `core.NoopProvenance{}` inside each `New` so any
  caller that left it unset continues to compile and behave exactly
  as in v0.1.0.
- Twelve fresh unit tests in `internal/core/provenance_test.go`
  cover: detection on synthetic /etc/os-release fixtures, ID_LIKE
  multi-token parsing, dpkg happy path with fixture .list files,
  file-conflict first-wins policy, the `/.` filter, the `:arch`
  suffix strip, the missing-info-dir degrade, missing-package-manager
  hosts (PkgMgrNone returns Unknown), pre-warmup lookups, rpm
  shell-out happy path against a fake-rpm shell script, rpm binary
  missing → Error, rpm non-zero exit → Error, build-timeout
  enforcement, idempotent Warmup, and a concurrent-lookup load test.
- ADR-0009 added: `docs/adr/0009-provenance-dpkg-rpm.md`.

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
- The report covers **all ten canonical cookbook queries (Q1-Q10)**
  plus a fleet overview: per-module / per-site_class / per-os_id
  counts, LFA stacking histogram (singletons highlighted), signal
  distribution bar chart. Each table is sortable by header click and
  filterable via a live search input. Dark and light themes
  auto-switch via `prefers-color-scheme`.
- Q7-Q10 Go-native implementations in `cmd/linpersist-report/stats.go`
  bring the report binary to parity with `tools/stack_demo.sql` so
  analysts no longer need DuckDB at view time:
  - **Q7 implant roll-call**: cross-cutting union of seven disjoint
    clauses (orphan+tmp, sudoers backdoors, uid=0 backdoors, kmod
    install directives, profile/motd curl|wget content, sysv
    referencing `/tmp`). Validated against a 25-host synthetic fleet
    with 13 documented implants: 13 rows, zero false positives.
  - **Q8 recent-mtime concentration**: per `(host, module)`
    aggregation surfacing config-management pushes or
    post-compromise sweeps. Filters on `count >= 5`.
  - **Q9 exec targets in tmp-class directories**: Q4's open half --
    `exec_target` under `/tmp/`, `/var/tmp/`, `/dev/shm/`,
    `/run/shm/` regardless of orphan state. Q9 minus Q4 yields
    "currently armed implants".
  - **Q10 per-host collection health**: records, distinct modules,
    distinct site_classes, recent-mtime count. Sort ASC for silent
    agent failures; DESC for anomaly outliers. Run first on any
    new dataset.
- Overview cards expanded from six to eight: added "Q7 roll-call"
  and "Q8 mtime spikes" alongside the existing host/record/module/
  site_class/singleton/Q4 counts.
- `tools/stack_demo.sql` curated to **ten expert non-redundant
  queries** (Q1-Q10) suitable as a default DuckDB pack. Header now
  documents the `./tools/ingest.sh -q tools/stack_demo.sql /fleet/`
  invocation contract. Q1-Q6 retained verbatim; Q7-Q10 added with
  the same clause logic the Go report uses, so the SQL and Go
  outputs agree row-for-row.
- `docs/stacking-cookbook.md` intro changed from "six" to "ten
  canonical queries". New "Recommended workflow" reorders triage:
  Q10 first (health check), Q7 second (roll-call), Q8/Q9 third.
  New "Running the queries" section documents the
  `tools/ingest.sh -q` argument.
- `docs/report.md` documents all ten Q-sections, the
  Go-native-no-DuckDB-at-runtime contract, and the empirical
  performance envelope (6k records ≈ 50 ms; 600k records ≈ 2.5 s).
- `Makefile` now drives a `BINARIES := linpersist linpersist-report`
  variable so the build/verify targets iterate over both binaries
  without duplication.

### Changed (README scope)
- `README.md` "Lab" section replaced with a "Validation" section.
  Removed all references to `lab/` and `lab-large/` -- those
  directories are local development infrastructure, are
  `.gitignored`, and never ship with the project. The new
  Validation section documents the project's actual public testing
  surface: golden fixtures per module, unit tests for normalizers
  and parsers, the `matrix-audit` release gate, and the 25-host /
  13-implant synthetic-fleet methodology used to validate Q7's
  zero-false-positive claim. The text is honest about what is
  shipped vs. what is local-only.

### Changed (README rewrite)
- `README.md` fully restructured around a clearer narrative: a
  60-second quickstart (3 commands to a report), an explicit
  two-binary overview, a "two analysis paths" section that
  prescribes when to use the Go-native report vs. the DuckDB
  cookbook, a "where the queries live" section with the same
  10-query roster in both SQL and Go form, and a "bring your own
  queries" snippet showing the `tools/ingest.sh -q FILE` invocation.
- New SVG diagrams `docs/img/pipeline.svg` (collection → agent →
  aggregation → two analysis paths) and `docs/img/queries.svg`
  (10 queries with two implementations that are kept in sync
  row-for-row). Hand-written, minimal monochrome, uses
  `currentColor` so dark/light themes work without an extra
  stylesheet.
- All references to "six cookbook queries" replaced with "ten" --
  the README was lagging the Q7-Q10 expansion.

### Changed (ingest.sh ergonomics)
- `tools/ingest.sh` now defaults `-q` to the bundled
  `tools/stack_demo.sql` (resolved relative to the script's own
  location, not the caller's `cwd`). The bare invocation
  `./tools/ingest.sh fleet/` now does what most operators expected
  on their first run: load the NDJSON and run the 10 cookbook
  queries. Pass `-q ''` to keep the previous load-only behavior
  (useful when combined with `-o fleet.parquet` for a pure
  export). Help text and examples updated; the "six demo queries"
  language is gone.

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
