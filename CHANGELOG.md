# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — anti-evasion detection (defender-aware attacker boundary)
- **Central `recent_ctime_{7d,30d}` anti-timestomp signal.** Computed
  once at the emit sink (`cmd/linpersist/main.go`) for every record that
  carries a ctime, rather than wired into each module's `baseSignals` —
  the sink is the single choke point where `CTime` and `CollectedAt` are
  already populated, so the signal lands uniformly across all modules
  with zero per-module edits. `touch -d`/`utimes(2)` back-date mtime but
  cannot move ctime backward; a record with `recent_ctime_7d` but no
  `recent_mtime_*` is the timestomp tell. Scored by the
  `timestomp_recent_ctime_stale_mtime` detection — **calibrated against
  the nspawn lab to severity high and gated on `package_file_tampered`**:
  validation showed the bare ctime-vs-mtime rule fires on ~2000
  records/host on ANY image- or tarball-provisioned host (cloud images,
  containers, debootstrap, `rsync -a`, restore-from-backup) because tar
  extraction resets ctime while preserving the old mtime. Requiring the
  tamper co-signal makes the rule immune to that benign class by
  construction (extraction never alters content), while the
  dropped-payload timestomp variant stays covered by
  `payload_under_tmp_via_persistence`. The `recent_ctime_*` signal
  itself is still emitted for backend stacking.
- **dpkg package-file integrity (`package_file_tampered`).** The
  provenance resolver gained `VerifyPath`, which compares a package-owned
  file against the hash dpkg recorded at install. It parses BOTH
  `/var/lib/dpkg/info/*.md5sums` (regular files) AND the `Conffiles:`
  stanzas of `/var/lib/dpkg/status` (registered conffiles such as
  `/etc/crontab`, which are absent from `md5sums` by design) — so the
  "append a line to a package-owned config" persistence shape, which
  emits no orphan/tmp/non_package signal, no longer evades on a dpkg
  host. Drives the `package_owned_file_tampered` detection (severity
  medium; FP class: legitimate conffile edits, which `dpkg --verify`
  also reports). Results are memoized per path. **dpkg only**; `rpm -V`
  and apk `Z:` verification are honest TODO extensions tracked against
  `Resolver.VerifyPath`. Verification wired via an interface upgrade in
  the sink, so `--no-provenance` / `NoopProvenance` skip it cleanly.
- **Three evasion lab implants** (`lab-realistic/implants/`):
  `evade-timestomp` (back-dated mtime), `evade-pkg-tamper` (append to
  package-owned `/etc/crontab`) and `evade-fleetwide-clean` (a clean
  systemd unit planted identically fleet-wide). The last is **expected
  to evade** — it is the honest boundary of singleton stacking, where a
  MISS is the documented finding, not a bug. Empirical re-scoring of all
  three awaits a Debian lab rebuild (the realistic lab is currently torn
  down); `rpm`/`apk` integrity paths cannot be exercised without a Rocky
  rebuild and are left unverified by charter.

### Security — hardening across the report binary, collector and detections loader
- **`linpersist-report` text output now neutralizes terminal-control
  sequences in untrusted, record-derived fields.** The fleet report,
  per-host dossier and diff renderers wrote attacker-influenced values
  (`locus`/path, `content_snippet`, `exec_target`, hostname, os_id,
  agent_version, module/site_class, signal lists) verbatim to the
  analyst's TTY. A compromised monitored host could embed ANSI
  cursor-movement / line-erase / OSC sequences in a filename or file
  content so that, when the analyst viewed the report in a terminal,
  the host's own singleton row was overwritten or hidden — defeating
  the singleton-hunt the tool exists to perform. New `safeCell` helper
  (`cmd/linpersist-report/render_common.go`) rewrites every C0 control,
  DEL and C1 control as a visible `\xHH` escape; all three text
  renderers route record-derived cells through it (via `safeCell` or
  the `fprintfSafe` wrapper), leaving the renderer's own color escapes
  intact. The HTML report was already safe (`html/template`
  auto-escaping). Tests: `render_sanitize_test.go`.
- **A single oversized NDJSON line no longer aborts the whole fleet
  report.** `readFile` previously used a `bufio.Scanner` whose
  `ErrTooLong` propagated up and failed the entire load, so one corrupt
  or hostile host file (a line > 4 MiB) blinded the analyst to every
  other host. It now reads via a bounded `bufio.Reader`, counts the
  oversized line as one skipped line, and continues.
- **Collector file reads are now hardened against TOCTOU swaps.** Every
  module previously did `os.Lstat` (size / regular check) then
  `os.ReadFile(real)`, leaving a window in which an attacker with write
  access to a scanned directory could swap the target for a much larger
  file (unbounded read → memory pressure) or a FIFO/device (a read-only
  open blocks until the module's 30s deadline). New
  `core.ReadFileCapped` / `core.OpenRegularNoBlock`
  (`internal/core/readfile.go`) open with `O_NONBLOCK`, `fstat` the
  resulting descriptor to reject non-regular targets (no pre-open Lstat
  race), and bound the read with `io.LimitReader`. Symlink-following is
  preserved (several modules legitimately hash a symlinked locus's
  target). All 28 module read sites plus the streaming readers
  (`sysusers`, `tmpfiles`, `cron.periodic`) were migrated. Tests:
  `internal/core/readfile_test.go`.
- **Detections loader now rejects SQL-unsafe characters in every value
  the SQL generator interpolates.** `content_contains_any` was already
  checked, but `module_in` / `site_class_in` — interpolated into
  `module = '<v>'` / `site_class = '<v>'` by `detgen` — were not, an
  asymmetric-escaping footgun should the rule source ever become less
  trusted. The loader now rejects `'` and `\` in those fields and, when
  a module registry is supplied, validates `module_in` against it (the
  previously-unused `modules` argument). No effect on the committed
  `detections.yaml`; `detgen --verify` output is unchanged. Tests:
  `internal/detections/detections_test.go`.

## [0.5.0] - 2026-05-24

v0.5.0 lands the cloud-native sprint deferred from v0.4.0: three new
persistence modules (`dbus`, `cloudinit`, `k8sstatic`) covering five
site_classes on the cloud / container surface, plus Alpine `apk`
provenance so package-managed binaries on Alpine-based hosts no longer
surface as `non_package_path` noise.

Matrix coverage: 39 → 44 site_classes implemented. Modules: 22 → 25
(three new packages). Catalog: no new signal names — the new modules
plug into the existing shared signals (`recent_mtime_*`,
`world_writable`, `non_root_owner`, `interpreter_in_tmp`,
`exec_target_orphan`, `shell_indirect`, `unqualified_exec_target`) via
`EmittedBy` expansions.

### Added — three cloud-native modules
- **`dbus` (T1543, Create or Modify System Process)** —
  `internal/modules/dbus` walks
  `/usr/share/dbus-1/{system,session}-services/` and
  `/etc/dbus-1/{system,session}-services/`. One record per `*.service`
  file. Parses the freedesktop INI (`[D-BUS Service]` section, `Name`,
  `Exec`, `User`, `SystemdService` keys) and extracts argv[0] of
  `Exec=` as ExecTarget; honours POSIX-sh single-level quoting (paths
  with spaces are legal freedesktop syntax). New site_classes:
  `dbus.system`, `dbus.session`. The new module needed zero net-new
  helpers — it consumes the shared `shellInterps`, `TmpDirs`,
  `isSystemPath` from `internal/core/`.
- **`cloudinit` (T1543 + T1547)** — `internal/modules/cloudinit` walks
  `/etc/cloud/cloud.cfg`, `/etc/cloud/cloud.cfg.d/*` and the three
  per-execution-phase script directories
  (`/var/lib/cloud/scripts/{per-boot,per-instance,per-once}/`). New
  site_classes: `cloudinit.config` (YAML configs), `cloudinit.script`
  (executable hooks). Scripts emit `ExecTarget = locus` (self-exec
  model, same shape as `cron.periodic` / `netdispatch`).
  Non-executable scripts emit a `NOT_EXECUTABLE` error envelope —
  cloud-init silently skips them, so the analyst sees the dead drop
  rather than a live vector and the implant doesn't disappear from
  triage.
- **`k8sstatic` (T1543.005, Container Service)** —
  `internal/modules/k8sstatic` walks `/etc/kubernetes/manifests/` (the
  kubelet `pod-manifest-path` default). One record per Pod manifest
  YAML. Parses a minimal subset of the Pod spec via `yaml.v3` — kind,
  namespace, name, first container's image and command — enough to
  surface the persistence target without modelling the full schema.
  `content_norm_sha256` is keyed on the canonical rendering of those
  fields so block-style and flow-style YAML representing the same Pod
  collapse into one Q1 group. `ExecTarget = first container's image
  string` so Q6 / Q12 cluster identical attacker images across the
  fleet. New site_class: `k8s.static-pod`.

### Added — Alpine apk provenance support
- `internal/core/provenance.go` learns `PkgMgrApk`. Detection runs
  off `/lib/apk/db/installed` plus an `/etc/os-release` ID match
  (`alpine`, `postmarketos`, `wolfi`, `chainguard`). `buildApkMap`
  parses the apk-tools world database record-by-record. Detection
  precedence: `apk > dpkg > rpm` when multiple package managers are
  present (rare, but possible in Alpine-on-Debian-with-chroot edge
  cases).
- Why: without this, every binary on an Alpine host surfaced as
  `non_package_path` and the whole `non_package_path` signal became
  useless noise on cloud-native fleets where Alpine is the default
  container base image.

### Tests
- Each new module ships with 6–9 unit tests covering canonical implant
  cases, classification edge cases, malformed-input envelopes, and
  stacking determinism. The apk parser is exercised via the existing
  `internal/core/provenance_test.go`.
- Stats smoke golden regenerated; five new dormant techniques now
  surface in the MITRE coverage panel.

### Notes
- `internal/modset/modset.go` is now 25 modules in alphabetical order;
  `modset_test` pins the count.
- No detection rules were added — the new modules connect to the
  existing rule vocabulary via shared-signal `EmittedBy` expansions.
  Bespoke rules over `k8s.static-pod` / `cloudinit.script` / `dbus.*`
  are deferred to a future calibration sprint once a lab fixture set
  with realistic baselines on those surfaces exists.

## [0.4.1] - 2026-05-24

Infrastructure + deliverable patch on top of v0.4.0. No collector or
report changes; ships the release pipeline and the first consultoría
deliverable kit.

### Added
- **Tag-driven release pipeline** (`.github/workflows/release.yml`):
  cosign keyless signing via OIDC, cross-arch binary builds, SHA256
  checksums, GitHub Release auto-publish on `v*` tags. Uses
  first-party `gh release create` (no race conditions vs. the previous
  `softprops/action-gh-release`).
- **`linpersist --self-sha256`** flag — prints the running binary's
  SHA256 to stdout and exits. Chain-of-custody primitive consumed by
  the engagement-kit RUNBOOK.
- **`make engagement-kit VERSION=…`** target produces a single
  client-ready tarball under `dist/`: both binaries × {amd64, arm64},
  RUNBOOK, SCOPE, LICENSE, README, CHANGELOG, golden
  `sample-report.{html,txt}`, `CHECKSUMS.txt`. Fails loudly if any
  required doc is missing so the kit never ships incomplete.
- **`docs/scope.md`** — eight sections (what the agent does, what it
  never does, evidence shape, footprint, required privileges,
  distribution integrity, source reproducibility, honest Limitations
  section). Designed to be quoted verbatim in the annex of an
  engagement contract.
- **`docs/client-runbook.md`** — bilingual EN+ES operator runbook. EN
  authoritative, ES mirror. Covers kit verification (sha256 + `cosign
  verify-blob` + `--self-sha256`), invocation patterns (Ansible
  playbook, AWS SSM RunCommand, systemd timer, manual), post-collection
  handoff, troubleshooting table, secure deletion at engagement close.

### Changed
- `actions/checkout`, `actions/setup-go`, etc. bumped to versions
  supporting Node 24 (the previous pins broke under GitHub's runner
  upgrade).
- `chmod +x` on `tools/*.sh` and `lab-realistic/*.sh` so CI runners
  can execute them.

## [0.4.0] - 2026-05-23

v0.4.0 closes the Linux MITRE bridge for the three highest-impact
persistence techniques the 18-ID matrix missed (T1546.005 trap,
T1098.007 privileged group membership, T1548.001 setuid/sgid),
finishes the Q12 worm-profile-arm consolidation deferred from
v0.3.3/v0.3.4, and lands a non-functional code-review refactor
(~1100 LOC of duplication removed) plus the first CI automation
this project has ever had.

Matrix coverage: 34 → 39 site_classes implemented. Catalog: 43 → 51
signals (+6 group membership, +2 suid/sgid). Detections: 23 → 24.
Modules: 21 → 22 (suidbits is the only new package).

### Added — three new MITRE techniques
- **T1546.005 (Event Triggered Execution: Trap)** — profile module
  scans every profile.d / bashrc / zshrc body for `trap CMD SIG…`
  lines and emits a record under the new
  `profile.trap.{system,user}` site_classes with
  `trap_command`, `trap_exit_handler` (if EXIT is in the signal
  list) and `trap_command_in_tmp` (if the command resolves under
  /tmp). Lands in v0.4.0 via the 2026-05-23 trap-detection commit.
- **T1098.007 (Account Manipulation: Additional Local or Domain
  Groups)** — passwd module reclassifies /etc/group records to a
  new `passwd.group.privileged` site_class when the group name is
  on the privileged list (wheel, sudo, docker, adm, lxd, root)
  AND at least one non-root supplemental member is present. Six
  new signals (`group_<name>_membership`), one per group, so Q1 /
  Q3 stacking can distinguish a benign baseline (engineering team
  in `docker`) from an anomaly (one host with eve in `wheel`).
  Reclassified records carry MITRE `[T1136.001, T1098.007]`.
- **T1548.001 (Abuse Elevation Control Mechanism: Setuid and
  Setgid)** — new `suidbits` module walks /usr/bin, /usr/sbin,
  /usr/local/{bin,sbin}, /opt, /home, /tmp, /var/tmp and emits one
  record per regular file with the suid (04000) or sgid (02000)
  bit set. Four site_classes split by suid-vs-sgid × system-vs-user.
  Two new signals (`suid_bit_set`, `sgid_bit_set`); pairs with the
  existing `non_package_path` to drive the new detection rule
  `suid_binary_outside_package_path` (severity: critical) in Q7.
  content_norm_sha256 is `mode_octal:basename` so legitimate
  package-managed suid binaries collapse to single Q1 rows across
  the fleet, leaving the /tmp / /home implants as Q1 singletons.

### Added — fleet engine improvements
- **Q12 worm-arm consolidation** (`internal/modules/profile/exec_target.go`):
  profile records now populate ExecTarget by scanning the script
  body for the first `. /path`, `source /path`, `exec /path` or
  leading absolute-path command. A 3-arm worm (cron + systemd +
  profile) consolidates into one Q12 cluster row instead of two.
  Closes the v0.3.3/v0.3.4 deferred item.
- **CI workflow** (`.github/workflows/ci.yml`) runs `make all` +
  `make test-race` + static-link gate on push/PR + on `v*` tags.
  Closes the discourse/praxis gap where ADR release gates only ran
  on Jarmi's laptop. A separate `duckdb-equiv` CI job installs the
  DuckDB CLI and runs the new Go↔SQL equivalence test (gated by
  `-tags=duckdb`, does not block the main gate). The equivalence
  test pins eight current SQL↔Go row-count divergences as TODO
  baselines so any future drift fails loudly.
- **Stats golden harness** (`cmd/linpersist-report/stats_golden_test.go`)
  pins build() + renderText / renderHTML output on a 13-record
  synthetic fixture covering Q1/Q4/Q7/Q11/Q12 paths. Required for
  every future stats.go refactor. Caught one pre-existing bug
  during landing: `BySiteClass` and `ByOSID` sorts were unstable
  on ties, shuffling rows between runs of the same input. Added
  Name tiebreakers.

### Changed — code-review refactor (P0–P3)
- **Helpers extracted to internal/core/**: `FillFileMeta` and
  `DedupSignals` / `DedupSignalsSorted` lived (mostly byte-identical)
  in 21 modules. Centralized. `TmpDirs` constant centralized too.
  Net delete: ~833 LOC across the modules.
- **Shared module registry** (`internal/modset/`): one explicit
  alphabetical slice consumed by both `cmd/linpersist` and
  `cmd/matrix-audit`. Adding a module is now one edit instead of
  three coordinated ones. Tests pin the count and ordering.
- **Q11/Q12 calibration moved to embedded YAML**
  (`cmd/linpersist-report/assets/{vendor_basenames,script_extensions}.yaml`):
  the 34-entry vendor baseline allow-list and the 5-entry Q12
  extension list are now data files an operator can tune without
  recompiling.
- **Shared text-render helpers** in
  `cmd/linpersist-report/render_common.go`: ansi/TTY/section/bar
  helpers consumed by render_text, render_host_text and
  render_diff_text, instead of one of them owning them implicitly.
- **Hardcoded signal name strings replaced with constants** in
  stats.go and render.go; new `signals_consumption_test.go` asserts
  every key in `warningSignals` exists in the core catalog, closing
  the drift channel the existing emission-side test does not see.
- **Hot-path improvements** in stats.go: `hasSignal()` linear-scan
  helper replaces `sigSet()` per-record map allocations in Q9 / Q10
  / Q11 loops; `worstSeverity` precomputed once at init
  (O(N×M) → O(N+M)); `computeQ3` fuses its two record passes into
  one.

### Added — lab-realistic v2 fixtures
- Three new implant templates + catalog entries + placements:
  `trap-bashrc-payload` (dev-workstation), `suid-rooted-binary`
  (legacy), `group-wheel-attacker` (build-ci). Ground truth grows
  from 33 to 36 placements across 26 hosts.

## [0.3.4] - 2026-05-22

### Fixed (v0.3.4 — ssh-forced-tmp end-to-end + lab fixture audit)
- **`lab-realistic/implants/catalog.yaml`: ssh-forced-tmp key_blob
  was not valid base64.** The pre-v0.3.4 value
  `AAAAC3NzaC1lZDI1NTE5AAAA-lab-implant-ssh-forced-tmp` carried ASCII
  hyphens, outside the strict base64 alphabet. The agent's ssh module
  decodes the blob via `base64.StdEncoding.DecodeString`
  (`internal/modules/ssh/normalize.go:139`), correctly rejected the
  line, `parseAuthKeyLine` returned false, and `processAuthkeysFile`
  silently dropped the implant. Across all three `ssh-forced-tmp`
  placements (bastion / build-ci / web-edge) the agent emitted zero
  `ssh.authkeys` records — exactly the v0.3.3 audit-doc MISSED count.
  Module behavior is DFIR-positive (a real attacker key from
  `ssh-keygen` is always valid base64); the bug was in the fixture.
  Fix replaces the blob with a wire-format ed25519 pubkey
  (`AAAAC3NzaC1lZDI1NTE5AAAAIGxpbnBlcnNpc3RMYWJJbXBsYW50Rm9yY2VkVG1wVjNh`,
  decodes to `<u32:11> "ssh-ed25519" <u32:32> "linpersistLabImplantForcedTmpV3a"`).
  Live-container repro from `r-build-ci-amzn-04` confirms the agent
  now emits a `ssh.authkeys` record with the expected signals
  (`interpreter_in_tmp`, `ssh_forced_command`, `non_package_path`,
  `recent_mtime_7d`, `recent_target_mtime_7d`).
- **`lab-realistic/implants/catalog.yaml`: ssh-forced-tmp variant
  metadata was inconsistent.** Catalog declared
  `variant: orphan` with `expected_signals: [..., exec_target_orphan]`
  but the `ssh-forced-tmp.tmpl` template explicitly creates the
  payload file (`The payload file IS created (armed).`). The two
  signal names mean different things in `internal/core/signals.go`:
  `exec_target_orphan` = exec_target path missing on disk;
  `non_package_path` = exec_target present but not package-managed.
  Fix flips `variant: armed` and `expected_signals` to
  `[interpreter_in_tmp, non_package_path]`, aligned with what the
  module actually emits.
- **`docs/benchmarks/v0.3.3-realistic.md`: Detection envelope section
  attributed the ssh-forced-tmp MISSED to a "template gap: writes to
  /root/.ssh/authorized_keys without mkdir -p $(dirname) first".**
  The template already had the mkdir; the live-container investigation
  traced the miss to the base64-invalid blob (above). Section
  rewritten with the real root cause and a note recording that the
  original hypothesis was wrong.
- **`lab-realistic/scripts/generate.py`: aggressive mtime stamping
  suppressed `recent_target_mtime_7d` for worm-shared-{cron,systemd}.**
  The v0.3.3 backdating pass `find /etc /opt /home /usr/local -type f
  -exec touch -d ${provisioned_at}` also stamped the worm's
  exec_target binary at `/usr/local/sbin/sync-agent`, so the agent's
  `recent_target_mtime_7d` signal could not fire. Drop `/opt` and
  `/usr/local` from the stamping pass: keep `/etc` and `/home`
  (operator-shaped configs and dotfiles) backdated, but leave
  binaries under `/opt` and `/usr/local` with their build-time mtime
  so worm payloads retain their `recent` flag. The `chmod 0700`
  step in the ssh-forced-tmp template was unaffected.

### Added (v0.3.4 — operator escape hatches)
- **`--peer-floor N` flag on `linpersist-report`.** Tunes the Q3
  minimum peer-group size. Default 3 (reproduces v0.3.1 behavior).
  Sparse fleets (under-populated labs, fine-grained tagging that
  splits the fleet into many 1-2-host cohorts) collapse Q3 to zero
  rows under the default; the flag lets the operator drop the floor
  to 2 or 1 to recover visibility. Smoke-tested against the lab v2
  NDJSON: Q3 row count scales 4 (floor=3) → 54 (floor=2) → 6848
  (floor=1). New `TestQ3_PeerFloorTunable` plus existing
  `TestQ3_PeerSizeFloor` cover the four canonical values (1/2/3/4).
  Documented in `docs/stacking-cookbook.md` Query 3.
- **MITRE coverage panel: dormant sub-categorization.** A dormant
  technique was previously a single bucket ("declared but no
  records observed"). v0.3.4 splits it into two operationally
  distinct cases:
  - `dormant_coverage_gap` — at least one covering module is active
    elsewhere in the dataset, yet no record carries this MITRE ID.
    Operationally interesting: review the module's MITRE tagging
    or the fleet sample.
  - `dormant_module_silent` — no covering module emitted any record
    fleet-wide. The site_class does not apply to this fleet shape
    (typical for `grub` / `xdg` / `polkit` in container-only labs).
    Not a coverage gap, just an environment artifact.
  
  Panel header in the lab v2 dataset shows
  `15/18 surfacing, 3 dormant (0 gap, 3 silent)` — the three dormant
  techniques (T1542.003 grub, T1547.013 xdg, T1548 polkit) all sit on
  modules that emit zero records fleet-wide, so the new classification
  correctly flags the absence as environmental, not a coverage gap.
  Pre-v0.3.4 the panel reported the lossy `15/18 surfacing, 3 dormant`. HTML row colors
  use `--tail` (orange) for coverage_gap and `--muted` (grey) for
  module_silent, leaving surfacing in bold. Sort order: surfacing
  before coverage_gap before module_silent.
- **`lab-realistic/implants/catalog.yaml`: future-fixture rule.**
  YAML comment now documents the base64-round-trip rule for any
  future ssh-key implant blob, so the v0.3.3 regression is hard
  to reintroduce.

### Changed
- **`score.py` docstring corrected.** The script's heuristic was
  PRESENCE-based (any signal at the `(host, module, site_class)`
  key counts as TP), not signal-exact as the docstring claimed.
  Documentation updated to match; the lax matching is intentional
  given the catalog ↔ agent signal-name overlap (e.g. catalog
  `exec_target_orphan` vs agent `non_package_path` for armed
  implants). Behavior unchanged.

### Verified (v0.3.4 release gate)
- `make all` clean: lint + test + audit + detgen-verify +
  matrix-sync-verify + build.
- Q3 tests: 8/8 pass including new `TestQ3_PeerFloorTunable`.
- MITRE tests: 4/4 pass — empty dataset all module_silent;
  coverage_gap vs module_silent split correctly; surfacing
  record promotion; summary string format.
- ssh-forced-tmp live-container repro on `r-build-ci-amzn-04`:
  agent emits one `ssh.authkeys` record with all expected signals.
- Full lab-realistic v2 re-bench against the freshly-built
  v0.3.4 agent (`dist/linpersist-linux-amd64`):
  - 45/45 hosts collected, 19,473 records (+3 vs v0.3.3 — the
    3 ssh.authkeys records that were silently dropped before).
  - score.py recall: **Q1 1.00, Q4 1.00, Q7 1.00, Q9 1.00**
    (vs v0.3.3 aggregate 0.82). Q12 is 0.67 (2/3); the
    remaining miss is the worm `profile` arm whose 3-arm
    clustering depends on exec_target population (deferred
    to v0.4.0 — pre-existing, not regression).
  - Module ssh now emits **3 ssh.authkeys records** for the
    bastion/build-ci/web-edge ssh-forced-tmp placements (the
    v0.3.3 MISSED batch). Each carries the expected signals
    `interpreter_in_tmp`, `ssh_forced_command`,
    `ssh_options_present`, `non_package_path`,
    `recent_mtime_7d`, and `recent_target_mtime_7d`.
  - Worm exec_target `/usr/local/sbin/sync-agent` retains a
    fresh build-time mtime on the 2 worm-shared-{cron,systemd}
    placements, so the `recent_target_mtime_7d` signal fires
    (2/2 — also previously zero).
  - MITRE panel header: `15/18 surfacing, 3 dormant
    (0 gap, 3 silent)`. The three dormants
    (`T1542.003` grub, `T1547.013` xdg, `T1548` polkit) all
    sit on modules emitting zero records in this
    container-only lab — classification confirms environmental
    absence, not a coverage gap.
  - Q3 with default `--peer-floor 3`: 4 rows (vs v0.3.3's
    zero-row collapse — over-tagging effect partially
    relieved by the new mtime / signal recoveries).
    Operator can tune to `2` (54 rows) or `1` (6848 rows)
    for sparse fleets.

### Deferred to v0.4.0
- Aligning catalog `expected_signals` vocabulary with
  `internal/core/signals.go` literals across all implants
  (only ssh-forced-tmp normalized in v0.3.4).
- Stricter `score.py`: actual signal-set intersection check
  instead of presence-based heuristic. Requires the catalog
  vocabulary alignment above.
- ssh-forced-tmp greedy placement bias toward build-ci/web-edge
  (zero placements on bastion under current policy weights).

## [0.3.3] - 2026-05-21

### Added (v0.3.3 — lab-realistic v2)
- **`docs/lab-realistic-v2-spec.md`** (650 lines). Design
  specification for the realistic 45-host fleet that
  supersedes the v1 minimal-container lab. Roles (13), drift
  sources, distro idiosyncrasies, taxonomy of tags
  (ADR-0015), implant distribution, ground-truth artifact,
  per-query recall scoring methodology. Five decisions
  closed: 1 legacy special host, AI CLI configs shipped now,
  3 users per dev-workstation, 3 vendor packages (DataDog +
  Splunk Forwarder + Vector), and `lab-realistic/` lifted
  from `.gitignore` (only `out/` stays ignored).
- **`lab-realistic/` infrastructure committed to repo** (was
  fully gitignored before; the v0.1.0 expedient is now an
  explicit policy reversal documented in `.gitignore`). Only
  `lab-realistic/out/` remains ignored as generated artifacts.
- **13 role templates** under `lab-realistic/roles/`:
  `web-edge`, `web-app`, `db-primary`, `db-replica`, `cache`,
  `mq`, `build-ci`, `k8s-cp`, `k8s-node`, `monitoring`,
  `bastion`, `dev-workstation`, `legacy`. Filesystem-only
  shape: config files + sudoers + cron + systemd units +
  ssh authorized_keys + vendor binaries under `/opt/`. No
  apt-get / dnf install of role-specific software (agent
  reads filesystem; binaries irrelevant). Templates render
  through `string.Template.safe_substitute` from
  `scripts/generate.py`.
- **6 distro base Dockerfiles** simplified to a universal
  minimum (cron + openssh-server + sudo + bash-completion +
  zsh + ca-certificates). Adds `amzn2.legacy.Dockerfile` for
  the single sysv-heavy host that anchors at-jobs / sysv
  init / modules-load coverage.
- **17-implant catalog** at `lab-realistic/implants/catalog.yaml`:
  14 implants (11 carry-over from v1 + 3 v0.3.0-coverage),
  plus a `placements:` section the generator consumes to
  greedy-assign implants to host candidates. Each entry
  carries `expected_signals`, `expected_caught_by` and
  `expected_q7_rule` for scoring.
- **`scripts/generate.py`** (270 LOC). Materialises Dockerfiles
  from the policy + role templates + implant catalog,
  produces deterministic per-host artifacts under `out/`:
  `dockerfiles/<host>.Dockerfile`, `hostlist.yaml`,
  `hostnames.txt`, `host-tags.tsv`, `ground_truth.jsonl`.
  Seed 42 (unchanged from v1).
- **`scripts/score.py`** (90 LOC). Joins `ground_truth.jsonl`
  with the rendered NDJSON and emits a markdown table of
  per-query recall (TP / FN / recall%).
- **`build.sh` rewritten** with three modes: full, `--validate`
  (one representative per `(distro, role)` for fast iteration),
  `--hosts h1,h2` (targeted single-host rebuild). Build cache
  is hot after the first run; iteration cost dropped to ~10s
  per modified host.
- **`collect.sh` rewritten** to load per-host tags from
  `out/host-tags.tsv` and pass them via `--tag` to the agent,
  so the NDJSON reflects realistic peer-group axes for Q3.

### Fixed
- **HTML report Q12 pane was missing in the v0.3.2 release**.
  `cmd/linpersist-report/report.tmpl` shipped with the
  `<button data-tab="q12">` in the nav strip but without the
  matching `<section data-pane="q12">` body. Clicking the Q12
  tab in any v0.3.2 HTML report opened an empty pane. v0.3.3
  re-injects the pane (the text rendering was unaffected --
  `render_text.go` always produced the Q12 block correctly).
  The lab v2 surfaced this regression during the final-tag
  inspection.

### Changed (v0.3.3 calibration -- two Go-side fixes the lab v2 surfaced)
- **`q11VendorBaselineBasenames` allow-list** in
  `cmd/linpersist-report/stats.go`. Q11 was surfacing vendor
  non-package binaries (DataDog, Splunk, Vector, filebeat,
  *_exporter, kubelet, kube-proxy, kubectl, kubeadm, crictl,
  containerd, rbash-wrapper, pm2, vault-cli, systemd-pcrphase,
  modprobe, node, trivy, hadolint, docker) as if they were
  implants. The new helper `q11BaselineBasename` excludes them
  from Q11 by basename match, dropping the row count from 27 to
  17 on the lab v2 fleet. The 17 remaining rows are single-host
  hits in `/usr/local/sbin/<name>` -- the actual implant shape.
- **`basenameForQ12` strips common operator extensions**
  (`.sh`, `.service`, `.conf`, `.timer`, `.socket`) before
  clustering. Without this, the worm 3-arm pattern
  (`deploy-sync.sh` in profile vs `deploy-sync` in cron vs
  `deploy-sync.service` in systemd) fragments across three
  rows. Post-calibration the worm surfaces in two TOP rows:
  `deploy-sync` (cron+profile, clustering by locus basename
  after strip) and `sync-agent` (cron+systemd, clustering by
  exec_target basename). Full 3-arm-into-1-row consolidation
  would require the `profile` module to populate exec_target
  from the script body (deferred to v0.4.0).

### Verified (v0.3.3 release gate against lab-realistic v2)
- 45 hosts (13 roles × distro mix), 19,470 records, 33 implants
  placed across 25 hosts (per policy `placements:`). Five
  iterative calibrations applied across the run (Q3 datacenter
  exclusion, Q5/Q8 mtime stamping, Q11 vendor allow-list, Q12
  strip-extensions); each lands a measurable reduction in
  documented FP surface.
- Aggregate recall across the measurable queries (Q1 / Q4 /
  Q7 / Q9 / Q12): **67/82 = 0.82**. Q12 perfect (1.00) on the
  coordinated multi-arm campaign. **30/33 implants caught
  end-to-end**; the 3 misses are all `ssh-forced-tmp` due to a
  template `mkdir` gap (v0.3.4 follow-up).
- The 13 v0.3.0-coverage detection rules
  (`linger`/`tmpfiles`/`sysusers`) achieve their **first
  end-to-end lab TPs** — pre-armed since v0.3.0, finally
  exercised on a fleet that seeds the vectors.
- Counts surface real drift v1 was hiding: Q1 grew from 26
  to 731 singletons.
- Q3 collapsed to 0 — exact "over-tagging" failure mode the
  SPEC warned about. v0.3.4 candidate: `--peer-floor N` CLI
  flag on `linpersist-report` for operator tuning.
- Q11 grew from 6 to 27 (vendor non-package binaries under
  `/opt/<vendor>/`); the sort-ASC heuristic correctly bubbles
  implant-shaped rows to the top.
- MITRE panel: 15/18 surfacing, 3 dormant
  (`T1053.001 at.jobs`, `T1542.003 kernel.grub`,
  `T1547.013 xdg.autostart`). The legacy host seeds at-jobs;
  the dormant misclassification is a panel-threshold review
  follow-up.
- Full benchmark with calibration follow-ups documented at
  `docs/benchmarks/v0.3.3-realistic.md`.

### Changed
- `.gitignore`: `lab-realistic/` no longer ignored — only
  `lab-realistic/out/`. The original "lab infrastructure is
  never published" comment was a v0.1.0 expedient; ADR-0015's
  positioning of the lab as the validation tool for the
  product changed that.

### Deferred to v0.3.4 / v0.4.0
- **`ssh-forced-tmp` template fix**: `mkdir -p
  $(dirname ${authorized_keys_file})` before the redirect.
  Trivial. Recovers Q4 recall to 1.00.
- **`--peer-floor N` flag on `linpersist-report`** for
  operator-side tuning of the Q3 `peer_hosts > 2` floor when
  the fleet is over-tagged.
- **Q11 vendor-basename allow-list calibration**: drops Q11
  from ~27 to ~5-7 rows by allow-listing
  `datadog-agent`, `splunkd`, `vector`,
  `*_exporter` basenames. Either a `detections.yaml`-style
  config or a CLI flag.
- **MITRE panel `dormant` threshold review**: at-jobs is
  surfacing in the lab but classified `dormant`. The
  threshold logic needs revisiting.

## [0.3.2] - 2026-05-21

### Added (v0.3.2 — MITRE coverage panel + Q12 campaign clusters)
- **MITRE ATT&CK coverage panel** in `linpersist-report`. New
  Overview card (`{surfacing}/{total} surfacing`) plus a
  dedicated table cross-referencing `matrix.yaml` (techniques
  declared as covered) with live records (techniques actually
  surfacing). Rows are sorted surfacing-first then by record
  count descending; dormant techniques (declared but not yet
  observed in the dataset) follow.
- **`matrix.yaml` embedded** in the report binary via
  `go:embed` so the panel is available in operator deployments
  far from the repo. Source of truth stays at the repo root;
  the embedded copy lives at
  `cmd/linpersist-report/assets/matrix.yaml`.
- **New release gate `matrix-sync-verify`** in the Makefile
  `all` target. Fails the build if the canonical `matrix.yaml`
  and the embedded copy drift apart. Re-sync with
  `cp matrix.yaml cmd/linpersist-report/assets/matrix.yaml`.
- **Q12 — Campaign basename clustering**. New query in Go
  (`stats.go::computeQ12`), text (`render_text.go`), HTML
  (`report.tmpl` tab + pane), SQL (`tools/stack_demo.sql`
  hand-edited), and cookbook
  (`docs/stacking-cookbook.md::Query 12`). Surfaces multi-arm
  campaigns whose individual arms each look like Q1 singletons
  in their own module. Validates on lab-realistic: top row is
  `sync-agent` clustered across `cron + systemd` on 2 hosts
  (the v0.2.0 deploy-sync case the v0.3.x backlog called out).

### Fixed
- **`tools/stack_demo.sql` Q11 query was truncated** at HEAD
  (the SELECT body ended mid-line at `AND exec_tar`). v0.3.2
  restores the full query body to mirror `computeQ11` in
  `stats.go`. Discovered while editing the file to add Q12;
  no production tag had the truncated SQL because the Go path
  is the canonical implementation.

### Changed
- **CHANGELOG split** along the actual tag history. The
  previous monolithic `[Unreleased]` (which evolved into a
  monolithic `[0.3.0]` block at the v0.3.1 release) now
  separates cleanly: `[0.2.0] - 2026-05-19` collects everything
  that pre-dates the v0.2.0 tag plus the post-tag-v0.2.0 work
  (ADR-0011 / 0012 / 0013, v0.2.x-tune) that never got
  promoted formally; `[0.3.0]` keeps only the v0.3.0 closure
  and v0.3.0-coverage subsections. Historical accuracy at the
  cost of a small migration in the CHANGELOG line numbers.

### Documented
- New Q12 cookbook section in `docs/stacking-cookbook.md`
  explaining the multi-arm campaign pattern, the FPs to expect
  (vendor baselines shipping the same name across systemd.unit
  + sysv.init), and when Q12 is most valuable.
- `docs/SPRINT-HANDOFF.md` rewritten to reflect v0.3.0 +
  v0.3.1 + v0.3.2 cumulative state. The original body
  (architectural canon, lessons learned, gotchas, cookbook,
  debug map) is preserved verbatim because it is evergreen;
  the head of the doc now carries an "everything that landed
  since this was written" delta block.

### Verified (v0.3.2 release gate against lab-realistic)
- `make all` clean: lint + test + audit + detgen-verify +
  matrix-sync-verify + build.
- 75-host fleet round-trip: Q1=26, Q2=33, Q3=158, Q4=6,
  Q5=53, Q6=44, Q7=22, Q8=40, Q9=17, Q10=75 hosts, Q11=6,
  **Q12=16** (new). The Q1-Q11 counts are byte-identical to
  v0.3.1. Q12's first row is the v0.2.0 sync-agent campaign,
  exactly as the v0.3.x backlog predicted.
- MITRE coverage panel surfaces 18 techniques: 15 surfacing,
  3 dormant (T1053.001 at.jobs, T1542.003 kernel.grub,
  T1547.013 xdg.autostart). The three dormant techniques
  correspond to vectors the lab does not seed.

### Deferred to v0.3.3 ("lab quality" sprint)
- **Lab implant fixtures** for `linger`/`tmpfiles`/`sysusers`.
  The 13 v0.3.0-coverage detection rules still ship pre-armed;
  `lab-realistic/` is gitignored and requires Docker to
  rebuild, which made it a sprint of its own. v0.3.3 should:
  add three implant templates under `lab-realistic/implants/
  templates/`, three catalog.yaml entries, hostlist
  assignments to 1-2 hosts per implant, re-collect, and
  publish `docs/benchmarks/v0.3.3-realistic.md`.

### Deferred to v0.3.x
- **Q12 baseline allow-list calibration**. The current
  implementation has no allow-list for vendor baseline
  basenames (nginx, redis-server, prometheus, sshd_config)
  that legitimately cross `systemd.unit` + `sysv.init`. The
  analyst's ASC-by-hosts triage handles this in practice, but
  a calibrated allow-list would clean up the tail.
- **Q3 SQL drift gate**. `tools/stack_demo.sql::Query 3`
  is hand-edited to mirror Go; an automated drift gate
  (mirror of `detgen-verify`) is still pending.

## [0.3.1] - 2026-05-21

### Added (v0.3.1-fleet — host tags, Q3 peer-group, --diff mode)
- **`--tag key=value` flag in the agent** (`cmd/linpersist`,
  ADR-0015). Repeatable; values land in `host_meta.tags` as the
  sorted, deduplicated, canonical-form slice. Validation is
  K8s-style strict: `key=[a-z][a-z0-9_-]{0,62}`,
  `value=[a-z0-9]([a-z0-9_.-]{0,61}[a-z0-9])?` or empty. Reserved
  keys (`hostname`, `hostname_hash`, `os_id`, `os_version`,
  `kernel`, `arch`, `boot_id`, `host_id`) are rejected at parse
  with hints pointing at the canonical HostMeta field.
- **Multi-value tag support**: the same key may appear multiple
  times (`--tag role=build --tag role=ci`), producing two distinct
  entries in `host_meta.tags`. Mirrors Kubernetes label semantics
  for hosts that legitimately serve two roles or are mid-migration
  between environments.
- **`internal/core/tags.go`** with `ParseTag`, `ValidateTagKey`,
  `ValidateTagValue`, `CanonicalizeTags`, `CanonicalTagKey`.
  Exported so future consumers (matrix-audit, report-side filters)
  can reuse the contract.
- **Q3 peer-group keyed by `(os_id, tags)`** in the report
  (`cmd/linpersist-report/stats.go::computeQ3`). Hosts with
  byte-identical canonical tag sets form one peer-group; hosts
  with any difference form a separate peer-group. Hosts with zero
  tags form the "untagged" peer-group (preserves v0.2.0 behavior
  for fleets not yet tagged). The `peer_hosts > 2` floor is kept.
  `PeerGroupRow.TagKey` is new in the struct; downstream render
  surfaces it on each row.
- **`tools/stack_demo.sql` Q3 hand-edited** to mirror the new
  Go logic. Uses a `host_tags` CTE that builds the canonical
  tag_key via `list_aggregate(list_sort(list_distinct(...)), ',')`
  and joins peer_size on `(os_id, tag_key)`. No automated drift
  gate yet (unlike detgen-verify for Q7); revisit if Q3 diverges
  further in v0.3.x.
- **`linpersist-report --diff prev.ndjson curr.ndjson`**: a new
  mode that compares two collections and emits annotated changes.
  Identity is `(host_id, module, site_class, locus)`;
  `content_norm_sha256` distinguishes Δ (changed) from = (idem).
  Output covers Added (`+`), Removed (`-`), Changed (`Δ`),
  UnchangedCount, plus host-level rows for hosts that entirely
  appeared/disappeared between the two collections (per ADR-0015:
  individual per-record + / - lines are suppressed for those
  hosts so container churn does not saturate the report).
- Both text and HTML rendering for diff mode
  (`renderDiffText`, `renderDiffHTML`). HTML is self-contained
  with inline CSS, mirrors `report.tmpl`'s single-file principle.

### Tests
- `internal/core/tags_test.go`: 8 unit tests covering valid
  parses, malformed grammar (uppercase, whitespace, multiple `=`,
  length boundaries), reserved-key rejection, canonicalization
  determinism, dedup of exact duplicates, untagged peer-group key
  invariant.
- `cmd/linpersist-report/stats_test.go`: 7 unit tests for the new
  Q3 peer-group logic: untagged migration safety net, same-tags
  same-peer-group, different-tags separate-peer-groups, tag-order
  independence, `peer_hosts > 2` floor, untagged vs tagged
  separation, fleet-wide line not surfaced.
- `cmd/linpersist-report/diff_test.go`: 10 tests for ComputeDiff:
  no changes, record added/removed/changed, host disappeared,
  host appeared, prev empty, curr empty, determinism, mixed
  scenario combining all four classifications.

### Documented
- **ADR-0015** (`docs/adr/0015-host-tags.md`): the canonical
  decision record for the four design choices closed in
  conversation -- strict K8s-style validation, multi-value
  permitted, exact-match peer-group identity, host-level row for
  full-host disappearance / appearance.
- **`docs/deployment.md`** (new). Operator-facing guide covering
  binary placement, five invocation patterns (Ansible/Salt/Chef
  /Puppet, cron, systemd timer, wrapper script reading host
  metadata, container DaemonSet), the host-tags contract,
  taxonomy of useful tag axes, transport options (file-based +
  shipper, piped, object-store), post-rollout verification and
  troubleshooting. Closes the "linpersist works for any Linux
  fleet, not just K8s" documentation gap exposed during the
  v0.3.1 sprint.

### Verified (v0.3.1 release gate against lab-realistic)
- 75-host fleet round-trip: Q1=26, Q2=33, Q3=158, Q4=6, Q5=53,
  Q6=44, Q7=22, Q8=40, Q9=17, Q10=75 hosts, Q11=6 -- byte-
  identical to v0.3.0. Q3 header rephrased to
  "Peer-group LFA by (os_id, tags)"; row count unchanged because
  the lab does not populate `host_meta.tags` yet, so all hosts
  fall into the "untagged" peer-group (the migration safety net
  ADR-0015 prescribes).
- `--diff` against prev=curr on the lab fleet produces "No
  changes between prev and curr." with 9,670 records matched on
  identity and zero per-record or host-level deltas.
- `make all` clean: lint + test + audit + detgen-verify + build.
- 25 packages green under `-race` (with 25 new tests from this
  release).

### Deferred to v0.3.2
- **MITRE coverage panel** in the fleet report Overview block.
  Cross-cuts `matrix.yaml` (technique IDs declared as covered)
  with live records (which techniques actually surfaced). The
  v0.3.1 sprint scopes it as "bonus, deferable"; cleaner as a
  standalone v0.3.2 because it does not depend on tags or diff
  to land usefully.

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

## [0.2.0] - 2026-05-19

> The v0.2.0 git tag (commit `a9ac2c4`, 2026-05-19) was
> created without a CHANGELOG bump. Subsequent work that
> landed before the v0.3.0 cycle officially started
> (signals catalog ADR-0011, host dossier ADR-0012,
> declarative detections ADR-0013, v0.2.x-tune calibration)
> is collected under this header for historical
> completeness. Operators consuming the CHANGELOG should
> read this section as "the cumulative v0.2.x state at the
> point v0.3.0 began."

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
