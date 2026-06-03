# Sprint handoff — read this first

> File maintained as the "open a new window and pick up where the
> last session left" entry point. If you are returning to the repo
> after a context loss (closed chat, new agent session, new
> developer), start here. It is intentionally dense: everything that
> is non-obvious from the code lives in this doc.
>
> Last updated: 2026-06-02 — the **detect-lab-hardening** sprint is
> MERGED to main (PR #2): anti-evasion v1.0 (dpkg/rpm/apk package-file
> integrity + central anti-timestomp), two 4-agent red/blue duels, and
> 6 backlog items. Detections 27 → 40; new site_classes systemd.generator,
> filecap, ssh.sshrc; xattr + ioctl layers. All lab-validated on real
> Debian + Rocky nspawn hosts. (Earlier: v0.5.0 "cloud-native coverage",
> 2026-05-24.)
>
> ### START HERE (next session)
> 1. State: everything below "What is OPEN after v0.5.0" is current.
>    `make all` is green on main (includes `duckdb-equiv`, the new Go↔SQL
>    gate — run it before touching Q6/Q12/stats.go or stack_demo.sql).
> 2. Next work = duel-2 backlog merged to main (PR #3). **Duel-3** is
>    lab-validated on branch `duel3-confexec` (3 commits, round 32) and
>    AWAITING MERGE — the generic `confexec` module (8 config-embedded
>    exec-edge sites) + systemd .socket/.timer/EnvironmentFile relations
>    edges. Detections 43→51, site_classes 48→56, modules 26→27. See the
>    "Duel-3" section below. Next: merge `duel3-confexec` (PR), then the
>    architect-agreed Tier-3 deferred items (`getty_autologin` signal,
>    `mount_shadows_path` /proc/self/mountinfo enrichment) or "Still OPEN"
>    (eBPF — needs ADR; webshell/supply-chain walk).
> 3. Detection-add recipe + the recurring discipline (gate every new Q7
>    rule on a tamper/orphan/non-package co-indicator; recent_ctime floods
>    on image-built hosts; lab the change before trusting it) are in the
>    body + memory ([[nspawn-lab]], [[tooling-gotchas]]).
>
> The body of this doc (architectural canon, lessons learned,
> known gotchas, conventions, iterate-fast cookbook, debug map)
> remains the authoritative reference for "how this project
> works". The block below summarises everything that has
> happened since the original handoff snapshot
> (`docs/SPRINT-HANDOFF.md` was first written at the v0.3.0-coverage
> merge); read both this block and the body when picking up a
> new session.

---

## TL;DR — what landed in main since the original handoff

The repo is now **five tagged releases** past the original
handoff snapshot, all by `Jarmi <jarmidaw@gmail.com>`.

- **`v0.3.0`** (2026-05-21) — golden coverage, module docs, Q9
  calibration. Closes the original hard pendings (golden tests
  for `linger`, `tmpfiles`, `sysusers`; module reference docs;
  Q9 ExecTarget=invokes-not-touches calibration in
  `docs/stacking-cookbook.md` + `cmd/linpersist-report/stats.go`;
  `docs/benchmarks/v0.3.0-realistic.md`; `docs/benchmarks/`
  no longer gitignored). 19 golden test cases across the three
  new modules; 90.4 / 86.0 / 85.7 % coverage.

- **`v0.3.1`** (2026-05-21) — host tags, Q3 peer-group, --diff,
  deployment guide. Introduces `--tag key=value` (repeatable) on
  the agent with K8s-style strict validation and multi-value
  support (ADR-0015); refactors Q3 to peer-group by
  `(os_id, canonical_tag_set)`; adds
  `linpersist-report --diff prev curr` with text + HTML render;
  ships `docs/deployment.md` with five operator patterns
  (Ansible/Salt/Chef/Puppet, cron, systemd timer, wrapper
  script, K8s DaemonSet). 25 new tests; 0 regressions on
  lab-realistic.

- **`v0.3.2`** (2026-05-21) — MITRE coverage panel + Q12
  campaign clustering + CHANGELOG cleanup. The MITRE panel
  cross-cuts `matrix.yaml` (with `go:embed` for operator
  deployments) against live records, showing surfacing vs
  dormant techniques per ATT&CK ID. Q12 surfaces multi-arm
  campaigns whose individual arms each look like Q1 singletons
  in their own module. New release gate `matrix-sync-verify`
  keeps the embedded `matrix.yaml` in sync with the repo root
  copy.

- **`v0.3.3`** (2026-05-21) — lab-realistic v2 + Q11/Q12
  calibrations + HTML Q12 pane fix. 45-host fleet (13 roles ×
  distro mix), 19,470 records, 33 implants placed across 25
  hosts. Aggregate recall 0.82. Lab v2 is now committed to the
  repo (only `lab-realistic/out/` ignored). Q11 vendor allow-list
  + Q12 strip-extensions calibrations land in
  `cmd/linpersist-report/stats.go`. HTML Q12 pane bug from v0.3.2
  fixed.

- **`v0.3.4`** (2026-05-22) — ssh-forced-tmp end-to-end +
  `--peer-floor` flag + MITRE dormant sub-categorization. Live-
  container investigation traced the v0.3.3 ssh-forced-tmp MISSED
  count (3/26 implants) to a base64-invalid `key_blob` in the lab
  catalog (ASCII hyphens). Module behaviour is DFIR-positive
  (rejects malformed lines); the bug was in the fixture. Sibling
  fixes: `variant: orphan` was inconsistent with the template
  (which IS armed); `expected_signals` realigned to use
  `non_package_path` (what the agent actually emits) instead of
  `exec_target_orphan`. Worm-shared `recent_target_mtime_7d`
  signal recovered by dropping `/opt` and `/usr/local` from the
  aggressive mtime stamping pass in `generate.py`. `--peer-floor N`
  flag on `linpersist-report` lets operators tune the Q3 minimum
  peer-group size (default 3, lower for sparse fleets, raise for
  over-tagged ones). MITRE panel dormant splits into
  `dormant_coverage_gap` (module active, technique not emitted)
  vs `dormant_module_silent` (no covering module fleet-wide);
  lab v2 shows `15/18 surfacing, 3 dormant (0 gap, 3 silent)`.
  Lab v2 re-bench: Q1/Q4/Q7/Q9 all at 1.00 recall, Q12 at 0.67
  (worm-profile-arm consolidation deferred). 19,473 records.

- **`v0.4.0`** (2026-05-23) — close the Linux MITRE bridge.
  Lands the three highest-impact missing techniques from the
  18-ID matrix: T1546.005 trap (extension to `profile` module,
  new `profile.trap.{system,user}` site_classes), T1098.007
  privileged group membership (extension to `passwd` module,
  new `passwd.group.privileged` site_class, six
  `group_<name>_membership` signals), T1548.001 setuid/setgid
  (new `suidbits` module, four site_classes, two new signals,
  one new detection rule `suid_binary_outside_package_path`).
  Q12 worm-profile-arm consolidation closed via
  `internal/modules/profile/exec_target.go`. First CI on the
  repo (`.github/workflows/ci.yml`): `make all` + `make
  test-race` + static-link gate on push/PR/`v*`. Code-review
  refactor lands `FillFileMeta` + `DedupSignals[Sorted]` +
  `TmpDirs` in `internal/core/` (net ~833 LOC deleted from
  modules), shared module registry `internal/modset/`, Q11/Q12
  calibration moved to embedded YAML, shared text-render
  helpers, hardcoded signal-name strings replaced with
  constants. Stats golden harness pins `build()` + renderers.
  Lab v2 ground truth grew 33 → 36.

- **`v0.4.1`** (2026-05-24) — release pipeline + first
  consultoría deliverable. Infrastructure-only patch (no
  collector/report changes). New `.github/workflows/release.yml`
  (tag-driven, cosign keyless via OIDC, cross-arch builds,
  SHA256 checksums, `gh release create`). New flag
  `linpersist --self-sha256` for chain-of-custody. New
  `make engagement-kit VERSION=…` target produces a
  client-ready tarball (binaries × {amd64, arm64}, RUNBOOK,
  SCOPE, LICENSE, README, CHANGELOG, golden sample report,
  CHECKSUMS). New docs `docs/scope.md` (SOW-ready,
  eight sections including honest "Limitations") and
  `docs/client-runbook.md` (bilingual EN+ES). actions/* bumped
  to versions supporting Node 24; `tools/*.sh` and
  `lab-realistic/*.sh` chmod +x for CI runners.

- **`v0.5.0`** (2026-05-24) — cloud-native coverage. Three new
  persistence modules covering five site_classes on the
  cloud/container surface, plus Alpine `apk` provenance.
  `internal/modules/dbus` (T1543) walks
  `/usr/share/dbus-1/{system,session}-services/` and
  `/etc/dbus-1/…`; parses freedesktop INI; new site_classes
  `dbus.system`, `dbus.session`. `internal/modules/cloudinit`
  (T1543 + T1547) walks `cloud.cfg`, `cloud.cfg.d/*` and
  `/var/lib/cloud/scripts/{per-boot,per-instance,per-once}/`;
  new site_classes `cloudinit.config`, `cloudinit.script`;
  non-executable scripts emit `NOT_EXECUTABLE` envelopes
  (cloud-init silently skips them so the analyst sees the
  dead drop). `internal/modules/k8sstatic` (T1543.005) walks
  `/etc/kubernetes/manifests/`; parses minimal Pod spec via
  yaml.v3; ExecTarget = first container image; new site_class
  `k8s.static-pod`. `internal/core/provenance.go` learns
  `PkgMgrApk` (detection via `/lib/apk/db/installed` + os-release
  ID match); precedence apk > dpkg > rpm. Without this, every
  binary on Alpine surfaced as `non_package_path` and the signal
  was useless noise on cloud-native fleets. Matrix: 39 → 44
  site_classes. modset: 22 → 25 modules. No new signal names
  or detection rules; new modules plug into existing shared
  signals via `EmittedBy` expansions.

**Tag history now**: `v0.1.0-alpha` → `v0.2.0` → `v0.3.0` →
`v0.3.1` → `v0.3.2` → `v0.3.3` → `v0.3.4` → `v0.4.0` →
`v0.4.1` → `v0.5.0`. v0.5.0 release notes drafted in
CHANGELOG `[0.5.0]`; commit/tag/push handed off to Jarmi via
the FINAL command sequence at sprint close.

## Inventory delta since the original handoff

- **+ 6 new top-level docs**: `docs/adr/0015-host-tags.md`,
  `docs/deployment.md`, `docs/benchmarks/v0.3.0-realistic.md`,
  `docs/benchmarks/v0.3.3-realistic.md`,
  `docs/lab-realistic-v2-spec.md`,
  `cmd/linpersist-report/diff.go` (+ companion renderers).
- **+ 3 new module docs** under `docs/modules/`: `linger.md`,
  `tmpfiles.md`, `sysusers.md`.
- **+ 3 new module test packages** with 19 golden cases total
  under `internal/testdata/golden/{linger,sysusers,tmpfiles}/`.
- **+ 1 new package** `internal/core/tags.go` (host tag
  validation, canonicalization, reserved key gate).
- **+ 1 new query** Q12 (campaign basename clustering) in
  Go (`stats.go::computeQ12`), SQL (`stack_demo.sql` hand-edited),
  HTML (`report.tmpl` tab + pane), text (`render_text.go`
  section), and cookbook (`docs/stacking-cookbook.md` section).
- **+ 1 new report panel** MITRE coverage (text + HTML +
  Overview card) in `cmd/linpersist-report/mitre_coverage.go`,
  with embedded `matrix.yaml` via `go:embed`, and v0.3.4
  dormant sub-categorization (`dormant_coverage_gap` /
  `dormant_module_silent`).
- **+ 1 new CLI flag** `--peer-floor N` on `linpersist-report`
  (v0.3.4), with new `TestQ3_PeerFloorTunable` covering four
  canonical values.
- **+ 2 release gates** `matrix-sync-verify` (v0.3.2),
  `detgen-verify` (v0.3.x).
- **+ 1 ADR** ADR-0015 (host tags).
- **+ 60+ unit tests** total across the five releases (golden
  cases excluded): linger 11, sysusers 16, tmpfiles 16, tags 8,
  Q3 peer-group 8, diff 10, MITRE coverage 4. All race-clean.
- **+ Lab-realistic v2 in-repo**: 13 role templates, 6 distro
  bases, 14-implant catalog, 33 placements, scoring kit.

## What is OPEN after v0.5.0

Closed in v0.4.0–v0.5.0 (no longer open):
- T1546.005 trap (v0.4.0), T1098.007 privileged group membership
  (v0.4.0), T1548.001 setuid/sgid (v0.4.0), T1053.007 container
  orchestration job (v0.5.0 via `k8sstatic`). Q12 worm-profile-arm
  consolidation closed in v0.4.0. CI gate landed in v0.4.0.
  Release pipeline + engagement-kit landed in v0.4.1.
- **Lab-realistic fixtures for v0.5.0 modules** (closed in commit
  6b332ca, post-v0.5.0). Three new implant templates
  (`dbus-system-impostor` L2 orphan × 2 dev-workstation hosts,
  `cloudinit-per-boot-payload` L2 armed × 2 k8s-node hosts,
  `k8s-static-attacker-pod` L2 armed × 1 k8s-cp host). Ground
  truth: 36 → 41 placements. Surfacing observed on the 45-host /
  20,210-record fleet: dbus → Q1 + Q4 + Q7
  (`payload_under_tmp_via_persistence`, high); cloudinit → Q1;
  k8sstatic → Q1. Templates embed `${hostname}` in rendered content
  so each placement gets a unique `content_norm_sha256` and Q1
  surfaces (without per-host variation the hashes collide and Q1
  misses).

Closed in v0.5.x follow-ups (no longer open):
- **Detection rules over the new v0.5.0 site_classes** (commit
  7dae474). Three rules added: `dbus_exec_under_tmp` (critical,
  module_in:[dbus]), `cloudinit_script_non_package_path` (high,
  module_in:[cloudinit]), `k8s_static_pod_unqualified_image`
  (high, module_in:[k8sstatic]). Detections 24 → 27. Lab Q7
  recall on the 5 v0.5.0 implants: 5/5, zero FPs across the
  rest of the fleet. Module-scoped via `module_in` (no
  `site_class_in` schema extension); cloudinit rule has a
  documented residual FP class for operator-deployed
  /etc/cloud/cloud.cfg.d/* fragments that aren't package-managed.

Closed in the v0.5.x consolidation sprint (6 follow-ups in chain):

- **Baseline fleet-wide dbus services** (commit 3ff3632). Six
  canonical *.service files via shared `_dbus-system-baseline.sh`.
  Each stacks to count=44; only implants are Q1 singletons.
- **Q12 worm-profile-arm signals empty** (commit 76f37fd). Profile
  module now emits `exec_target_orphan` and `recent_target_mtime_7d`
  via a new `execTargetStatSignals` helper. Q12 recall 0.67 → 1.00
  (score.py heuristic stopped under-counting the profile arm).
- **`site_class_in` predicate** (commit feab4fb). Symmetric
  counterpart to `module_in`. Tightens
  `cloudinit_script_non_package_path` to fire only on
  `cloudinit.script` (not `cloudinit.config`).
- **amzn2 noise singletons** (commit 1e799f2). Bumped legacy role
  count 1 → 2. The 7 amazonlinux:2-shipped systemd dbus *.service
  files now stack across both legacy hosts (count=2) instead of
  appearing as Q1 singletons. Lab post-fix: zero dbus.system noise
  singletons; only the 2 intentional implants surface.
- **Catalog `expected_signals` vocabulary alignment** (commit
  15f43a1). Three v0.4.0 trap signals (`trap_command`,
  `trap_exit_handler`, `trap_command_in_tmp`) were emitted as bare
  string literals in `internal/modules/profile/trap.go` without
  corresponding constants in `internal/core/signals.go` or entries
  in `signals_catalog.go`. Registered properly; trap.go uses the
  constants; vocabulary audit: 0 drift.
- **score.py heuristic is presence-based, not signal-exact** AND
  **ssh-forced-tmp greedy placement bias** (commits 4c07c78 +
  e3cc5d0, coupled). score.py now requires every name in
  expected_signals to be observed; reports per-FN gap detail.
  generate.py: stamp step moved BEFORE implants (implants keep
  build-time mtime, recent_mtime_7d fires reliably). generate.py:
  assign_implants switched from flat-shuffle-take-N to round-robin
  across declared roles — each role gets one placement before any
  doubles up. Lab bench under exact + round-robin: Q1 1.00 (38/38),
  Q4 1.00 (11/11), Q7 1.00 (32/32), Q9 1.00 (15/15), Q12 1.00 (3/3)
  — first time the lab is clean across every implant family under
  signal-exact scoring.

MERGED to main via PR #2 (the `detect-lab-hardening` sprint,
2026-06-02). Everything in this block is now on main, lab-validated on
real Debian + Rocky nspawn hosts (signal-exact `lab-nspawn/validate-evade.py`,
rounds 20–27, zero clean-host FPs). Detections 27 → 40. The `apt*`/`apt2*`
lab implants in `lab-realistic/implants/catalog.yaml` are the regression
set; re-run any `lab-nspawn/fleet.sh --round N --implants <ids>` to
re-validate. The narrative below is the WHAT + WHY (each fix names the
real FP the lab caught and how it was fixed at the root):

- **Anti-evasion detection sprint.** Three "defender-aware attacker"
  lab implants (`evade-timestomp`, `evade-pkg-tamper`,
  `evade-fleetwide-clean`) were built to probe linpersist's real
  limits, and two of the gaps they expose were closed:
  - `recent_ctime_{7d,30d}` — central anti-timestomp signal computed at
    the emit sink (`cmd/linpersist/main.go`), NOT per-module. The sink
    is the choke point where every record already carries `CTime` +
    `CollectedAt`, so it lands uniformly with zero edits across the 20+
    module `baseSignals`. Helper: `core.RecentCtimeSignals`. Detection:
    `timestomp_recent_ctime_stale_mtime` (`recent_ctime_7d` AND NOT
    `recent_mtime_*`). Tested in `filemeta_test.go`.
  - `package_file_tampered` — `Resolver.VerifyPath` (dpkg) compares a
    package-owned file against its recorded hash, parsing BOTH
    `*.md5sums` AND the `Conffiles:` stanza of `/var/lib/dpkg/status`
    (conffiles like `/etc/crontab` are absent from `md5sums`). Wired
    into the sink via an interface upgrade so `NoopProvenance` skips it.
    Detection: `package_owned_file_tampered`. Tested with synthetic
    dpkg fixtures in `provenance_verify_test.go`.
  - `evade-fleetwide-clean` is **expected to evade** — the honest LFA
    boundary; its MISS is the documented finding.
  - Both detections are severity **medium** with documented residual-FP
    classes (timestomp: rsync/tar/backup; tamper: legit conffile edits).
    The durable discriminator stays LFA singleton stacking.
  - **VALIDATED end-to-end on the nspawn lab** (rounds 20 Debian + 21
    Rocky via `lab-nspawn/fleet.sh`; signal-exact checker
    `lab-nspawn/validate-evade.py`). All assertions PASS:
    `evade-pkg-tamper` -> `package_file_tampered` + the Q7 rule on
    `/etc/crontab` (Debian), zero tamper FPs fleet-wide; on Rocky/rpm it
    correctly does NOT fire (still a Q1 singleton). A real Ubuntu host
    built 81,134 dpkg integrity entries with zero tamper FPs.
    `evade-timestomp` -> `recent_ctime_7d` fires on BOTH dpkg and rpm
    (distro-agnostic, as designed). `evade-fleetwide-clean` -> evades on
    all 6 hosts (the honest LFA boundary, as predicted).
  - **Calibration the lab forced:** the first cut of
    `timestomp_recent_ctime_stale_mtime` (bare `recent_ctime_7d` AND NOT
    `recent_mtime_*`) flooded Q7 with ~1,850 rows/host on every host --
    and the real Ubuntu host matched (2,114/3,579 records). Cause: tar/
    image extraction (debootstrap, cloud images, containers, `rsync -a`,
    backups) resets ctime to "now" but preserves the old mtime, so every
    packaged file looks timestomped. Fix: the rule is now **tamper-gated**
    (`signals_all: [recent_ctime_7d, package_file_tampered]`, severity
    high) -- immune to extraction by construction. The dropped-payload
    timestomp stays covered by `payload_under_tmp_via_persistence`; the
    bare signal is still emitted for backend stacking. `detections_test.go`
    pins the three shapes. Re-check: timestomp Q7 rows 1,850/host -> 0,
    recall intact. **Lesson reinforced: fix the CLASS, validate on real
    distro data before trusting a fresh detection rule.**
  - **rpm + apk integrity now implemented too** (no longer dpkg-only).
    One `Resolver.VerifyPath` serves all three: it stores the
    package-recorded digest (dpkg MD5; rpm `FILEDIGESTS` via a bulk
    `rpm -qa --qf '[%{FILENAMES} %{FILEDIGESTS}\n]'`; apk `Q1` SHA-1 from
    `/lib/apk/db/installed`) in one map and **infers the hash algorithm
    from the recorded hex length** (32→MD5, 40→SHA-1, 64→SHA-256) — so no
    `FILEDIGESTALGO` parsing and no per-manager compare path. rpm/apk
    unit-tested with fixture commands / installed DB
    (`provenance_verify_test.go`). The Rocky lab exercises the positive
    rpm path end-to-end (re-run round 21 with the new binary to observe
    `package_file_tampered` on `/etc/crontab` via FILEDIGESTS).
    Cross-distro re-confirmed on round 26 (Rocky): all the duel-1/2
    detections fire identically via rpm provenance/FILEDIGESTS. The rpm
    `%config` residual FP (package_owned_file_tampered) is empirically
    just TWO files on a clean Rocky GenericCloud host -- `/etc/sudoers`
    and `/etc/cloud/cloud.cfg` (cloud-init edits both; `rpm -V` reports
    them too). FILEVERIFYFLAGS already cut the round-21 baseline from 6
    files to these 2; they are fleet-identical (not singletons), so LFA
    is the discriminator and the medium severity is correct. No further
    fix -- this is the documented `%config` boundary.

- **Red/blue duel hardening** (4-agent Workflow: APT intrusion specialist
  vs blue-team hunter, adjudicated by two architects). 11 real-TTP
  implants; verdict: all evade Q7, caught only by LFA/Q1. Three FP-gated
  fixes landed and VALIDATED on the lab (round 22 Debian, all PASS,
  zero clean-host FPs):
  - `ld_preload_target_tampered` (critical): `ldso.go` now runs
    `VerifyPath` on the PRELOADED `.so`, not just the ld.so.preload locus
    the sink checks — an in-place overwrite of a package-owned library
    (Symbiote/HiddenWasp) stays owned (`non_package_path` silent) but its
    digest mismatches. Validated: `package_file_tampered` +
    `ld_preload_target_tampered` fire on the tampered `libpcprofile.so`,
    only on the implant host.
  - `netdispatch_run_unmanaged` (high): netdispatch emitted
    `non_package_path` on an orphan dispatcher but no rule consumed it
    (pure YAML, mirrors udev). Validated: fires only on the implant.
  - **polkit `recent_ctime_7d` gate — TRIED AND REVERTED.** Adding it to
    close the `touch -d` bypass flooded on the image-extracted stock
    vendor rules under `/usr/share/polkit-1` (round 22: every host fired
    on `50-default.rules`/`systemd-networkd.rules`). No clean
    co-indicator (polkit drop-ins aren't package-owned → no tamper-gate),
    so the timestomp is left to LFA singleton stacking (implant surfaces
    in Q1, not Q7). Same image-extraction lesson as timestomp, third time.
  - Architect consensus left as **signal+LFA, no detection**: packaged-
    LOLBin sshd `AuthorizedKeysCommand` (the non-package gate protects the
    legit SSSD helper) and base64-`eval` profile loaders (a content
    singleton, not a substring arms race).
  - Both queued architect proposals BUILT + VALIDATED (round 24 Debian,
    all PASS, zero clean-host FPs):
    - `interpreter_runs_orphan_script` (+ `interpreter_executes_unmanaged_script`,
      high): cron/systemd resolve the SCRIPT ARGUMENT of a packaged
      interpreter via `core.InterpreterScriptOrphan` and flag when orphan.
      Two lab-driven fixes en route: the implant uses `/bin/bash` (Essential/
      owned) not python3 (the base lacks python3 → it resolved orphan and
      masked the test); and the helper now BAILS on inline `-c`/`-e` code
      (round 24 caught it firing on `ExecStart=/bin/sh -c '...< /opt/...'`
      — labcollect.service and every vendor `sh -c` unit — by scanning abs
      paths inside the inline code; inline is LFA-only by design).
    - `sudoers_nopasswd_gtfobin` (+ `sudoers_nopasswd_shell_escape`, high):
      curated shell-escape set, EXCLUDES commonly-legit systemctl/service/
      docker/git (left to LFA). Unit-tested.
  - Detections: 27 (pre-duel) → 34.

- **Red/blue duel #2 (harder)** — 8+6 novel/complex implants; the blue
  team found whole-module coverage holes and unparsed fields. Both
  architects converged; the 5 high-ROI fixes were IMPLEMENTED (detections
  34→37, all gated on orphan/non_package/tamper co-indicators, lab implants
  `apt2-*` added to validate):
  - script-ARG integrity: cron/systemd now VerifyPath the resolved
    interpreter script argument (not just rec.Locus) → closes the
    owned-but-tampered-script asymmetry (uniform with ldso preload).
  - systemd `ExecStartPre/Post/...` resolution → `systemd_aux_exec_unmanaged`
    (Turla drop-in behavior injection).
  - systemd **generators** → new site_class `systemd.generator` +
    `systemd_generator_unmanaged` (was a zero-record primitive).
  - **file capabilities** → suidbits reads `security.capability` xattr,
    new site_class `filecap`, `file_capability_outside_package`.
  - **immutable flag** → `core.InodeFlagSignals` (FS_IOC_GETFLAGS) at the
    sink → `immutable_flag`/`append_only_flag` enrichment (no detection;
    anti-remediation; defeats the immutable-aged implant via LFA).
  - **Deferred backlog — progress (detections 37→40):**
    - DONE `/etc/ssh/sshrc` + `~/.ssh/rc` → site_class `ssh.sshrc` +
      `ssh_sshrc_unmanaged_exec` (commit 8a877f0).
    - DONE sudoers GTFOBin set expanded (rsync/socat/openssl/busybox/…),
      systemctl/docker still LFA-only (8a877f0).
    - DONE `ExtractExecTarget` lifted profile → `core` (shared) (8a877f0).
    - DONE kmod autoload + resolve named module to its `.ko` via
      modules.dep + provenance → `kmod_autoload_unpackaged_module`
      (critical) (1b994bb).
    - DONE sshd `SetEnv`/`AcceptEnv`/`PermitUserEnvironment` →
      `sshd_login_env_injection` (73e2b58).
    - LAB-VALIDATED (round 27, Debian): sshrc, kmod-`.ko`, sshd-env each
      fire only on their implant host, zero clean-host FPs (apt2-sshrc-hook,
      apt2-kmod-rootkit, apt2-sshd-setenv).
    - DONE scope.md §8.1 boundaries doc (73e2b58).
    - DONE + LAB-VALIDATED (round 28, Debian) **BASH_ENV / ENV in
      /etc/environment** (duel-2 backlog #1). New sibling extractor
      `core.ExtractEnvHookTarget` recognizes `BASH_ENV=`/`ENV=` assignments
      (optional `export `, quote-stripped) and returns the RHS only when it
      is a clean absolute path ($-expanded/relative RHS stays signal-free —
      same non-decision as PROMPT_COMMAND). The profile module checks the
      env-hook FIRST (higher-signal than a plain source/exec line; the only
      branch that can populate ExecTarget on /etc/environment's KEY=value
      content), sets it as ExecTarget, and emits new signal `env_hook_set`.
      `execTargetStatSignals` also gained `interpreter_in_tmp` (latent gap,
      now uniform with every other module; profile added to its catalog
      EmittedBy). Detection `profile_env_hook_unmanaged` (high, T1546.004)
      gated `signals_all:[env_hook_set]` + `signals_any:[non_package_path,
      exec_target_orphan, interpreter_in_tmp]` — same shape as
      `ssh_sshrc_unmanaged_exec`. Detections 41. Tests: 18-case extractor
      table, 5 detection-matcher goldens, module golden `env_hook_environment`
      (env_hook_set + exec_target_orphan via the real collector). `make all`
      green (incl. duckdb-equiv). Lab round 28 (Debian, 6 hosts) via
      `apt2-env-hook`: validate-evade.py all PASS — env_hook_set +
      non_package_path (real dpkg provenance resolved /opt/.envhook/agent
      orphan) + profile_env_hook_unmanaged in Q7 on the implant host only;
      env_hook_set on 1/6 hosts, profile_env_hook_unmanaged fires exactly
      once fleet-wide, ZERO clean-host FP on the 5 baseline hosts.
      2. DONE + LAB-VALIDATED (round 29, Debian)
         **initramfs hook module** (duel-2 backlog #2). NEW module
         `internal/modules/initramfs/`, generator-AGNOSTIC — covers all of
         Linux, not just two distros: initramfs-tools (Debian/Ubuntu/Mint/
         Devuan/Kali), dracut (RHEL/Rocky/Alma/Fedora/SUSE/Gentoo) and
         mkinitcpio (Arch/Manjaro/Artix). Recursively walks each generator's
         hook/script dirs (local /etc + package /usr); one
         `boot.initramfs.hook` record per regular file, ExecTarget=self so
         provenance flags a non-package hook and the sink's
         package_file_tampered covers an in-place overwrite of a packaged
         hook (Bootkit shape). Local /etc dirs are empty on a stock host
         (verified) → any file there is an addition; /usr hooks stack
         fleet-identically. MITRE T1542 (parent; no Linux initramfs
         sub-technique). Detection `initramfs_hook_unmanaged` (high),
         `module_in:[initramfs]` + `signals_any:[non_package_path,
         package_file_tampered]`. Detections 41→42. site_classes 47→48.
         modset 25→26. Registered in modset + both matrix.yaml copies.
         Tests: 4 unit + 2 golden (multi_generator_hooks, clean_empty) + 4
         detection-matcher goldens; stats MITRE-panel golden bumped 24→25
         techniques. `make all` green. Live-host smoke (real Ubuntu WSL):
         42 initramfs records all under /usr/share (package-owned), 0 under
         /etc, ZERO non_package_path / tamper / Q7 FP. OOS (documented in
         matrix notes): compiled initrd cpio + config file-baking
         (dracut.conf.d install_items, mkinitcpio.conf FILES=). Lab round 29
         (Debian, 6 hosts) via `apt2-initramfs-hook`: validate-evade.py all
         PASS — planted /etc/initramfs-tools/hooks hook → non_package_path
         (real dpkg provenance) + initramfs_hook_unmanaged on the implant
         host only; fires exactly once fleet-wide; the 5 clean hosts each
         carry 5 package-owned /usr/share hook records with ZERO
         non_package_path. The same recursive walk + provenance path covers
         dracut + mkinitcpio (unit/golden-validated).
      3. DONE + LAB-VALIDATED (round 30, Debian)
         **ld.so.conf.d library SHADOW** (duel-2 backlog #3). Extends the
         `ldso` module: a search-path directive that adds a NON-standard dir
         (not under /lib, /usr/lib, /lib64, /usr/lib64 or /usr/local/lib —
         prefix match, so multiarch + sanctioned local dirs are exempt)
         whose `*.so*` basename collides with a package-OWNED library on a
         standard path emits the new signal `ld_library_shadows_packaged`,
         with the planted .so as ExecTarget (so non_package_path co-fires).
         The search-path dir is still NEVER an exec_target (the v0.2.0
         FP-flood); only the colliding planted .so is. Bare path-injection
         (non-standard dir, no collision) stays signal-free / LFA-only.
         Collision check: `shadowingSo` enumerates the dir's .so files and,
         for each basename, looks across the memoized standard lib dirs
         (base + multiarch subdirs) for a same-named PkgStatusOwned file.
         Detection `ld_library_shadow_implant` (critical, T1574.006) gated
         `signals_all:[ld_library_shadows_packaged]`. Detections 42→43.
         No new site_class (enriches ldso.confd/conf), so matrix stays 48.
         Tests: 2 unit (collision fires w/ exec_target=planted .so +
         non_package_path; standard dir + no-collision control stay clean)
         + 2 detection-matcher goldens. `make all` green. Live-host smoke
         (real Ubuntu): 7 ldso records, ZERO ld_library_shadows_packaged /
         Q7 FP — the host's two non-/lib dirs (libfakeroot, wsl) are under
         the /usr/lib prefix so are exempt by design. Residual FP class
         (documented in the signal): a locally source-built lib legitimately
         shadowing the distro one. Lab round 30 (Debian, 6 hosts) via
         `apt2-ldso-shadow` (plants /opt/.perflib/libc.so.6 + a .conf):
         validate-evade.py all PASS — ld_library_shadows_packaged +
         non_package_path (real dpkg provenance) + ld_library_shadow_implant
         (critical) on the implant host only; fires exactly once fleet-wide,
         ZERO ld_library_shadows_packaged on the 5 clean hosts.
      4. DONE + LAB-VALIDATED (round 31, Debian)
         **systemd OnFailure= / .path Unit= relationship EDGES** (duel-2
         backlog #4). BACKEND/Q12 correlation, NOT a Q7 rule. New additive
         Record field `Relations []string` (json `relations,omitempty`,
         schema stays 1 per convention) carrying `Key=Value` edges —
         populated ONLY by systemd, empty for every other module. The
         systemd module's `relationEdges` extracts [Unit]
         OnFailure=/Requires=/Wants= targets (After=/Before= excluded —
         ordering only) and [Path] PathModified=/PathChanged=/PathExists=/
         PathExistsGlob=/DirectoryNotEmpty= watches + the activated Unit=
         (explicit, or implicit <basename>.service). Two marker signals:
         `systemd_has_onfailure` (OnFailure= present) and
         `systemd_path_trigger` (.path arms a watch) — Requires=/Wants= are
         edge-only (ubiquitous, no signal, so Q7/the human report stay
         clean). No detection: the payload arm is already flagged by the
         exec/orphan rules; this records the trigger→payload edge so the
         backend joins them. Detections unchanged (43); no new site_class
         (matrix 48). Tests: 4 unit (path explicit/implicit Unit, OnFailure
         + deps with After= excluded, plain unit yields nothing) + golden
         `path_trigger_and_onfailure`; one existing golden gained an
         additive `relations` field (no other churn). `make all` green.
         Live-host smoke (real Ubuntu, 698 systemd units): 217 records with
         relations, 26 systemd_has_onfailure, 6 systemd_path_trigger — all
         on legit vendor units (apport-autoreport.path, e2scrub@.service,
         systemd-ask-password-*.path) with their Unit=/OnFailure= edges
         correctly captured; real-systemd parse validated end-to-end. These
         markers on vendor units are BY DESIGN (backend graph edges, not
         verdicts). Lab round 31 (Debian, 6 hosts) via `apt2-systemd-pathunit`:
         validate-evade.py all PASS — the planted zz-watch.path carries
         systemd_path_trigger + Relations [PathModified=/tmp/.cachetrigger,
         Unit=zz-payload.service], and the activated zz-payload.service
         resolves non_package_path (the chain's payload arm). Both implant
         units exist on the implant host only; the 5 clean hosts carry
         neither.
  - **scope boundaries now documented in scope.md §8.1** (recent_ctime
    live-FS limit, initrd cpio OOS, %config edits report tampered, inline
    interpreter code is signal+LFA).

## Duel-3 (config-embedded exec edges) — branch `duel3-confexec`, LAB-VALIDATED (round 32)

A third red/blue/architects Workflow (re-run via `lab-nspawn/redblue-duel.workflow.js`,
REPO_CONTEXT updated to mark the duel-2 backlog covered) found the dominant
remaining blind spot: a disk-walk collector only sees sites a module was
written for, and an entire FAMILY of **config-embedded exec edges** (a config
whose grammar turns a string into a root-exec/dlopen edge) was uncollected —
evading per-record detection AND LFA (the payload is package-owned and benign
alone; only the config edge naming it is malicious). The architects' unified
fix (not 8 one-off modules) was built:

- **Phase 1 — systemd `.socket`/`.timer`/`EnvironmentFile` relationship
  edges** (commit on branch). Completes the relations feature #4 advertised:
  `relationEdges` gained [Timer]/[Socket]/[Service]EnvironmentFile branches +
  `systemd_timer_trigger`/`systemd_socket_trigger` markers (backend/Q12, no Q7).
- **Phase 2 — NEW generic `confexec` module** (table-driven). Each site =
  (site_class, MITRE, loci globs, grammar); a grammar lifts an absolute
  command/.so to ExecTarget and reuses the central provenance pipeline. A
  record is emitted ONLY when an exec edge is found → clean configs yield
  NOTHING (zero FP by construction). 8 sites + 8 detections (gated
  `site_class_in` + `signals_any:[non_package_path, exec_target_orphan,
  interpreter_in_tmp]`): mail.aliases (`mail_alias_pipe_unmanaged`), incron.d
  (`incron_exec_unmanaged`), logrotate.d (`logrotate_script_unmanaged`),
  pkgmgr.hook=apt+dnf/yum (`pkgmgr_hook_unmanaged`), sudo.conf.plugin
  (`sudo_plugin_unmanaged`, critical), nss.nsswitch (`nss_module_unmanaged`,
  critical, Symbiote — curated vendor-token allowlist), environment.d
  (`environment_d_hook_unmanaged`), xsession.d (`xsession_hook_unmanaged`).
  Only absolute argv0/.so lifted; bare $PATH commands + inline shell left to
  LFA (scope.md 8.1).
- **Deltas:** detections 43→51, site_classes 48→56, modules 26→27, MITRE
  panel 25→27. `make all` green on each commit. Live-host smoke (real Ubuntu):
  systemd timer/socket edges on vendor units (by design); confexec lifted 4
  real owned hooks (rsyslog/suricata logrotate, packagekit apt), ALL
  package-owned → ZERO Q7 FP.
- **Non-actions the duel confirmed:** the symlink/owned-dir "laundering"
  implants are CAUGHT (provenance is exact-path — do NOT add directory-prefix
  ownership); bind-mount runtime byte-view + inline HOOK_CMD shell stay OOS.
- **Tier-3 DEFERRED** (architect-agreed, not in this branch): `getty_autologin`
  (credential-bypass signal, FP on kiosk/appliance — ship signal-first) and
  `mount_shadows_path` (a bounded /proc/self/mountinfo read recording the
  bind-mount desync without reading mounted bytes). Specs in the duel-3
  architect output.
- **LAB-VALIDATED — nspawn round 32 (Debian, 11 hosts).** All 9 implants
  `apt2-{mail-alias,nss-hijack,apt-hook,incron,logrotate,sudo-plugin,
  environmentd,xsession,systemd-timer}` PASS via signal-exact
  `validate-evade.py`: each confexec site lifted its non-package/orphan exec
  edge (real dpkg provenance) and fired its detection; the .timer
  reconstructed the timer->payload edge + the payload service resolved
  non_package_path. Each of the 8 confexec detections fired EXACTLY ONCE
  fleet-wide (on its implant host); ZERO confexec non_package/orphan on the
  clean hosts. (apt2-sudo-plugin also tripped package_file_tampered by
  overwriting the owned /etc/sudo.conf.) Lab implants + data-driven
  validator are committed; re-run any subset with
  `lab-nspawn/fleet.sh --implants <ids>`.

## Coherence backlog (finite — completeness within the charter, ADR-0016)

Not the infinite tail and not Regime 3 — the bounded set that makes the
tool consistent with its own "all-Linux, on-disk persistence" promise.
Prioritised:

1. DONE — branch `provenance-pacman-portage` **provenance for pacman +
   portage + honest degradation for unsupported managers.** Was the
   sharpest coherence gap: on Arch/Gentoo/Nix `pkgMgr==PkgMgrNone` made
   `LookupPath` return Unknown for everything, so `non_package_path` /
   `package_file_tampered` were SILENTLY INERT — a clean Q7 looked like
   "nothing found". Added `PkgMgrPacman` (/var/lib/pacman/local/*/files,
   `%FILES%` parse) and `PkgMgrPortage` (/var/db/pkg/*/*/CONTENTS, obj/sym
   paths; VerifyPath via the CONTENTS md5 — pacman tamper deferred: hashes
   live only in the gzipped mtree). detect: os-release prefs (arch/manjaro/
   endeavouros/artix/… ; gentoo/funtoo/calculate) + presence + precedence.
   Honest degradation: new `host_meta.pkg_mgr` field (dpkg/rpm/apk/pacman/
   portage/none) so the backend can tell "empty" from "oracle unavailable",
   plus a loud stderr Warn on PkgMgrNone. Unit-tested (pacman/portage
   ownership, portage tamper, arch/manjaro/gentoo detection); `make all`
   green; live-host (Ubuntu) shows pkg_mgr=dpkg, non_package_path not
   regressed. LAB-VALIDATED on real Arch (nspawn round 40, via the new
   arch-bootstrap): host_meta.pkg_mgr=pacman on the whole fleet (provenance
   NOT inert), the implant files resolved non_package_path via the real
   pacman DB, 4 detections fired (one per implant host), zero Q7 clean-host
   FP. (12 clean-host non_package SIGNALS were all correct — 11 orphan
   targets absent from the minimal bootstrap, e.g. /usr/bin/quotaon without
   the quota pkg, a known base-fidelity artifact like Debian minbase/udev;
   1 a genuinely-unowned admin config /etc/locale.conf — none fire Q7, all
   fleet-common so not LFA singletons.) **Gentoo/portage ALSO lab-validated**
   (round 41, via gentoo-bootstrap fixed to parse the PGP-clearsigned
   latest-stage3 pointer): host_meta.pkg_mgr=portage fleet-wide, all 4
   implants PASS via the real portage CONTENTS DB. That round surfaced one
   real critical FP — `suid_binary_outside_package_path` on
   /usr/bin/unix_chkpwd on every clean Gentoo host — caused by Gentoo's FULL
   usr-merge (/bin,/sbin,/usr/sbin all collapse into /usr/bin) while portage
   records /sbin/unix_chkpwd: a /usr/bin lookup never tried the /sbin key.
   FIXED on branch `provenance-usrmerge-collapse`: `usrMergeAlternates` now
   returns the basename under all four bin/sbin merge dirs (was 1:1 pairs),
   so the /sbin record resolves owned. Generic (helps any distro), unit-
   tested; re-run `--suite gentoo` to confirm the unix_chkpwd FP is gone.
   NIX stays on the honest-degradation path (content-addressed store needs
   its own resolver).
2. DONE — branch `runtimeinit-python` **interpreter/runtime auto-exec.**
   New `runtimeinit` module (site_class `runtime.python`): walks the
   CPython site/dist-packages dirs (globbed across distro layouts +
   per-user ~/.local) for `sitecustomize.py` / `usercustomize.py` and
   *.pth files carrying an `import` code line; ExecTarget=self so
   provenance gates it (a shipped sitecustomize / distutils-precedence.pth
   resolves OWNED and stays silent — the gate is load-bearing, both are
   common+packaged; a planted/tampered one fires). Detection
   `python_runtime_hook_unmanaged`. Follows symlinks (Debian ships
   sitecustomize as a symlink to /etc/pythonX/ — live-host smoke caught
   this, fixed with os.Stat). PHP added to confexec (site_class `php.ini`:
   auto_prepend_file/auto_append_file → `php_autoprepend_unmanaged`); the
   environment.d env-hook grammar extended with PYTHONSTARTUP (path) and
   NODE_OPTIONS `--require/--import <path>`. PERL5OPT=-M / RUBYOPT=-r carry
   module NAMES not paths → LFA (documented). Detections 51→53,
   site_classes 56→58, modules 27→28. make all green; live-host (Ubuntu):
   2 code-.pth + the symlinked sitecustomize collected, ALL package-owned,
   ZERO Q7 FP. LAB-VALIDATED on real Arch (nspawn round 40): the planted
   .pth in Arch's site-packages -> non_package_path (real pacman provenance)
   + python_runtime_hook_unmanaged, zero Q7 clean-host FP.
3. TODO — finish the loops already opened: duel-3 Tier-3 (`getty_autologin`
   signal; `mount_shadows_path` via a bounded /proc/self/mountinfo read) +
   dpkg/rpm maintainer scripts (postinst/preinst/%post) as a pkgmgr.hook
   sibling.

### Multi-distro nspawn lab (Arch + Gentoo) — validates coherence #1 + #2

The nspawn lab now boots Arch and Gentoo, the same way it does Debian
(debootstrap) and Rocky (cloud-image extract), so pacman/portage
provenance (#1) and the runtimeinit module (#2) can be validated on real
distro package DBs. Built `lab-nspawn/arch-bootstrap.sh` (official Arch
bootstrap tarball → real /var/lib/pacman/local) and
`lab-nspawn/gentoo-bootstrap.sh` (official **systemd** stage3 → real
/var/db/pkg with per-file md5). Each writes `$CACHE/<suite>.base.tar`, the
same contract `fleet.sh --suite` already uses for rocky9. NOTE: like the
rest of `lab-nspawn/`, these scripts are LOCAL-ONLY (the dir is
gitignored); the TRACKED pieces are the implant `apt2-python-hook` +
catalog entry. New lab implant `apt2-python-hook` (a code .pth in the
python site dir) validates runtimeinit AND, being a non-package file,
doubles as a pacman/portage non_package_path check.

Run (each suite needs its base built once, as root):
```
! sudo apt install -y curl zstd tar xz-utils libguestfs-tools
! sudo lab-nspawn/arch-bootstrap.sh
! sudo lab-nspawn/fleet.sh --suite arch --round 40 \
    --implants apt2-python-hook,apt2-mail-alias,apt2-systemd-pathunit,apt2-initramfs-hook
python3 lab-nspawn/validate-evade.py lab-nspawn/out/round-40
# then the same with: ! sudo lab-nspawn/gentoo-bootstrap.sh ; --suite gentoo
```
Expect: each implant's detection fires with `non_package_path` resolved by
the real pacman/portage DB (proving #1), and `python_runtime_hook_unmanaged`
fires on Arch's site-packages (proving #2), zero clean-host FP.

Still OPEN:

- **eBPF state inspection** (deferred from v0.5.0 candidate
  backlog). Requires vetting the cilium/ebpf dependency vs. the
  project's "no CGO, no daemons, pure Go" invariant. Could surface
  in-memory persistence (bashrc loaded by current shells,
  LD_PRELOAD active in running procs, kprobes hooked by rootkits)
  that artifact-on-disk modules cannot see. ADR needed first.
- **Webshell + supply-chain walk** (deferred). Walk
  DocumentRoot-style paths (`/var/www/`, `/srv/`, common custom
  roots), hash candidate PHP/JSP/CGI files, compare against a
  small embedded hash catalog. Lower-risk than eBPF — fits the
  existing artifact-walk-on-disk model.

## Next sprint (v0.4.0 — "close the Linux MITRE bridge") — ARCHIVED, all six tasks shipped in v0.4.0

**Theme**: depth over breadth. Cover the three highest-impact
Linux persistence techniques that the current 18-ID matrix
misses, plus close the Q12 worm-profile-arm deferred item from
v0.3.4. Estimated 1-2 days. Three other paths (cloud-native /
container orchestration; eBPF state inspection; webshell walk +
supply chain) were considered for v0.4.0 and lifted to v0.5.0+
because they each require new infra (k8s YAML parsing, cilium/ebpf
dependency vetting, hash catalogs respectively) — v0.4.0 stays
artifact-walk-on-disk like the existing modules.

### 1. T1546.005 Trap detection — extend `profile` module
- MITRE: T1546.005 (Event Triggered Execution: Trap).
- Loci: `/etc/profile.d/*.sh`, `/etc/bashrc`, `/etc/zshrc`,
  `/etc/profile`, `~/.bashrc`, `~/.profile`, `~/.bash_profile`,
  `~/.zshrc`.
- Implementation: line-level scanner for
  `^[[:space:]]*trap[[:space:]]+` matching `trap CMD SIGNAL...`.
- Site_classes: `profile.trap.system`, `profile.trap.user`.
- Signals: `trap_command_in_profile`,
  `trap_command_under_tmp` (when CMD path resolves under /tmp).
- Golden tests: happy path, EXIT-only, multi-signal, commented-out
  (must not fire), nested in conditionals.
- Tracked as task #11.

### 2. T1548.001 Setuid/Setgid module — new `suidbits`
- MITRE: T1548.001 (Abuse Elevation Control Mechanism: Setuid
  and Setgid).
- Loci (configurable, defaults): `/usr/bin`, `/usr/sbin`,
  `/usr/local/bin`, `/usr/local/sbin`, `/opt`, `/tmp`, `/home`.
- Implementation: walk each root, filter `mode & 04000` (suid)
  or `mode & 02000` (sgid). Skip `/proc`, `/sys`, `/dev`,
  `/run` (pseudofs).
- Site_classes: `suid.system`, `sgid.system`, `suid.user`,
  `sgid.user`.
- Signals: `suid_bit_set`, `sgid_bit_set`, `non_package_path`
  (via provenance helper — already exists), `world_writable`.
- Care: many suid binaries are legitimate (passwd, sudo, mount,
  ping, su...). The provenance helper will filter them as
  package-managed; only `non_package_path` ones bubble up
  to Q11.
- Tracked as task #12.

### 3. T1098.007 Privileged group signals — extend `passwd`
- MITRE: T1098.007 (Account Manipulation: Additional Local or
  Domain Groups).
- The `passwd` module already parses `/etc/group` and emits
  one record per group entry. v0.4.0 adds detection-oriented
  signals tagging membership of privileged groups: `wheel`,
  `sudo`, `docker`, `adm`, `lxd`, `root` (when non-root user
  is a member).
- New signal names: `group_wheel_membership`,
  `group_sudo_membership`, `group_docker_membership`,
  `group_adm_membership`, `group_lxd_membership`,
  `group_root_membership`.
- matrix.yaml: new `passwd.group.privileged` site_class entry.
- Tracked as task #13.

### 4. Q12 worm-profile-arm consolidation
- See "What is OPEN" above. The profile module learns to
  populate `exec_target` from the script body (look for the
  primary command being sourced or executed), so the 3-arm
  worm clusters in a single Q12 row instead of two.
- Tracked as task #14.

### 5. Lab v2 fixtures for the 3 new techniques
- Three new implant templates + catalog entries + placements:
  `trap-bashrc-payload` (T1546.005, armed),
  `suid-rooted-binary` (T1548.001, armed),
  `group-wheel-attacker` (T1098.007, armed).
- Ground truth grows from 33 to 36 placements.
- Tracked as task #15.

### 6. Release gate v0.4.0
- `make all` clean + lab v2 re-bench + CHANGELOG + commit +
  tag + push, same shape as v0.3.4. Tracked as task #16.

### Sprint composition
- Order of attack: #11 (trap, smallest), #13 (group signals,
  small), #12 (suidbits, medium new module), #14 (Q12
  profile-arm, requires careful parsing), #15 (fixtures), #16
  (release gate).
- Validation: each task must pass its own golden tests + the
  full repo `go test -race ./...` before moving to the next.
- Tooling lesson from v0.3.4: **prefer Write + Python over
  Edit tool for any change touching files > 100 lines on the
  Windows-mounted filesystem** — the Edit tool truncated the
  EOF of stats.go, main.go, stats_test.go, and catalog.yaml
  during v0.3.4, all recoverable but costly to chase. Recovery
  pattern: `git show HEAD:<path>` → in-memory edit → Write the
  whole file. The git-related ops (status / diff / commit / tag /
  push) must run from Jarmi's WSL because the sandbox's mount
  cache shows a phantom `.git/index.lock` plus zombie `./`
  index entries that block `git restore --staged`.

---

The block below is the original handoff body, conserved as-is.

## Current inventory (from matrix-audit + code)

```
21 Go packages, all tests green under -race.
3 binaries  : linpersist (agent), linpersist-report, detgen
21 modules  : atjobs, cron, grub, kmod, ldso, linger, motd,
              netdispatch, pam, passwd, polkit, profile, ssh,
              sshd, sudoers, sysusers, systemd, sysv, tmpfiles,
              udev, xdg
32 site_classes (in matrix.yaml, all status=implemented)
43 signals  (internal/core/signals.go + catalog in signals_catalog.go)
23 detections (internal/detections/detections.yaml)
14 ADRs     (docs/adr/0001..0014)
11 queries  (Q1..Q11 in stack_demo.sql, mirrored in
              cmd/linpersist-report/stats.go)
2 release gates: `make audit` (ADR-0001) + `make detgen-verify`
              (ADR-0013), both wired into `make all`.
```

Last fleet validation against `lab-realistic` (75 hosts, ~35 k
records): Q1=26, Q4=6, Q7=22 (13 critical + 9 high), Q8=40,
Q11=6. Zero post-calibration FPs in the tmpfiles signal chain.

---

## Architectural canon (do not re-derive)

These are the rules every sprint has had to internalise. They are
written down in their respective ADRs but bundled here for the
"new session, no context" case.

1. **The agent collects; the backend decides.** No verdicts in
   `linpersist` itself. Detections live in `detections.yaml`, not
   in module code. ADR-0001.

2. **`content_norm_sha256` is the pivot.** Each module's
   canonical form must be deterministic across hosts. Two
   semantically-equivalent inputs must hash the same. This is the
   LFA grouping key — without it, the whole project loses value.
   ADR-0007 for systemd; per-module sections in `docs/modules/`
   (sparse).

3. **`ExecTarget` means "binary the persistence INVOKES".** Not
   "path the directive touches". Tmpfiles taught us this the hard
   way: mapping tmpfiles target paths to `ExecTarget` polluted Q9
   with 341 baseline rows. Three categories to chequear before
   populating:
   - run-the-binary → populate (cron command, systemd ExecStart,
     pam module path, kmod install cmd, udev RUN+=, xdg Exec=,
     ldso preload library, etc.)
   - touch-this-path-but-no-exec → do NOT populate (tmpfiles target
     path)
   - marker-only → do NOT populate (linger file presence)
   ADR-0014, calibration commit `7b736af`.

4. **Signals catalog ↔ emission must be consistent at build time.**
   Two cross-source audit tests in
   `internal/core/signals_emission_test.go` scan the source tree
   with regex and fail the build on drift. Adding a new signal
   requires THREE coordinated changes: const in `signals.go`, entry
   in `signals_catalog.go` Signals slice, real emission from a
   module or core helper. ADR-0011.

5. **detections.yaml is the single source of truth for Q7
   clauses.** The Go matcher in `stats.go` and the SQL `WHERE`
   block in `stack_demo.sql` BOTH come from it. `make
   detgen-verify` enforces this. Touching only one side breaks
   `make all`. ADR-0013.

6. **The host dossier (`--host`) is single-host-per-invocation,
   on demand.** Never embedded into the fleet report (does not
   scale: 1000 hosts → 1000 tabs). Q3 / Q5 / Q6 / Q10 are
   deliberately omitted from the dossier (fleet aggregates, no
   per-host meaning). ADR-0012.

7. **Zero CGO, build tags `osusergo netgo` always.** Verified by
   `tools/verify_static.sh`. Any dependency that drags in CGO gets
   rejected. Pure-Go YAML (gopkg.in/yaml.v3) and pure-Go regex
   (stdlib) are the only exceptions to "stdlib first".

8. **Output is NDJSON to stdout by default.** Agent never writes
   to the host disk except `--output <file>` if specified. No
   network calls from the agent. Transport is the operator's
   problem.

## Lessons learned across sprints (calibration history)

These are operational. The current `detections.yaml` reflects
them; future calibration should preserve the same instincts.

- **`curl` / `wget` in shell init**: raw substrings flood with
  dotfile-installer FPs (rustup, nvm, homebrew). Refined to
  piped-to-shell patterns (`| sh`, `curl | `, etc.). v0.2.x-tune.
- **`/tmp/` in sysv init**: raw substring flooded with lockfile
  FPs (mktemp, /tmp/<svc>.lock). Refined to implant-style
  patterns (`. /tmp/`, `exec /tmp/`, `/tmp/.`). v0.2.x-tune.
- **`kmod_install_directive` alone**: dist-alsa, nvidia, wireguard
  ship legitimate `install <mod> <cmd>` lines. Refined to require
  `signals_any: [interpreter_in_tmp, exec_target_orphan,
  non_package_path, shell_indirect]`. v0.2.x-tune.
- **`sudoers_nopasswd + sudoers_all_commands`** still FP-prone for
  CI service accounts (jenkins, gitlab-runner, ansible). Pure-
  signal calibration cannot disambiguate without role tags
  (v0.3.1 work). Detection ships LOUD with the FP channel
  documented in the rule description.
- **tmpfiles `creates under /tmp`** had a v1 that fired on X11
  socket dirs, systemd-private sandboxes, dnf locks. Calibration
  in agent: require `f`/`F`/`w` type letter (file create, not
  dir), reject paths with glob/template metacharacters
  (`*?%[`), allow-list X11 baseline dirs. v0.3.0-coverage post-
  validation calibration.
- **`PermitRootLogin`** signal fires ONLY on literal `yes`.
  `prohibit-password` is OpenSSH 7+ default; flagging it would
  dirty LFA fleet-wide. Documented inline in sshd module.

## Known gotchas (operational)

- **Sandbox ↔ host filesystem desync (WSL2)**. When iterating on
  files from `/mnt/c/...` paths, edits sometimes truncate or
  duplicate on the WSL side while the Windows host sees the
  correct content (or vice versa). Recover by re-reading the
  file with `wc -l` + `tail`, and forcing atomic rewrite via
  bash heredoc (`cat > file << 'EOF'`) or Python. Symptom: `go
  vet` fails with `unexpected EOF, expected }` mid-function.
  Workaround for future sessions: move the repo to native WSL fs
  (`~/Linpersist`) to dodge this entirely.

- **`.git/index` corruption** (Windows-side processes locking the
  index). Symptom: `git status` → `fatal: index file corrupt`.
  Recovery: `rm .git/index && git reset HEAD .`. Working tree is
  preserved; only staging area is rebuilt from HEAD.

- **Index extension warnings** (`index uses XYZ extension, which
  we do not understand`): WSL git is older than the Windows git
  that wrote the index. Same `rm .git/index && git reset HEAD .`
  fixes it.

- **detgen default path**: `--yaml` defaults to
  `internal/detections/detections.yaml` (not the repo root).
  The canonical YAML moved there in v0.2.x because `go:embed`
  forbids `..` patterns. The repo-root `detections.yaml` was
  removed in `bb35f67`.

- **`cmd/detgen` must be re-run after every edit to
  detections.yaml**. `make detgen-verify` (in `make all`) catches
  the drift; `make detgen` regenerates.

## Convenciones del proyecto que no son obvias del código

- **Language gate** (project prompt): conversación con Jarmi en
  español. TODO archivo que vive en el repo (código, comentarios,
  ADR, CHANGELOG, mensajes de commit, schemas YAML, etc.) en
  inglés.

- **Author tag** (project prompt): commits con
  `Jarmi <jarmidaw@gmail.com>`. NUNCA "Arq. Persist" — eso es solo
  el rol pedagógico que la IA adopta en chat.

- **Schema version stays at `1`** even after additive extensions.
  `signals_none` got added in v0.2.x without bumping. The wire
  format stays `schema_version: 1`; ADR updates document what's
  in v1. A bump to `2` only if a breaking change.

- **MITRE IDs are precise**. Use sub-techniques (`T1053.003`) not
  parents (`T1053`) where the sub-technique exists. If no Linux
  sub-technique exists in ATT&CK, the matrix.yaml entry says
  `mitre: [T1546]` (parent) with a note explaining the gap.

- **Test fixtures live under `internal/testdata/golden/<module>/`
  per ADR**. Three module sprints (linger / tmpfiles / sysusers)
  shipped without unit fixtures — deuda menor noted in "Open
  follow-ups" below.

- **Module name vs site_class**: Go package `xxx` typically emits
  `xxx.something` site_classes. The `systemd` package emits
  `systemd.unit` + `systemd.timer`. The three v0.3.0 modules
  (`linger`, `tmpfiles`, `sysusers`) emit `systemd.linger`,
  `systemd.tmpfiles`, `systemd.sysusers` despite their package
  name not carrying the prefix. matrix-audit enforces the
  mapping.

---

## Open follow-ups — punch list

Stuff committed-but-pending, ordered by priority. Tackle from the
top.

### Hard pendings (before tag v0.3.0)

- [ ] **Golden tests for the three v0.3.0 modules** (`linger`,
  `tmpfiles`, `sysusers`). Validated end-to-end against
  lab-realistic; missing unit fixtures per the ADR base
  contract (>=3 edge cases, >70% coverage).
- [ ] **Module reference docs** under `docs/modules/` for the
  three new ones. Other modules also miss this — pay down as we
  go.

### Soft pendings (post-tag, can ship as v0.3.x)

- [ ] **Q9 documentation update**: the Q9 description in
  `docs/stacking-cookbook.md` and `stats.go` predates the
  tmpfiles calibration; mention the
  "ExecTarget-means-invokes-not-touches" rule explicitly.

- [ ] **MITRE coverage panel** in the fleet report. Cross-cuts
  matrix.yaml (technique IDs) and the live records (which
  techniques actually surfaced). Card in the Overview block.
  Proposed in the "Eje 3" doc but not built yet.

---

## v0.3.1-fleet sprint (NEXT recommended)

This is the next sprint by ROI. Scope (do all three together):

### 1. Host tags

Agent accepts `--tag key=value` (repeatable). The tags land in
`host_meta.tags` as a list of strings.

```go
// cmd/linpersist/main.go
flag.Var(&tags, "tag", "key=value, repeatable")
```

ADR placeholder: `0015-host-tags.md`. Format decisions: lowercase
keys, no whitespace, `=` separator, repeatable flag.

### 2. Peer-group LFA by `(os_id, tag)` in Q3

Today Q3 groups by `os_id` only. Add `tag` as a secondary key.
Hosts without a tag form their own "untagged" peer group.

This is THE fix for the CI sudoers FP channel: a fleet with 30
build hosts tagged `role:build`, each with `/etc/sudoers.d/20-jenkins`,
collapses to a single Q3 row (not 30 singletons).

Update `cmd/linpersist-report/stats.go` `computeQ3` and the
matching SQL in `stack_demo.sql` (NOT generated; hand-edit + add a
release-gate equivalent if we want full symmetry).

### 3. `linpersist-report --diff prev.ndjson curr.ndjson`

Time-series diff between two collections. Outputs the same Q1..Q11
layout but every row is annotated:

- `+` appeared since prev
- `-` disappeared
- `Δ` content_norm_sha256 changed (same module+site_class+locus,
  different hash)

Operationally the most valuable next feature. ~300 LOC in a new
`cmd/linpersist-report/diff.go` + template additions.

### Sprint composition

- ~1h30 — host tags (agent flag + Q3 + ADR-0015 + tests).
- ~2h    — diff mode (set semantics, render variants, tests).
- ~30min — MITRE coverage card in Overview.
- ~30min — gate, CHANGELOG, ADR.

Total ~4h30.

---

## v0.3.x / v0.4.0 candidate backlog (after v0.3.1)

Ordered by value, not priority:

- **dbus.services** (`/usr/share/dbus-1/system-services/*.service`)
  — T1543 family. ~30 min implementation.
- **cloud-init** (`/etc/cloud/cloud.cfg`, `/etc/cloud/cloud.cfg.d/`,
  `/var/lib/cloud/scripts/per-boot/`) — T1543/T1547 hybrid. ~60 min;
  bigger because scope is split.
- **Container persistence** (T1543.005 + T1053.007) — docker
  daemon.json, k8s static pods under `/etc/kubernetes/manifests/`.
  Sprint of its own (~2h).
- **Trap handlers** (T1546.005) — extend `profile` parser to
  tokenize `trap '...'` lines. Vector documented in DFIR Report.
- **Initramfs hooks** (T1542 family) — `/etc/initramfs-tools/`,
  `/etc/dracut.conf.d/`. Module of its own.
- **nsswitch.conf** — T1556 family, vector via NSS module
  hijacking.
- **incron / fcron** — T1053.003 sibling cron implementations on
  legacy hosts.
- **Installer packages** (T1546.016) — .deb postinst / .rpm
  %post extraction. Plugin separate from the core agent because
  it requires deb/rpm extraction tooling.

## Tools / process improvements (low-priority but high-value)

- **Move the repo to native WSL filesystem** if you're hitting
  the `/mnt/c/...` desync issue. `~/Linpersist` instead. 10× faster
  git, no more index corruption, no more truncated edits.
- **Cosign-sign release binaries** before v1.0.0 — already on the
  roadmap, needs CI work in `.github/workflows/release.yml`.
- **Reproducible-build check** in CI: build the same source twice
  with the same toolchain → identical SHA256 binaries. We claim
  this is the case (-trimpath, -buildvcs=false) but never tested
  it.

---

## Iterate-fast cookbook (commands you'll need)

These are the commands the last sprints used over and over. Keep
them at hand.

### Rebuild the agent + report (no Docker rebuild)

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -buildvcs=false -tags=osusergo,netgo \
  -ldflags="-s -w -X main.version=$(git describe --tags --always --dirty 2>/dev/null) -X main.commit=$(git rev-parse --short HEAD)" \
  -o dist/linpersist-linux-amd64 ./cmd/linpersist

go build -trimpath -buildvcs=false -tags=osusergo,netgo \
  -ldflags="-s -w" \
  -o dist/linpersist-report ./cmd/linpersist-report
```

### Re-collect against the lab-realistic containers (bind-mount, ~60s)

```sh
LINPERSIST_HOST_BINARY="$PWD/dist/linpersist-linux-amd64" \
  ./lab-realistic/collect.sh
```

### Render fleet HTML + text reports

```sh
./dist/linpersist-report -i lab-realistic/out/fleet-realistic.ndjson -o informe.html

./dist/linpersist-report -i lab-realistic/out/fleet-realistic.ndjson \
  -format text -color=off | less
```

### Per-host dossier

```sh
./dist/linpersist-report -i lab-realistic/out/fleet-realistic.ndjson \
  --host r-db-amzn-03 -o dossier-r-db-amzn-03.html

# Batch dossiers for a list of suspect hosts:
for h in $(cat suspects.txt); do
  ./dist/linpersist-report -i lab-realistic/out/fleet-realistic.ndjson \
    --host "$h" -o "out/$h.html"
done
```

### Headline counts in one line

```sh
./dist/linpersist-report -i lab-realistic/out/fleet-realistic.ndjson \
  -format text -color=off | grep -E "Q[1-9]+ |^    (critical|high|medium):"
```

### Detection distribution per row

```sh
./dist/linpersist-report -i lab-realistic/out/fleet-realistic.ndjson \
  -format text -color=off | awk '/^Q7 /,/^Q8 /' \
  | grep -oE '[a-z_]+_(backdoor|implant|account|override|tmp|fetch|persistence|reference|enabled|external|unmanaged|password|at_boot)' \
  | sort | uniq -c | sort -rn
```

### Gate before commit

```sh
make all
# = lint + test + audit + detgen-verify + build
```

### Adding a new detection rule

1. Edit `internal/detections/detections.yaml`.
2. Run `go run ./cmd/detgen` (regenerates the Q7 block in
   `tools/stack_demo.sql`).
3. Add a golden test case in
   `internal/detections/detections_test.go`
   `TestRepoYAMLMatchesQ7Goldens`.
4. `make all`.

### Adding a new module

1. Create `internal/modules/<name>/<name>.go` implementing
   `core.Module` interface (Name, SiteClasses, Collect).
2. Register in `cmd/linpersist/main.go` and
   `cmd/matrix-audit/main.go`.
3. Add entry to `matrix.yaml` with status `implemented`,
   `test_coverage` and notes.
4. If emitting new signals: add const to
   `internal/core/signals.go`, entry to
   `internal/core/signals_catalog.go` `Signals` slice with
   `EmittedBy: []string{"<modulename>"}`.
5. Add the new module to `EmittedBy` lists for shared signals
   (`recent_mtime_7d`, `world_writable`, `non_root_owner`, etc.)
   if the module emits them.
6. Golden tests under `internal/testdata/golden/<name>/`.
7. `make all`.

### Investigating one host (the DFIR happy path)

```sh
# 1. Where in the fleet?
./dist/linpersist-report -i fleet/ -format text -color=off \
  | grep <suspect-host>

# 2. Full dossier
./dist/linpersist-report -i fleet/ --host <suspect-host> -o dossier.html
xdg-open dossier.html

# 3. Module-level drill via shell
duckdb -c "
  CREATE TABLE r AS SELECT * FROM read_ndjson_auto('fleet/*.ndjson');
  SELECT module, locus, content_snippet, signals
  FROM r WHERE host_meta.hostname = '<suspect-host>'
    AND list_has_any(signals, ['exec_target_orphan','non_package_path','interpreter_in_tmp']);
"
```

---

## Map of the repo (where to look for what)

| Question | Where to look |
|---|---|
| What does the agent collect? | `internal/modules/*/` (one dir per family) |
| What signals can the agent emit? | `internal/core/signals.go` + `signals_catalog.go` |
| What detections fire in Q7? | `internal/detections/detections.yaml` |
| Why was X decided? | `docs/adr/` (14 entries) |
| What's coming up? | This file, section "v0.3.1-fleet" |
| How is the report built? | `cmd/linpersist-report/stats.go` (compute) + `render.go` / `render_text.go` (render) + `host_stats.go` (dossier) |
| What's the analysis SQL? | `tools/stack_demo.sql` (Q7 generated from YAML) |
| Project conventions? | The project prompt (Custom Instructions in Claude) + this file's "Convenciones" section |
| Release gates? | `Makefile` `all` target → audit + detgen-verify |

## ADR index (latest first)

- ADR-0016 — coverage philosophy (enumerative coverage, three regimes,
  two load-bearing assumptions; how to triage a duel finding). Companion
  to scope.md §8.2.
- ADR-0015 — host tags via `--tag key=value`.
- ADR-0014 — systemd structural family (linger, tmpfiles, sysusers).
- ADR-0013 — `detections.yaml` as single source of truth.
- ADR-0012 — `linpersist-report --host` per-host dossier mode.
- ADR-0011 — iterable signals catalog with buildtime audit.
- ADR-0010 — `/proc` live-process correlation.
- ADR-0009 — dpkg / rpm provenance (Q9: rpm switched to
  `--filesbypkg`).
- ADR-0008 — `linpersist-report` dual rendering (HTML + text).
- ADR-0007 — systemd canonical form.
- ADR-0006 — hostname policy (`--include-hostname` opt-in).
- ADR-0005 — password hash never emitted.
- ADR-0004 — sshd Match block canonical form.
- ADR-0003 — SSH public-key blob handling.
- ADR-0002 — record granularity per site_class.
- ADR-0001 — module interface + matrix-audit release gate.

---

## "If something goes wrong" debug map

| Symptom | First thing to check |
|---|---|
| `go vet` fails mid-function | File truncated by WSL desync. `wc -l` + `tail`; rewrite with bash heredoc |
| `make audit` fails | matrix.yaml ↔ modules drift; the audit prints the exact diff |
| `make detgen-verify` fails | detections.yaml edited without `make detgen`; just regenerate |
| Q7 = N+1 with one weird row | A new detection rule baseline-FP'd. Check `awk '/^Q7 /,/^Q8 /'` for the row, calibrate rule |
| Q9 row count explodes | Some module is over-populating `ExecTarget`. Look for newest module's `recordFromLine` |
| Q5 has a signal name nothing matches | Signal in catalog but no rule — open `detections.yaml` and add one |
| `git status: fatal: index file corrupt` | `rm .git/index && git reset HEAD .` |
| `Unable to read current working directory` | `cd .. && cd Linpersist` (WSL stale inode) |

---

## Final sanity check the next session should run

```sh
cd <repo>
git log --oneline -5      # head should be 7b736af or later
make all                  # everything green
go run ./cmd/linpersist-report -i lab-realistic/out/fleet-realistic.ndjson \
  -format text -color=off | grep "Q7 roll-call"
# expected: 22 (or whatever the latest commit's lab-realistic produces)
```

If those three commands work, you have a working baseline.
Anything beyond that, follow the roadmap above.
