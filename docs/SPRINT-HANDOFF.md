# Sprint handoff — read this first

> File maintained as the "open a new window and pick up where the
> last session left" entry point. If you are returning to the repo
> after a context loss (closed chat, new agent session, new
> developer), start here. It is intentionally dense: everything that
> is non-obvious from the code lives in this doc.
>
> Last updated: 2026-05-24 after the v0.5.0 release ("cloud-native
> coverage") and at the close of the v0.4.x line.
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

Still OPEN:

- **`site_class_in` predicate** (lifted from above). Would tighten
  `cloudinit_script_non_package_path` to fire only on
  `cloudinit.script`, eliminating the residual FP class on
  operator-deployed `cloud.cfg.d/*` fragments. Same shape as the
  existing `module_in` predicate — small additive schema change.
  Defer until the residual FP class is observed on a real fleet;
  current bench has zero FPs.
- **Baseline fleet-wide dbus services** (closed in commit 3ff3632).
  Six canonical *.service files (NetworkManager, polkit,
  accountsservice, systemd-{hostnamed,localed,timedated}) added to
  the four modern distro base images via a shared
  `_dbus-system-baseline.sh` helper. Each baseline service stacks to
  count=44 across the fleet; the two implant placements remain the
  only intentional Q1 singletons. Lab Q1/Q4/Q7/Q9 all at 1.00 recall
  (was 0.97 before the baseline due to the pre-existing suid amzn2
  miss, which the rebuild also cleared). A 5-singleton FP class
  remains on r-legacy-amzn2-01 from systemd dbus files preinstalled
  in the `amazonlinux:2` image — kept as documented noise.
- **eBPF state inspection** (deferred from v0.5.0 candidate
  backlog). Requires vetting the cilium/ebpf dependency vs.
  the project's "no CGO, no daemons, pure Go" invariant. Could
  surface in-memory persistence (bashrc loaded by current
  shells, LD_PRELOAD active in running procs, kprobes hooked
  by rootkits) that artifact-on-disk modules cannot see. ADR
  needed first.
- **Webshell + supply-chain walk** (deferred). Walk
  DocumentRoot-style paths (`/var/www/`, `/srv/`, common
  custom roots), hash candidate PHP/JSP/CGI files, compare
  against a small embedded hash catalog. Lower-risk than eBPF
  — fits the existing artifact-walk-on-disk model.
- **ssh-forced-tmp greedy placement bias** (v0.3.4). The greedy
  `assign_implants` in `generate.py` places all 3 ssh-forced-tmp
  instances on build-ci + web-edge, zero on bastion despite the
  `placements: roles: [bastion, build-ci, web-edge]` declaration.
  Cosmetic for now; bench passes. Worth revisiting if more
  implants land with similar role triplets.
- **score.py heuristic is presence-based, not signal-exact**
  despite the docstring's original claim. v0.3.4 corrected the
  docstring. A future revision could tighten the matching once
  the catalog vocabulary is aligned with
  `internal/core/signals.go` literals.
- **Catalog `expected_signals` vocabulary alignment** (v0.3.4
  normalized `ssh-forced-tmp` from `exec_target_orphan` to
  `non_package_path`; other implants may have similar drift).
  Audit-and-normalize sprint candidate.

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
