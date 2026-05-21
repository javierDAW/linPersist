# Sprint handoff — read this first

> File maintained as the "open a new window and pick up where the
> last session left" entry point. If you are returning to the repo
> after a context loss (closed chat, new agent session, new
> developer), start here. It is intentionally dense: everything that
> is non-obvious from the code lives in this doc.
>
> Last updated: 2026-05-20 after the v0.3.0-coverage merge
> (commit `7b736af`).

---

## TL;DR — what landed in main

The project sits **two minor releases past the last tag**:

- `v0.2.0` (tag, commit `a9ac2c4`) — provenance, /proc correlation,
  5 new modules, validated against lab-realistic 75-host fleet.
- `4b73ad7` — signals catalog (ADR-0011), host dossier
  (ADR-0012), declarative Q7 detections via `detections.yaml`
  (ADR-0013). NOT tagged.
- `bb35f67` — repo scrub + `.gitignore` hardening after the first
  push left junk in history.
- `7b736af` (HEAD on main) — v0.3.0-coverage: three systemd-
  structural modules (linger, tmpfiles, sysusers), ten
  orphan-signal detection rules, three module-specific detections,
  Q9 calibration. NOT tagged.

**Next tag should be `v0.3.0`** once the items in "Open follow-ups"
below are closed.

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
