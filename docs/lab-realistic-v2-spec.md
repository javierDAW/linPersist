# Lab-realistic v2 — design specification

> Status: **Draft** — under construction during the v0.3.3
> sprint. Source of truth for the rebuild of `lab-realistic/`
> that supersedes the v1 fleet shipped in v0.1.0..v0.3.2.

## Philosophy

Lab v1 was "75 minimal Docker containers, one per distro/role
combination, with 11 implant types sprinkled on top". It
validated that the agent reads the canonical persistence files;
it did NOT validate that the agent produces useful output on
the kind of Linux host an operator would actually deploy on. Two
years of `/etc/cron.d/` drift, dozens of vendor packages,
sysadmins editing PAM by hand at 3am, oh-my-zsh chunks in
`~/.bashrc`, JIRA-1234 comments in sudoers — none of that
exists in v1. The result: detection-envelope numbers (precision
1.00 on Q4 / Q9) look great in benchmarks but tell us nothing
about real-world FP rates.

Lab v2 simulates the messy reality. Every host has:

- A full software stack for its role (web tier ships nginx +
  PHP-FPM + certbot + log shipper; DB tier ships PostgreSQL with
  WAL archiving + pg_cron + monitoring exporter; etc.).
- A `provisioned_at` date spread between 6 months and 3 years
  ago. mtimes spread proportionally, so `recent_mtime_*` only
  fires on actually-recent edits.
- 3-8 user accounts with shell variety (bash, zsh, fish), each
  with dotfile abundance (oh-my-zsh, starship, p10k, aliases).
- Vendor non-package binaries under `/opt/<vendor>/` for some
  hosts (DataDog, Splunk forwarder, custom monitoring agent).
- Distro-specific quirks (SELinux contexts on RHEL, snap on
  Ubuntu, OpenRC on Alpine).
- Operator-edited configs with realistic mistakes: trailing
  whitespace, mixed tabs/spaces, line endings, `# DON'T REMOVE`
  comments, deprecated directives.
- Tags assigned per ADR-0015 (`role=`, `env=`, `datacenter=`,
  `tier=`, `team=`).

The lab generator publishes a **ground truth** alongside the
NDJSON: for each implant instance, the exact (host, module,
locus, expected_signal, expected_q7_rule). The benchmark
computes precision and recall by query, not just row counts.

## Goals (what v2 lets us measure)

1. **Real FP rate** on persistence queries — how many vendor
   baselines does Q1 flag as singletons? How many cross-module
   basename overlaps in Q12 are vendor noise vs deploy-sync
   campaigns? Numbers we cannot get from v1.
2. **Precision per detection rule** — for each rule in
   `detections.yaml`, count TPs (implants we placed) vs FPs
   (records that match but are not implants). v0.2.x calibration
   was done by eyeballing v1 output; v2 makes it numerical.
3. **MITRE coverage saturation** — does the panel show all 18
   declared techniques as `surfacing`? Lab v1 had 3 dormant
   (at.jobs, kernel.grub, xdg.autostart) because the lab did
   not seed those vectors. v2 fixes that.
4. **Tag effectiveness** — does Q3 peer-group by `(os_id, tags)`
   collapse the CI sudoers FP channel? v1 had no tags, so the
   ADR-0015 promise of "30 build-host singletons collapse to one
   row" remained theoretical. v2 measures it.
5. **Time-series diff utility** — does
   `linpersist-report --diff` produce useful output on a
   realistically drifting fleet? v1 had no drift, so diff was
   trivially noisy or trivially empty.

## Non-goals

- **Network simulation**: hosts do not talk to each other. The
  agent is local-only and does not need a cluster runtime.
- **Live processes**: containers run only the agent (the v1
  `--rm` collect pattern). The `live_process_attached` signal
  is structurally unusable in this lab; that is a known v1
  caveat and v2 inherits it.
- **Kernel-level realism**: the lab does NOT simulate
  kernel-loaded modules, eBPF state, or running services. The
  agent reads filesystem state; that is what we test.
- **Cross-distro behavior of the same software**: we ship
  PostgreSQL on Debian and RHEL but do NOT verify that the agent
  parses both packagers' init scripts byte-identically — that
  is a Q1/Q3 byproduct of stacking, validated incidentally.
- **Penetration testing**: implants are inert markers, not
  functioning malware. The point is to validate detection, not
  evade or test EDRs.

## Architecture

Same shape as v1: one Docker container per host, generator
script renders Dockerfiles from a declarative spec, `build.sh`
builds, `collect.sh` runs the agent inside each container,
NDJSON aggregated for the report.

What changes from v1:

| dimension | v1 | v2 |
|---|---|---|
| host count | 75 | ~50 (smaller, denser) |
| hosts per role | 3-10 trivially similar | 4-5 differentiated |
| software stack per host | minimal distro base | full role stack + admin drift |
| `provisioned_at` | implicit (build time) | explicit, distributed 6mo-3yr |
| mtimes | uniform (build time) | distributed per file age |
| user accounts | root + 0-2 svc accts | 3-8 users with dotfiles |
| vendor packages | none | per-role realistic vendor set |
| tags | none | per-host axis set |
| ground truth | implicit in catalog | explicit JSONL per host |
| benchmark | row counts | precision + recall per query |

The Dockerfile-per-host approach scales to ~50 containers in
~10 min on a developer laptop (~12s per container with cached
base layers). Docker layer cache makes this tractable for
iterative work.

## Roles

Eleven roles, ~4-5 hosts each = 47 hosts target. Slot for
specials: 1-2 unique hosts (legacy CentOS 7 / amzn2, lone
weird-config) bring total to ~50.

### `web-edge` (4 hosts)

The HTTP termination layer. nginx as reverse proxy + certbot for
TLS + fail2ban + rsyslog/log shipper.

**Software:**

- `nginx` (full config, multiple vhost files under
  `/etc/nginx/sites-enabled/`, real-world TLS ciphers).
- `certbot` cron job for renewal (`/etc/cron.d/certbot`).
- `fail2ban` with `jail.local` admin override.
- `logrotate` configs for nginx access/error logs.
- Either `filebeat` or `vector` (50/50 split per host) as log
  shipper, with per-host config.

**Drift sources:**

- Vhost files added at different dates (3-12 months apart).
- nginx.conf hand-edited (worker_processes adjusted, gzip tuned).
- fail2ban `jail.local` with custom IP allowlist.
- certbot renewal cron edited to add a webhook on success.

**Tags:** `role=web-edge env={prod,staging,canary} tier=edge`

### `web-app` (5 hosts)

Application tier behind the edge. Mix of PHP-FPM and Node.js
between hosts (60/40 split).

**Software:**

- PHP hosts: `php-fpm` + `composer` + `redis-cli` + custom
  systemd service per app.
- Node hosts: `node` + `pm2` (systemd-managed) + `npm` global
  binaries under `/usr/lib/node_modules/`.
- App-specific cron jobs (cache warmup, queue workers).
- `supervisor` configs on legacy hosts (mix in the fleet).

**Drift sources:**

- `composer.lock` / `package-lock.json` with realistic dep
  graphs (touched in `/var/www/<app>/`).
- Multiple app versions deployed (blue/green leftovers under
  `/var/www/<app>/releases/`).
- systemd unit overrides under `<unit>.d/local.conf`.

**Tags:** `role=web-app env={prod,staging,dev} tier=app
runtime={php,node}`

### `db-primary` (3 hosts)

Primary database. PostgreSQL or MySQL (66/33 split).

**Software:**

- PostgreSQL: full `postgresql.conf` + `pg_hba.conf` with real
  replica entries, WAL archiving cron, `pg_cron` extension.
- MySQL: `my.cnf` with `binlog_format` + monitoring user.
- `pgbackrest` or `wal-g` for PostgreSQL backups.
- `prometheus-postgres-exporter` or `mysqld_exporter` (vendor
  non-package binary under `/opt/prometheus-exporters/`).

**Drift sources:**

- `pg_hba.conf` edited multiple times over months
  (`host replication ...` entries added).
- Replica grants in custom `/etc/sudoers.d/postgres-replica`.
- Backup cron with operator comments
  (`# JIRA-2104 -- nightly to S3`).

**Tags:** `role=db-primary env={prod,staging} engine={pg,mysql}
tier=data`

### `db-replica` (4 hosts)

Read replicas + streaming replication consumers.

**Software:** like `db-primary` but with replica connection
configs, no backup cron, monitoring exporter same.

**Tags:** `role=db-replica env=... engine=...`

### `cache` (3 hosts)

Redis or Memcached, plus monitoring.

**Software:**

- Redis: `redis.conf` with realistic eviction policy, AOF or
  RDB persistence, Sentinel config.
- `redis_exporter` (vendor non-package).
- `tuned-adm` profile on RHEL hosts (`/etc/tuned/active_profile`).
- `sysctl.d` drop-ins
  (`/etc/sysctl.d/99-redis.conf` with TCP backlog tuning).

**Drift sources:** sysctl drop-ins, `redis.conf` `maxmemory`
adjusted over time, Sentinel quorum changes.

**Tags:** `role=cache tier=data engine={redis,memcached}`

### `mq` (2 hosts)

Message queue. RabbitMQ or Kafka.

**Software:** RabbitMQ with `rabbitmq.conf`, definitions file,
custom user-tag policies. Kafka with `server.properties` + JMX
exporter.

**Tags:** `role=mq tier=data engine={rabbitmq,kafka}`

### `build-ci` (5 hosts)

The famously noisy class — CI runners. Multiple language
toolchains, Docker socket, NOPASSWD sudoers for the agent.

**Software:**

- `gitlab-runner` OR `jenkins` agent (mix in the fleet).
- Docker installed + the runner user in `docker` group.
- Multiple language SDKs (`/opt/jdk-{8,11,17,21}/`, Python
  `pyenv` install, Node via `nvm`).
- Pre-installed CI tools (`hadolint`, `trivy`, `kubectl` under
  `/usr/local/bin/`).
- `/etc/sudoers.d/20-jenkins` or `/etc/sudoers.d/20-gitlab-runner`
  with `NOPASSWD: ALL` (the v0.2.0 sudoers FP channel —
  intentionally legitimate noise).

**Drift sources:** pyenv shims, nvm-installed node binaries,
runner registration tokens in `/etc/`, custom Docker daemon.json
with insecure-registries entry.

**Tags:** `role=build-ci env={ci,dev} runtime={jenkins,gitlab-runner}
tier=build`

### `k8s-cp` (3 hosts)

Kubernetes control plane. Static pods, etcd, audit policy.

**Software:**

- `kubelet` registered as a node + static pod manifests under
  `/etc/kubernetes/manifests/` (kube-apiserver, kube-scheduler,
  etcd).
- TLS certs under `/etc/kubernetes/pki/` (rotation-aware: some
  certs renewed recently, others stale).
- Audit policy + log writer in `/etc/kubernetes/audit/`.
- `crictl` + `containerd` configs.

**Drift sources:** cert renewal touched specific files;
audit-policy.yaml hand-edited over time; kube-apiserver
manifest with feature-gate flags accumulating.

**Tags:** `role=k8s-cp env={prod,staging} cluster=<name>
tier=cp`

### `k8s-node` (5 hosts)

Worker nodes. Kubelet + container runtime + CNI.

**Software:**

- `kubelet` configured as a worker.
- Container runtime: `containerd` on most, `cri-o` on 1-2.
- CNI plugins under `/opt/cni/bin/` (vendor non-package).
- `kube-proxy` static pod or systemd unit.
- Workload-specific kernel modules in `/etc/modules-load.d/`.

**Drift sources:** modules-load drop-ins added for specific
workloads (`overlay`, `br_netfilter`, sometimes `vxlan` or
`tcp_bbr`); CNI config rotated.

**Tags:** `role=k8s-node env=... cluster=<name> tier=worker`

### `monitoring` (3 hosts)

Prometheus + Grafana + Alertmanager + node-exporter on every
host.

**Software:**

- `prometheus` with scrape configs targeting the fleet
  (realistic large `scrape_configs:` list).
- `grafana` with provisioned dashboards under
  `/etc/grafana/provisioning/`.
- `alertmanager` with routing trees, Slack webhook tokens
  redacted but present.
- `node-exporter` on every host (it's a fleet baseline) but
  the monitoring hosts specifically also run
  `blackbox_exporter`.

**Drift sources:** alert rules accumulated over time, scrape
configs added per service rollout.

**Tags:** `role=monitoring env=ops tier=observability`

### `bastion` (3 hosts)

The SSH bastion. 2FA, audit logging, restricted shell.

**Software:**

- `sshd` with `AuthorizedKeysCommand` calling a vault-cli
  binary (vendor non-package under `/opt/vault-cli/`).
- `pam-yubikey` or `pam-duo` module configured.
- `auditd` rules in `/etc/audit/rules.d/`.
- `rsyslog` forwarding audit logs to SIEM.
- `/etc/security/limits.d/` with per-team overrides.
- Restricted shell `/usr/local/bin/rbash-wrapper` for non-admin
  users.

**Drift sources:** PAM stack edits, audit rules added per
incident, sudo Defaults customizations.

**Tags:** `role=bastion env={prod,corp} tier=access`

### `dev-workstation` (4 hosts)

Developer machines. THE FP minefield: dotfiles, IDE configs,
arbitrary tools, multiple AI CLI configs.

**Software:**

- Multiple language runtimes via version managers (rbenv,
  pyenv, nvm, mise).
- Docker desktop or rootless Docker.
- VS Code with extensions configured under `~/.vscode/extensions/`.
- `tmux` / `screen` configs.
- `~/.ssh/config` with 20+ host aliases.
- `oh-my-zsh` + custom plugins + `~/.zshrc` ~1000 lines.
- `~/.bashrc` with proxy settings, aliases, function library.
- `git config --global` with worktrees, custom aliases.
- **AI CLI configs** — `~/.config/anthropic/`, `~/.config/github-copilot/`,
  `~/.cursor/`, Claude Code settings (emerging vector).
- `~/.local/bin/` with developer tools.

**Drift sources:** all of it. Every developer workstation drifts
weekly.

**Tags:** `role=dev-workstation env=corp team={data,ops,sre,backend,frontend}
tier=internal`

### Specials (1-2 hosts)

- 1 host on legacy distro (CentOS 7 or amzn2) with old-style
  configs (sysv init heavy, no systemd).
- 1 host with deliberate misconfigurations (mode 0666 on
  /etc/cron.d, world-writable sudoers — the kind of operator
  mistakes that look like attacks).

## Distros

Same five as v1:

- `rhel9` (UBI9 base, with subscription-manager files mocked).
- `amzn2023` (Amazon Linux 2023, cloud-init heavy).
- `alpine320` (Alpine 3.20, apk + OpenRC).
- `ubuntu2204` (Ubuntu 22.04 LTS, snap + unattended-upgrades).
- `debian12` (Debian 12 Bookworm).

Plus the **legacy special**: amzn2 or CentOS 7 to exercise the
sysv-heavy path the modern distros have moved away from.

Per-distro idiosyncrasies that v2 actually populates:

| distro | quirks v2 ships |
|---|---|
| rhel9 | SELinux contexts in xattrs, subscription-manager state, `/etc/dnf/dnf.conf` plugins |
| amzn2023 | cloud-init `/var/lib/cloud/instance/`, IMDS-aware scripts, ssm-agent |
| alpine320 | `/etc/apk/world`, OpenRC `/etc/init.d/`, busybox utilities |
| ubuntu2204 | snap packages, `unattended-upgrades` config, `ESM`-tagged sources.list entries |
| debian12 | apt-listchanges hooks, `/etc/apt/apt.conf.d/`, dpkg triggers |

## Drift sources catalog

Every fixture file is stamped with a mtime drawn from a per-host
distribution. The host has a `provisioned_at` and ages
backwards in time: files touched at install time get
`provisioned_at`; files touched by package updates get the
package release date; files touched by the operator get random
dates between provision and "now".

Concretely, six drift classes:

1. **Vendor baseline**: file shipped by the distro package,
   never edited. mtime = package release date.
2. **Vendor recent update**: file shipped by the distro,
   updated by recent `dnf upgrade` / `apt upgrade`. mtime
   within last 30 days.
3. **Admin-edited at provision**: file edited once at host
   provisioning. mtime = provisioned_at.
4. **Admin-edited over time**: file edited multiple times.
   mtime = most recent edit, random within last year.
5. **Recent admin edit**: file edited in the last 7 days.
   Should NOT make Q8 (`recent_mtime_concentration`) flood
   unless the host genuinely had an operator visit.
6. **Implant**: file dropped by attacker. mtime within the
   v0.2.0 "recent attack" window.

The generator's seed (the existing `42`) makes the distribution
reproducible across runs.

## Tags taxonomy

Per ADR-0015 every host carries 3-5 tags from this set:

| axis | values |
|---|---|
| `role` | web-edge, web-app, db-primary, db-replica, cache, mq, build-ci, k8s-cp, k8s-node, monitoring, bastion, dev-workstation, legacy |
| `env` | prod, staging, canary, dev, ci, ops, corp |
| `datacenter` | lhr-01, fra-02, dub-03, ams-01 |
| `tier` | edge, app, data, build, cp, worker, observability, access, internal |
| `engine` | pg, mysql, redis, memcached, rabbitmq, kafka (for relevant roles only) |
| `runtime` | php, node, jenkins, gitlab-runner (for relevant roles only) |
| `cluster` | prod-eu, prod-us, staging-eu (for k8s roles only) |
| `team` | data, ops, sre, backend, frontend (for dev-workstation) |

Expected Q3 peer-group shape: typically 2-3 peer-groups per
role × env combination. Build-ci hosts with `role=build-ci,
env=ci` should cluster together regardless of distro — the v0.2.0
sudoers FP channel COLLAPSE this group expected to validate.

## Implant distribution

The v1 catalog has 14 implants. v2 keeps all 14 plus the 3 new
ones from v0.3.0-coverage. Distribution across the ~50-host
fleet:

| implant id | hosts | targets per query |
|---|---|---|
| cron-tmp-payload | 3 | Q4, Q9 |
| cron-tmp-dangling | 3 | Q4, Q7, Q9 |
| systemd-tmp-armed | 3 | Q9 |
| systemd-tmp-orphan | 3 | Q4, Q7, Q9 |
| ssh-forced-tmp | 3 | Q4, Q7, Q9 |
| sudoers-nopass-attacker | 3 | Q7 (FP channel) |
| passwd-uid0-backdoor | 3 | Q7 |
| kmod-install-implant | 3 | Q7 |
| worm-shared-cron | 1 | Q6 (paired) |
| worm-shared-systemd | 1 | Q6 (paired) |
| worm-shared-profile | 1 | Q6 (paired) + Q12 |
| **linger-non-root-account** | 2 | Q7 (new) |
| **tmpfiles-payload-at-boot** | 2 | Q7 (new) |
| **sysusers-second-uid-zero** | 2 | Q7 (new) |

Total implants: 36 across ~50 hosts. The non-implant hosts (14)
exist to validate clean-baseline behaviour with full software
stacks.

## Ground truth artifact

The generator emits `lab-realistic/out/ground_truth.jsonl`
alongside the NDJSON. One line per implant placement:

```json
{"host":"r-web-app-php-01","implant":"cron-tmp-dangling","module":"cron",
 "site_class":"cron.d","locus":"/etc/cron.d/update-poll",
 "expected_signals":["interpreter_in_tmp","exec_target_orphan"],
 "expected_q7_rule":"payload_under_tmp_via_persistence"}
```

The benchmark joins ground_truth with the rendered Q7 output and
computes:

- **TP** (true positive): an implant placement that appears in
  the corresponding Q7 row.
- **FN** (false negative): an implant placement that does NOT
  appear in Q7.
- **FP** (false positive): a Q7 row whose `(host, module, locus)`
  is NOT in ground_truth.

Per-query precision = TP / (TP + FP). Per-query recall =
TP / (TP + FN).

## Scoring methodology

The benchmark (`docs/benchmarks/v0.3.3-realistic.md`) reports,
for each of Q1 through Q12:

1. **Row count** (carry-over from v1).
2. **Per-row classification** — implant vs FP (using
   ground_truth.jsonl).
3. **Precision and recall** (numerical, not anecdotal).
4. **FP families** — a short prose paragraph naming the
   recurring legitimate patterns that look like hits and the
   proposed calibration (catalog signal, allow-list, peer-group
   tag filter).

For the MITRE panel: count surfacing techniques (target: 18/18
or as close as the implant placement allows).

For tags + Q3: the headline number is "Q1 singletons vs Q3
peer-group survivors". A well-tagged fleet should see Q3
substantially smaller than Q1 — that's the value tags deliver.

For `--diff`: a synthetic re-collection 24 hours after the
first should show only the implants placed in the second pass
as `+ Added`, validating that the diff captures real changes
without flooding with build-time noise.

## File layout

```
lab-realistic/
├── README.md              -- the operator-facing readme
├── policies/
│   └── realistic-50.yaml  -- the v2 generator policy (per-role host counts, distro mix)
├── distros/
│   ├── rhel9.base.Dockerfile
│   ├── amzn2023.base.Dockerfile
│   ├── alpine320.base.Dockerfile
│   ├── ubuntu2204.base.Dockerfile
│   ├── debian12.base.Dockerfile
│   └── amzn2.legacy.Dockerfile  -- new in v2
├── roles/
│   ├── web-edge/
│   │   ├── role.Dockerfile.tmpl       -- master stencil for the role
│   │   ├── files/                     -- static assets injected
│   │   └── README.md                  -- what this role represents
│   ├── web-app/...
│   ├── ... (one per role)
│   └── dev-workstation/...
├── implants/
│   ├── catalog.yaml       -- 17 implants (14 carry-over + 3 v0.3.0)
│   └── templates/         -- one .tmpl per implant
├── scripts/
│   ├── generate.py        -- materialises Dockerfiles from policy + roles + implants
│   ├── ground_truth.py    -- emits ground_truth.jsonl alongside each generate
│   └── score.py           -- runs precision/recall on a rendered report
├── build.sh
├── collect.sh
└── out/                   -- gitignored, generated artifacts
    ├── dockerfiles/
    ├── per-host-ndjson/
    ├── fleet-realistic.ndjson
    └── ground_truth.jsonl
```

## Iteration loop

```
edit policies/realistic-50.yaml or a role template
python3 scripts/generate.py   # regen Dockerfiles + ground_truth
./build.sh                     # rebuild containers (docker cache hot)
./collect.sh                   # re-collect NDJSON
python3 scripts/score.py       # compute precision/recall
./dist/linpersist-report -i out/fleet-realistic.ndjson \
  -format html -o out/report.html
```

Steady-state cycle target: ~5 minutes for a single-file edit, ~30
minutes for a full rebuild.

## Out of scope (revisited, for emphasis)

- Network simulation between hosts.
- Live processes / runtime state.
- Penetration testing of the agent itself.
- Cross-distro behavior verification (incidental from Q1/Q3).

## Closed decisions

These were open during the SPEC draft and are now fixed for the
v0.3.3 implementation. Reopening one requires updating this
section.

1. **Special host count = 1.** One host on a legacy distro
   (`amzn2` chosen — sysv-heavy, no systemd dependency, broadly
   representative of long-lived enterprise hosts). The host
   exercises sysv.init / motd / sysv.kmod paths that the modern
   distros have largely abandoned, and serves as the MITRE
   coverage anchor for techniques the rest of the fleet would
   leave dormant (T1037.004 via /etc/init.d/, T1547.006 via
   /etc/modules-load.d, T1053.001 via at jobs).
2. **AI CLI configs: ship stubs now.** Every dev-workstation
   host gets representative `~/.config/anthropic/`,
   `~/.config/github-copilot/`, `~/.cursor/` and Claude Code
   settings files. Contents are realistic but inert (no actual
   API keys); file structure matches what current AI tools
   write. The stubs are the artifact the future
   `ai-cli.configs` module will read; populating them now means
   v0.4.0 can land that module against a lab that already
   has the vector.
3. **dev-workstation user count = 3 per host.** One primary
   (the host's "owner"), two former employees / inactive
   accounts that nobody got around to deleting. Their dotfiles
   are NOT trimmed — half of v1's "looks clean because nothing
   is there" disappears with this single change. Drift is the
   whole point.
4. **Vendor non-package catalog = 3.** DataDog agent
   (`/opt/datadog-agent/`), Splunk Forwarder
   (`/opt/splunkforwarder/`), Vector
   (`/opt/vector/`). Three is enough to validate the
   `non_package_path` signal calibration without inflating the
   lab build time. DataDog appears on monitoring + bastion +
   db-primary; Splunk on bastion only (regulated-env shape);
   Vector on web-edge log-shipper hosts (50% mix with
   filebeat).
5. **Repo placement: `lab-realistic/` committed, only
   `lab-realistic/out/` gitignored.** The spec writes itself as
   templates + role configs + an implant catalog + scripts; all
   of that is the "lab is part of the product, not a personal
   research note" investment. The previous policy (the whole
   directory gitignored) was a v0.1.0 expedient and explained
   inline in `.gitignore` as such ("privados hasta que v0.2.0
   cierre"). It is past time to lift it. Only the *output*
   (`out/dockerfiles/`, `out/per-host-ndjson/`,
   `out/fleet-realistic.ndjson`, `out/ground_truth.jsonl`,
   `out/report.html`) stays ignored. The .gitignore change
   lands in the v0.3.3 first commit.

## Definition of done for the v0.3.3 lab v2 sprint

- All 11 role templates implemented and produce a valid
  container for at least one distro.
- `generate.py` emits the ground_truth.jsonl alongside the
  NDJSON.
- `score.py` reports per-query precision/recall.
- Benchmark `docs/benchmarks/v0.3.3-realistic.md` shows the
  numbers.
- MITRE panel: at minimum 17/18 techniques surfacing
  (the legacy special host should cover at.jobs and kernel.grub
  with stock distro contents).
- Q1 singleton count: substantially higher than v1 (because the
  software-stack expansion produces legitimate singletons), but
  Q3 peer-group survivors should be markedly fewer than Q1
  thanks to tags.
- All v0.2.0 calibrations still hold: Q4 precision 1.00, Q9
  precision close to 1.00.
- The 13 v0.3.0-coverage detection rules each fire on their
  intended implant placements (recall 1.00 per rule).
