# linpersist — engagement scope

> SOW-ready statement of what the linpersist agent does, what it
> never does, and what evidence it produces. Designed to be quoted
> verbatim in the annex of a consultoría engagement contract.
>
> Applies to the binary distributed in `linpersist-vX.Y.Z-engagement-kit.tar.gz`.
> The exact version + sha256 of the binary handed over MUST be
> recorded in the engagement contract before deployment.

---

## 1. What the agent does

`linpersist` is a read-only Linux persistence-artifact collector. On
invocation it walks a fixed, documented set of filesystem paths that
the Linux kernel and userland use as persistence sites (cron tables,
systemd units, /etc/passwd, ssh authorized_keys, etc.), parses each
file in its native format, computes deterministic content hashes,
and emits one NDJSON record per artifact to **standard output**.

The complete list of inspected paths is enumerated in `matrix.yaml`,
shipped with the engagement kit and embedded in the binary itself
(visible by running `linpersist --help` and the linked module
documentation).

The agent produces **no other side effects** on the target host
beyond:

- Reading files listed in `matrix.yaml`.
- Reading `/etc/os-release`, `/etc/machine-id`, the kernel version
  string, and the hostname (for the per-record envelope).
- Walking `/proc` once per invocation to build a snapshot of
  currently-running processes (the `live_process_attached`
  correlation; disable with `--no-live-process`).
- Querying the local package database (`dpkg`, `rpm`, `apk`) to
  determine which discovered binaries are package-managed (the
  `non_package_path` enrichment; disable with `--no-provenance`).
- Optionally writing the NDJSON stream to a file specified by the
  operator via the `--output` flag.

## 2. What the agent never does

The following actions are **architecturally precluded**. They are
not feature flags — the binary contains no code path that performs
them, and the release pipeline includes static-link and audit
checks that reject any commit that would introduce one.

- **No network calls.** The agent does not initiate any TCP, UDP,
  ICMP, DNS, or HTTP connection. Verifiable by `strace` / `bpftrace`
  during a collection run, or by reading the source under
  `internal/`.
- **No writes outside `--output`.** No log file, no cache, no
  socket, no scratch directory. The agent's only write target is
  the file path explicitly provided by the operator.
- **No persistent installation.** The agent is a single static
  binary. It does not install services, daemons, cron entries,
  systemd units, or shell hooks. Removing the binary from disk
  removes the agent entirely.
- **No mutation of inspected artifacts.** Every file is opened
  read-only. Inspected files retain their original `atime`,
  `mtime`, `ctime`, mode, and content.
- **No execution of inspected payloads.** When the agent records
  that, e.g., a cron entry invokes `/tmp/.payload`, it does not
  execute `/tmp/.payload` — only records the reference.
- **No process killing, no syscall interception, no kernel module
  loading.** Strictly userland read-only.
- **No collection of password hashes.** `/etc/shadow` and
  `/etc/gshadow` are parsed, but the hash field is reduced to a
  status enum (`set`, `empty`, `locked`, `disabled`, `unknown`)
  before emission. The hash bytes never enter any hash input or
  the output stream. (ADR-0005.)
- **No collection of plaintext hostnames by default.** The
  `host_meta.hostname_hash` field is always populated (sha256 of
  the hostname); the `host_meta.hostname` plaintext field is
  emitted only when the operator opts in via `--include-hostname`.
  (ADR-0006.)
- **No collection of SSH private keys, no collection of TLS keys,
  no collection of cloud IAM credentials.** The agent inspects
  `/root/.ssh/authorized_keys` and per-user variants for the
  public-key directives that authorize remote login; it does not
  open `id_*` private key files, `*.pem`, `~/.aws/credentials`,
  `~/.config/gcloud/`, or analogous secret stores.

## 3. What it produces

A single NDJSON stream on stdout. Each line is one JSON record. The
schema is documented in `internal/core/record.go`, summarised here:

| Field family | What it contains |
|---|---|
| Envelope | `schema_v`, `host_id`, `host_meta.{hostname_hash, os_id, os_version, kernel, arch}`, `collected_at`, `agent_version`, `agent_commit` |
| Artifact identity | `module` (which collector), `site_class` (where in the persistence taxonomy), `locus` (the filesystem path), `mitre` (MITRE ATT&CK technique IDs) |
| Content | `content_sha256` (raw bytes), `content_norm_sha256` (canonical form for stacking), `content_snippet` (first 256 chars) |
| Resolved target | `exec_target`, `exec_target_sha256`, `exec_target_pkg`, `exec_target_pkg_status` (managed / orphan / non_package_path) |
| File metadata | `owner_uid`, `owner_gid`, `mode`, `mtime`, `ctime`, `atime`, `size` |
| Detection signals | `signals[]` — a list of named conditions the agent observed (e.g. `interpreter_in_tmp`, `world_writable`, `non_package_path`) |
| Errors | `errors[]` — per-field error envelopes when a read or parse failed; the rest of the record is still emitted |

Records carry **no plaintext usernames** under `--redact-pii`. Under
the default mode, group memberships and account names visible in
`/etc/passwd` and `/etc/group` are emitted verbatim because they
are needed for stacking — discuss with the client whether to
enable `--redact-pii` for delivery copies.

## 4. Footprint and operational impact

Measured on Ubuntu 22.04 LTS, 4 vCPU, 4 GB RAM, ext4 on SSD, with
no other significant load:

| Metric | Value |
|---|---|
| Wall-clock per invocation | < 1 second on a typical host (`< 5s` worst case on hosts with very large `/usr/bin` and slow rpm) |
| Resident memory peak | < 30 MB |
| CPU | One core, < 10 % during the run |
| Disk reads | bounded by the size of inspected files (typically < 100 MB total per host) |
| Disk writes | 0 (or `--output` size, if used) |
| Network | 0 packets sent, 0 received |
| Output size | typically 100 KB – 1 MB of NDJSON per host |

Bench numbers for additional OS targets (RHEL 9, Amazon Linux 2023,
Alpine 3.19) are in `docs/benchmarks/`.

## 5. Required privileges

The agent should be run as `root` to read `/etc/shadow`,
`/etc/gshadow`, root-owned cron and systemd files, and the
`/var/spool/at/` queue. When run as an unprivileged user, the
agent **does not abort** — it emits per-file error envelopes for
the artifacts it could not read and continues, so the operator
sees what was missed.

Capabilities-only mode (CAP_DAC_READ_SEARCH) is sufficient and is
the recommended deploy mode when the client policy disallows full
root. The agent is verified to function correctly under that
capability set; CAP_NET_*, CAP_SYS_PTRACE, CAP_SYS_MODULE etc. are
NOT required and SHOULD NOT be granted.

## 6. Distribution integrity

The binary is distributed in `linpersist-vX.Y.Z-engagement-kit.tar.gz`,
which contains:

- `linpersist-linux-amd64` (and `linpersist-linux-arm64`) — the agent
- `linpersist-report-linux-amd64` (and `-arm64`) — the operator-side
  analysis tool (NOT run on client hosts)
- `RUNBOOK.md` — how to invoke
- `SCOPE.md` — this document
- `LICENSE`, `README.md`, `CHANGELOG.md`
- `sample-report.html`, `sample-report.txt` — examples of the
  analyst-side output the operator will deliver
- `CHECKSUMS.txt` — sha256 of every file in the kit

Each binary in the GitHub Release (`https://github.com/javierDAW/linPersist/releases`)
is additionally signed with **cosign keyless** via the GitHub OIDC
token, producing `.sig` and `.pem` files the client can verify
independently:

```
cosign verify-blob \
  --certificate linpersist-linux-amd64.pem \
  --signature   linpersist-linux-amd64.sig \
  --certificate-identity-regexp 'https://github.com/.+/linPersist/.+' \
  --certificate-oidc-issuer    'https://token.actions.githubusercontent.com' \
  linpersist-linux-amd64
```

The agent itself can also report its own runtime sha256 for
chain-of-custody:

```
linpersist --self-sha256
# 3601...  /usr/local/bin/linpersist
```

This digest MUST match the entry in `CHECKSUMS.txt` shipped with
the kit.

## 7. Source and reproducibility

Full source is published at https://github.com/javierDAW/linPersist
under the license in `LICENSE`. Build pipeline (`-trimpath`,
`-buildvcs=false`, `CGO_ENABLED=0`, `osusergo,netgo` tags) produces
deterministic binaries; any party with the same Go toolchain version
and the source at the same commit will produce a byte-identical
binary.

Architectural decisions are documented in `docs/adr/`. Detection
rules are declarative YAML at `internal/detections/detections.yaml`.

## 8. Limitations

What `linpersist` is NOT, so the engagement scope is honest:

- **Not an EDR.** No real-time monitoring, no behavioral analytics,
  no remediation actions. A point-in-time collector.
- **Not a syscall tracer or memory inspector.** Filesystem +
  `/proc` only. Userland-resident malware that lives only in
  memory (no disk artifact) will not be detected.
- **Not a network or container forensics tool.** Container runtime
  introspection, network packet capture, image scanning are out
  of scope and should be paired with appropriate tools.
- **Not authoritative for compliance frameworks** (PCI-DSS, HIPAA,
  ISO 27001). The output is evidence input for an analyst, not a
  compliance attestation.
- **Reports false positives.** The agent surfaces *patterns* the
  operator must triage. A non-package-path binary may be a
  legitimate vendor install; a sudoers NOPASSWD entry may be a
  CI service account. The Q7 detection rules are calibrated to
  minimise FPs but cannot eliminate them; the analyst's
  judgement is required.

### 8.1 Known detection boundaries (red/blue duel findings)

Surfaced by adversarial APT-emulation testing and documented here so
they are honest engagement limits, not silent gaps:

- **Timestamp aging on image-built hosts.** The `recent_ctime_*`
  anti-timestomp signal relies on ctime being unforgeable on a *live*
  filesystem. An attacker who controls image-build ordering (a poisoned
  golden image / container layer) can produce a planted file whose ctime
  AND mtime are both genuinely old. Combined with byte-identical
  fleet-wide placement (which also defeats LFA singleton stacking), this
  is the irreducible boundary — the agent cannot distinguish a
  genuinely-old benign file from a genuinely-old planted one. LFA on a
  *heterogeneous* fleet remains the discriminator; on a uniformly-imaged
  fleet it does not.
- **Compiled boot images are not unpacked.** `linpersist` walks the
  on-disk *source* of boot persistence (initramfs/dracut hook scripts,
  GRUB config, systemd units/generators) but does NOT unpack the sealed
  `/boot/initrd.img` cpio. A payload baked only into the compiled initrd
  (never present as an on-disk hook source) is out of scope for the
  disk-walk model.
- **Package-owned config edits report as tampered.** `package_file_tampered`
  fires on any package-owned file whose content differs from the
  package-recorded digest — which includes legitimate admin/image edits
  to `%config` files (`/etc/sudoers`, `/etc/cloud/cloud.cfg`, ...).
  `rpm -V` / `dpkg --verify` report the same. These are fleet-common
  (not singletons); LFA is the discriminator. rpm `%verify(not md5)`
  files (the `setup` package's `/etc/passwd` etc.) are correctly skipped.
- **Inline interpreter code is not parsed.** `python3 -c <code>`,
  `sh -c <code>`, `PROMPT_COMMAND=<code>` and base64/obfuscated loaders
  are recorded as signals (e.g. `shell_indirect`) for LFA/backend
  scoring but are not decoded — chasing obfuscation with substring rules
  is an arms race the agent does not enter. The unique content makes them
  LFA singletons.
- **eBPF / kernel state is not inspected.** Malicious eBPF persistence
  (a hidden program attached to a tracepoint/kprobe, a BPF-LSM hook) lives
  in the kernel, not on disk. Enumerating it (`/sys/fs/bpf` pins,
  `/proc/<pid>/fdinfo` prog_ids) yields only a name list with no
  FP-defensible discriminator — it is dominated by legitimate loaders
  (systemd-networkd/resolved, Cilium, Calico, Falco, bpftrace) and telling
  a malicious program from a benign one requires reading bytecode, which
  needs `bpf(2)`/CGO or a resident watcher. That breaks the no-CGO /
  no-daemon / point-in-time invariants, so eBPF state is OUT OF SCOPE by
  charter (Regime 3 per ADR-0016; eBPF *loading* was already rejected in
  ADR-0010). The only disk-resident sliver — a systemd unit or initramfs
  hook that loads a pinned BPF object from an unowned path — is already
  covered by the existing exec-edge / `non_package_path` rules. Pair
  linpersist with an eBPF-aware runtime sensor for the kernel surface.
- **FP-economics gates on the modal small-N install (duel-final).** Three
  collectors deliberately stay SILENT on the common benign shape, leaving
  the rare malicious shape to LFA, because firing on the benign shape would
  flood an analyst on a single-host deployment (where every record is a
  content singleton):
  - *Webroot.* A settled web install (old mtime, mode 0644) emits nothing;
    `webroot.script` records require a co-indicator (`recent_mtime_*` or
    `world_writable`). A single web server with thousands of legitimate
    `/var/www` files is therefore quiet; a freshly-dropped or world-writable
    shell still surfaces. `non_root_owner` is NOT emitted (web content is
    owned by `www-data`/`apache` by design). Trade-off: a webshell dropped
    with a backdated mtime and 0644 into an existing docroot is left to LFA
    content-singleton stacking across a heterogeneous fleet.
  - *Maintainer-script exec edges.* `parseMaintscript` lifts an unmanaged
    exec only when the target is under a tmp-class dir (unconditional) or
    under `/opt` **with a hidden `/.` segment**. A present vendor SDK sourced
    by a postinst (`. /opt/vendorsdk/helper.sh`) is benign and common on
    hosts with commercial agents, so a non-hidden `/opt` payload is left to
    LFA on the script-body singleton rather than firing `non_package_path`
    on every such package.
  - *Python `.pth` files.* setuptools/pip editable plumbing
    (`distutils-precedence.pth`, `__editable__*.pth`, `_distutils_hack` /
    `_virtualenv` import lines) is skipped — ubiquitous on dev/CI/data-science
    boxes and not package-owned, so emitting it would fire
    `python_runtime_hook_unmanaged` 15–40× per workstation with zero TPs.
    Plain path-only `.pth` (sys.path additions) are likewise left to LFA,
    mirroring how `ldso` treats a bare `ld.so.conf.d` dir entry. A real
    planted code-`.pth` does not match the plumbing shape and still surfaces.
- **Provenance-blind hosts are flagged, not silently weaker.** On a host
  with no detected package manager (`host_meta.pkg_mgr` == `none`/empty —
  distroless / from-scratch / appliance images) the `non_package_path` /
  `package_file_tampered` gate cannot run. The report surfaces a
  coverage-degraded banner listing those hosts so an analyst does not read
  "0 findings" as "clean" when it means "could not verify ownership".
- **The peerless single-role host — the discriminator ladder (ADR-0017).**
  LFA content-rarity only discriminates where a valid comparand population
  exists, and homogeneity is a property of a `(host, site_class)` pair,
  not of a host: the one bastion *does* have peers for its base `cron.d`
  yet has **none** for its bespoke `authorized_keys`. Any single-purpose
  host (the one DB, web, jump, CI, monitoring box) carries files that are
  **unique-by-design**, and each becomes a Q1 content-singleton. The
  backend therefore descends a ladder per `(host, site_class)`:
  **(1)** a structural co-indicator (orphan/non-package/tmp/tamper/…) →
  **actionable regardless of population**; **(2)** a sized homogeneous
  cohort (`os_id`+tags, ≥ peer-floor) → cohort-LFA; **(3)** a prior
  snapshot of the host → within-host diff; **(4)** none of the above →
  the bare content-singleton (`co=0`) is **INFORMATIONAL ONLY — ranked
  and shown, never suppressed, never deleted**. The Q1 panel renders this
  as two groups (Actionable vs Informational). The **irreducible
  boundary**: a settled, tell-free implant on a peerless host seen on
  first contact (no prior snapshot) is a `co=0` singleton indistinguishable
  from the benign unique-by-design files at the same locus — linpersist's
  honest role there is **triage, not adjudication**. Restore verdict-power
  by deploying across role replicas (≥ peer-floor), re-scanning over time
  (diff), or pairing with host-baselining / EDR. This is a sibling of the
  packaged-LOLBin and golden-image boundaries, not a defect.

### 8.2 Coverage model — what stays uncovered, and why

`linpersist`'s coverage is **enumerative**: a persistence site is
covered only where a module walks its locus and parses its grammar. The
Linux persistence surface is open-ended, so coverage is best understood
as **three regimes**, not a percentage. (Architectural rationale:
ADR-0016.)

1. **Covered well — the tool's domain.** On-disk artifacts at *known
   loci* carrying a structural tell (orphan / non-package / tmp /
   tampered / recently-changed), surfaced by fleet rarity (LFA). The 56
   site_classes in `matrix.yaml` live here; recall is high and FPs are
   calibrated low. This is what the engagement buys.

2. **A long tail, inside the model.** Every other config-file-with-an-
   exec-edge that does not yet have a parser: language-runtime auto-exec
   (Python `.pth`/`sitecustomize`, `NODE_OPTIONS`, `PERL5LIB`, ...),
   obscure scheduler/init variants, per-application hooks. New software
   adds new sites. We extend coverage here by value; **we do not claim to
   exhaust it.** A finding here is a prioritisation question, not a
   defect.

3. **Out of scope, by design — another tool's job.** A point-in-time,
   agentless, disk-walk collector cannot (and should not) see:
   in-memory / fileless implants; the *runtime* view when it diverges
   from disk (bind-mount/overlay shadowing, rootkit-hidden entries, a
   deleted-but-open file); kernel/eBPF/loaded-module state; firmware /
   pre-OS bootkits; and anything that exists only between scans or only
   at trigger time. Covering this regime means becoming an EDR — a
   resident agent with entirely different cost, footprint and false-
   positive characteristics. Pair `linpersist` with such tools; it does
   not replace them.

**Two assumptions that, if false, silently defeat the tool** — state
them to the client up front:

- **Package metadata is trusted.** The non-package / tampered signals
  trust the dpkg/rpm/apk database. A *malicious package-owned* binary (a
  poisoned repository, a trojaned package) resolves as "owned" and stays
  silent. `linpersist` is not a supply-chain attestation (SBOM /
  signature) tool.
- **Fleet rarity needs a heterogeneous fleet.** On a single host, or a
  uniformly-imaged fleet where the implant is baked into the golden
  image, the singleton model degrades. Persistence built from only
  owned binaries on owned paths (or malicious *arguments* to a
  legitimate directive) carries no structural tell and is recorded for
  rarity analysis only.

The honest one-line summary: **`linpersist` is a high-precision,
low-false-positive, agentless triage layer over on-disk persistence
state — one layer of a defensive stack, with deliberate, documented
boundaries, not the whole stack.**
