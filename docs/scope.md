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
