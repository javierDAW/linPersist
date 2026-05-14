# ADR-0006: Hostname representation in host_meta

- Status: Accepted
- Date: 2026-05-14
- Related: `docs/schema-v1.md`, `internal/core/hostmeta.go`,
  `cmd/linpersist/main.go`.

## Context

Every record carries a `host_meta` envelope. Two fields in that
envelope describe the host's name:

- `host_meta.hostname_hash` — always present. Up to this ADR it was
  `"sha256:" + hex(sha256(os.Hostname()))` with no further processing.
- `host_meta.hostname` — plaintext, only emitted when the operator
  passes `--include-hostname`. Default OFF.

A third field, `host_id`, also implicitly carries identity. Its source
order is `/etc/machine-id` → `/var/lib/dbus/machine-id` →
`sha256(hostname)`.

Five questions were open and worth pinning down before v0.1.0 tags,
because changing any of them after a public tag is a schema-v1 break:

1. Is the hostname normalized before hashing?
2. Is the hash salted / HMAC-ed?
3. Is `host_id` (machine-id) emitted in plaintext?
4. Under what conditions is `host_meta.hostname` plaintext emitted?
5. How are container / Kubernetes / autoscaling workloads — whose
   hostnames are per-instance random — handled given that
   `hostname_hash` is supposed to group equivalent hosts?

## Decision

### 1. Normalize the hostname before hashing

`hashHostname(h)` now computes
`"sha256:" + hex(sha256(normalizeHostname(h)))` where

```
normalizeHostname(h string) string {
    h = strings.ToLower(strings.TrimSpace(h))
    if i := strings.IndexByte(h, '.'); i >= 0 {
        h = h[:i]
    }
    return h
}
```

That is: ASCII-lowercase, then truncate at the first `.`.

This collapses the four cosmetic variants commonly seen on the same
fleet — `WEB-01`, `web-01`, `web-01.prod.example.com`,
`WEB-01.PROD` — into one canonical input. Without the normalization,
the same logical host produces four distinct hashes depending on how
`/etc/hostname`, `/proc/sys/kernel/hostname`, and the DNS suffix were
populated by the provisioner, and LFA across the fleet fragments into
noise.

The plaintext `host_meta.hostname` field (when `--include-hostname` is
set) carries `os.Hostname()` verbatim — no normalization. Operators
who opt in to plaintext want the original value, not a transform of
it.

### 2. No salt in v1

The hash is plain `sha256`, no salt, no HMAC. The threat the salt would
mitigate is rainbow-table reversal of `hostname_hash` against a
predictable naming scheme (e.g. `web-001` through `web-5000`) given an
adversary who has obtained the log stream.

We accept that risk in v1 because:

- A salt that ships inside the agent binary is publicly visible to
  anyone who can inspect the binary and adds no real protection.
- A salt that lives outside the agent and is rotated per-fleet
  requires a key-management mechanism (sidecar, env var, vaulted
  secret). That is out of scope for a static, read-only collector.
- The operator who *needs* this hardening can already achieve it by
  not emitting `hostname_hash` at all and joining records by `host_id`
  (machine-id), which is not derivable from the hostname.

If a future fleet operator demands it, v2 can add HMAC-SHA256 with a
per-fleet secret, gated by `--hostname-hmac-key=/path/to/key`. Doing
so will bump `schema_v` to 2 because consumers will need to know
which keyspace produced the digest.

### 3. `host_id` (machine-id) is emitted in plaintext

`host_id` carries the contents of `/etc/machine-id` verbatim when
present. This is by design:

- `machine-id` is a per-host opaque identifier defined by systemd /
  D-Bus, intended as a stable join key for telemetry systems. It is
  treated as non-PII by every other endpoint tool the analyst is
  likely to be cross-referencing (osquery, auditd, Velociraptor, EDR
  agents).
- Hashing it would prevent that cross-referencing without adding
  meaningful privacy. The machine-id is already public from the host's
  perspective; treating it as a secret in the collector while it leaks
  through every other channel is theater.
- The fallback chain (`hostname` → `sha256(hostname)`) only kicks in
  on hosts where machine-id is unavailable, and at that point the
  hostname is the only stable identifier the host exposes.

### 4. `host_meta.hostname` plaintext stays opt-in via `--include-hostname`

Default OFF. The flag exists so an operator running on a private
internal log pipeline who *wants* the plaintext hostname for triage
ergonomics can have it; the default protects an operator who pipes
NDJSON to a SaaS or cross-team data lake from leaking the network
topology in cleartext.

Enabling the flag is the operator's explicit assertion that the log
sink is acceptable for plaintext network identifiers. The agent does
not gate the flag on anything; trust is delegated to the operator.

### 5. Container / Kubernetes / autoscaling workloads use `host_meta.tags`

Per-instance random hostnames (`7f6b5c8d4xyz` from Docker,
`web-deployment-7f6b5c8d4-xyz12` from a Kubernetes pod, `i-0abc1234`
from an EC2 ASG) are the failure mode of any hostname-based grouping
strategy. Every replica of the same logical workload produces a
distinct `hostname_hash`, which is exactly the *opposite* of what LFA
wants.

The `host_meta.tags` field already exists in schema v1. The contract
this ADR pins is: the operator is expected to set fleet-level labels
on the agent invocation that identify the logical workload, e.g.
`--tag fleet=prod-web --tag role=api --tag env=production`. The
backend stacks by tag membership, not by `hostname_hash`, on those
fleets.

The agent does NOT introspect the runtime (no `/proc/1/cgroup`
sniffing, no Docker socket calls, no Kubernetes API). All correlation
above the host level is the operator's responsibility, expressed
through tags.

(`--tag KEY=VALUE` as a CLI flag is not yet implemented; the contract
is documented here so the eventual implementation has a target. Until
then operators can inject tags by wrapping the agent in a script that
post-processes the NDJSON.)

## Consequences

- **Breaking change to `hostname_hash` values.** Hosts whose hostname
  contained uppercase letters or a domain suffix will now produce a
  *different* `hostname_hash` than they did before this ADR. We do
  this now, before v0.1.0 is tagged, precisely because there are no
  external consumers locked into the old digest yet.
- **Test gain.** This ADR motivates the first unit tests in
  `internal/core/`: `hashHostname`, `normalizeHostname`,
  `readOSRelease`, `readFirstLine`, `FormatMode`. That starts paying
  down the "zero coverage in core" debt called out in the v0.1.0
  audit.
- **Schema doc updated.** `docs/schema-v1.md` now spells out the
  normalization rule next to the `hostname_hash` field; downstream
  consumers can replicate it if they need to canonicalize an external
  hostname into the same digest.
- **`--tag` flag is debt.** The decision to handle containers via
  `host_meta.tags` only ships in full once the flag exists. Until
  then, the field is reachable only by operators willing to mutate
  the NDJSON downstream. Tracked separately.

## Alternatives rejected

- **Hash the FQDN verbatim.** Rejected: fragments across hosts whose
  resolver populated `/etc/hostname` differently. Same machine,
  different digests.
- **Emit both `hostname_hash_short` and `hostname_hash_fqdn`.**
  Considered. Rejected: two fields invite confusion about which is
  the stacking key. The operator who needs FQDN can flip
  `--include-hostname` and hash on the backend.
- **Default-on `--include-hostname`.** Rejected: a fleet-scale agent
  whose default leaks plaintext network identifiers to whatever
  pipeline the operator wired up is the wrong default. Defaults must
  be safe.
- **Salt the hash with the host's machine-id.** Rejected: makes the
  hash unstable per-host (a reinstall changes machine-id) and breaks
  cross-host equivalence.

## References

- `os.Hostname` — Go stdlib; reads `/proc/sys/kernel/hostname` on
  Linux.
- `machine-id(5)` — systemd documentation for the file at
  `/etc/machine-id`.
- `os-release(5)` — for `host_meta.os_id` and `host_meta.os_version`,
  unchanged by this ADR but parsed alongside hostname.
