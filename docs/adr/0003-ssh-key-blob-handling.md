# ADR-0003: Handling of SSH public-key blobs in the ssh module

- Status: Accepted
- Date: 2026-05-13
- Related: ADR-0002 (record granularity), `internal/modules/ssh`,
  `docs/schema-v1.md`, MITRE ATT&CK T1098.004.

## Context

The `ssh` module collects `~/.ssh/authorized_keys` and equivalent
files under `/etc/ssh/`, `/root/.ssh/`, and every directory under
`/home/`. Each non-comment, non-blank line in those files has the
shape

```
[options] keytype base64-blob [comment]
```

where `base64-blob` is the public-key material. Two facts drive this
ADR:

1. **The blob is semi-sensitive.** A public key by itself does not
   grant access, but a fleet-wide dump of every authorized public
   key is a high-quality target reconnaissance asset for any
   attacker who later compromises the NDJSON stream or its
   downstream storage. The combination "this exact public key
   authorizes login as user U on host H" is the entire content of
   an authorized_keys file; emitting it verbatim turns linpersist
   into a key-harvesting tool by accident.

2. **LFA only needs equivalence, not content.** Frequency stacking
   asks: "does this key blob appear on exactly one host, or on
   many?" That question is answered identically whether the records
   carry the raw blob or only its SHA-256. Two hosts with the same
   key produce the same `sha256(blob)`; two hosts with different
   keys produce different `sha256(blob)`. The hash is sufficient
   for every stacking query the project documents.

`linpersist`'s design tenet is *the agent collects, the backend
decides*. That tenet says nothing about what level of data
sensitivity the agent should preserve; this ADR fills that gap for
the first site_class where the question becomes material.

## Decision

**The agent NEVER emits the raw base64 blob of an SSH public key.**

Concretely, for every record emitted with `site_class = ssh.authkeys`:

- `exec_target` carries the value of `command="..."` when that
  option is present in the line; otherwise the field is omitted.
  Ordinary keys (no forced command) have no path-like artifact to
  target, so `exec_target_orphan`, `interpreter_in_tmp` and
  `recent_target_mtime_7d` do not fire spuriously on them. Keys
  carrying `command="/tmp/.h/x"` DO fire those signals because the
  forced command IS a path-like artifact.
- `exec_target_sha256` carries the lowercase hex SHA-256 of the
  raw bytes obtained by base64-decoding the public-key blob.
  Always populated (this is the canonical join key for "same key
  across hosts"). Backends MAY join across hosts on this column.
- `content_sha256` is computed over a reconstructed line of the
  form `<raw-options-or-empty> <keytype> <sha256-prefix-12>
  <comment-or-empty>`, where `<sha256-prefix-12>` is the first 12
  hex chars of `exec_target_sha256`. This keeps `content_sha256`
  a one-to-one fingerprint of formatting variations on the source
  line without ever including the blob in the hash input.
- `content_norm_sha256` is computed over the canonical form
  `<canonical-options> <keytype> <sha256-prefix-12>` — comment
  excluded, options sorted alphabetically. See comment exclusion
  rationale below.
- `content_snippet` shows the keytype, the 12-char SHA-256 prefix
  of the blob, and the comment if present. It never shows the raw
  blob. Example:
  `"ssh-ed25519 <sha256:8a3f7c2d9e1b> ops@ansible"`.

The `exec_target_sha256` column is the only field anywhere in the
pipeline that lets a holder of the NDJSON answer "do I have this
specific key?". A holder who has the blob can compute its
SHA-256 and match; a holder who only has the NDJSON cannot recover
the blob, only test specific candidate blobs against the hash.

### Comment exclusion from `content_norm_sha256`

The trailing comment on an authorized_keys line is free-form text
typically set by `ssh-keygen` to `user@hostname-of-keygen-machine`.
It varies between hosts of the same fleet for the same logical
key (different laptops, different config-management revisions,
different generations of a service account).

Including the comment in `content_norm_sha256` would split otherwise
stack-identical records into per-host buckets, defeating LFA. The
comment is preserved in `content_snippet` for human-readability and
analyst attribution but is not part of the join key.

This decision is internal to the SSH module's `Normalize`; ADR-0002
already established per-line granularity as the project default.

## Rationale

- **Exfiltration risk reduction.** An attacker who compromises the
  NDJSON stream (in transit, in the analytical store, in an
  analyst's laptop) cannot reconstruct usable key material.
  Authentication still requires the private half; the public half
  alone does not, but as a reconnaissance asset it tells the
  attacker which keys to look for in private-key dumps from other
  compromised hosts. Withholding it removes that asset entirely.
- **Compliance posture.** Some operators classify public keys as
  attestation material (the matched private key proves who a user
  is). Treating them as not-for-logging by default aligns the
  agent with the stricter compliance regimes without having to
  retrofit redaction later.
- **LFA invariance.** Every stacking query the project documents
  works identically against `sha256(blob)` as against the blob
  itself. We lose nothing analytical.
- **Symmetry with cron's content_sha256.** The `cron` module
  treats `content_sha256` as a hash of the source line bytes, with
  `content_norm_sha256` as a hash of the canonical form. The SSH
  module preserves this convention by substituting the SHA-256
  prefix of the blob for the blob itself in the source-line
  reconstruction. Backends that diff `content_sha256` to detect
  byte-level change still work; they see a change when ANY
  non-blob byte of the line changes, and they see a change when
  the blob itself changes (because the prefix changes too).

## Consequences

- **Cannot revoke a specific public key from NDJSON alone.** An
  operator who wants to push "revoke this key everywhere" cannot
  paste a public key into a backend query and find every host
  carrying it; they must first compute `sha256(blob)` from the
  candidate key and query on the hash. This is a feature, not a
  bug, but it is a workflow change for operators used to
  grep-based key-hunting. Documented in `docs/modules/ssh.md`.
- **Backends cannot fuzz-match keys.** Approximate matching against
  partial blobs is not possible. Exact-hash matching only. We
  accept this; the use case is rare and partial matching of public
  keys is itself a security-questionable workflow.
- **Reversal of this decision is a BREAKING SCHEMA CHANGE.** Adding
  a `key_blob` field later would expand the surface every operator
  has to reason about. If a future release wants to expose blobs
  it MUST be opt-in via an explicit CLI flag (e.g.
  `--ssh-emit-blob`) and the flag MUST default to off. The flag
  must NEVER be implied by `--include-hostname` or any other
  privacy-relaxation flag; the two decisions are independent.

## Alternatives rejected

- **Emit the raw blob in `exec_target`.** Maximum analytical
  convenience for operators, maximum exfiltration risk for the
  fleet. Rejected: the convenience does not outweigh the risk and
  the LFA queries do not require it.
- **Emit only the first/last N characters of the blob.** Provides
  no analytical value (partial blobs do not equality-join) AND
  leaks identifying material. Worst of both worlds. Rejected.
- **Emit the blob behind a flag (opt-in, off by default).**
  Tempting but the existence of the flag itself becomes a target:
  any process that runs `linpersist --ssh-emit-blob` ships
  full-fat key material to disk. Better to make blob emission
  impossible at the v0.1.0 surface and revisit only when there is
  a concrete operator workflow that needs it.

## References

- MITRE ATT&CK T1098.004 (Account Manipulation: SSH Authorized
  Keys): https://attack.mitre.org/techniques/T1098/004/
- `man 5 sshd_config` (AuthorizedKeysFile, AuthorizedKeysCommand).
- `man 8 sshd` (authorized_keys file format).
- ADR-0002 (record granularity) — per-line policy this ADR builds on.
