# ADR-0005: Password hash in /etc/shadow never emitted raw

- Status: Accepted
- Date: 2026-05-13
- Related: ADR-0003 (SSH blob handling), `internal/modules/passwd`,
  `docs/schema-v1.md`, MITRE ATT&CK T1136.001.

## Context

The `passwd` module reads `/etc/shadow` to emit one record per
account with the site_class `passwd.shadow`. The shadow line format
per shadow(5) is:

```
username:$y$j9T$<hash>:lastchg:min:max:warn:inactive:expire:flag
```

The second field carries:

- A modern crypt-style hash (`$y$...`, `$6$...`, `$5$...`, `$1$...`)
  when the account has a password.
- A single `*` when the account is administratively disabled and
  has never had a password set.
- One or two `!` characters when the account is locked (the hash,
  if any, is preserved underneath the `!` prefix so it can be
  unlocked without resetting).
- An empty string when the account has NO password (any user can
  log in as that account without authentication -- a strong
  anti-pattern, but it happens on misconfigured systems).

The hash itself is a high-value target for offline brute-force
attacks. Modern crypt schemes (yescrypt, sha512crypt) are designed
to resist brute force but they are not unbreakable, especially with
GPU clusters and dictionary attacks against weak passwords. A
fleet-wide dump of every `/etc/shadow` hash converts linpersist
NDJSON into an attractive offline cracking target the moment any
downstream storage is compromised.

`linpersist`'s design tenet -- "the agent collects, the backend
decides" -- says nothing about the sensitivity of collected data.
This ADR fills that gap for the second site_class in the project
where the question becomes material (the first was SSH public-key
blobs, covered by ADR-0003).

## Decision

**The agent NEVER emits the raw password hash from /etc/shadow.**

For every record emitted with `site_class = passwd.shadow`, the
hash field is reduced to a single enum-valued field
`password_status` with values:

| Value | Source character | Meaning |
|-------|------------------|---------|
| `set` | starts with `$` | hash is present (any crypt scheme) |
| `locked` | starts with `!` or `!!` | account locked; hash may exist underneath |
| `disabled` | starts with `*` | administratively disabled, never had password |
| `empty` | empty field | NO password required for login (anti-pattern) |
| `unknown` | other | unrecognized first character; record carries an error |

The `content_norm_sha256` of a passwd.shadow record is computed
over the canonical form
`<username>:<password_status>:<lastchg>:<min>:<max>:<warn>:<inactive>:<expire>:<flag>`
-- the same shape as the source line but with the hash field
replaced by the status word. This makes two shadow entries with
the SAME password but DIFFERENT lastchg values produce different
hashes (as they should -- they encode different timestamps), while
making two entries with DIFFERENT hashes BUT same status produce
the same canonical -- because the agent has thrown the hash away.

`content_sha256` is computed over the same canonical form (not the
raw line). A backend that wants to detect "this shadow line was
modified byte-for-byte" cannot do it from our records; this is a
deliberate trade-off in favor of the privacy guarantee.

The `password_status` value also drives one signal:
`passwd_no_password` fires when `password_status == empty`. Lock
state and disabled state are observable in the field itself; no
signal needed.

## Rationale

- **Exfiltration risk reduction.** An attacker who compromises the
  NDJSON stream (in transit, in the analytical store, in an
  analyst's laptop) cannot recover the hashes to brute-force them
  offline. The status enum tells them which accounts are
  authenticated-vs-locked but not what those passwords are.
- **Compliance.** Password hashes are PII / authentication
  material in most regulatory frameworks (GDPR, HIPAA, PCI-DSS).
  Treating them as not-for-logging by default aligns the agent
  with the stricter compliance regimes without retrofit.
- **LFA invariance.** Stacking across the fleet still works: the
  fleet's "common" shadow entries (root locked, www-data disabled,
  service accounts with NOPASSWD) collapse to the same canonical
  per their status; outlier accounts surface as singletons via
  username and timestamps even without the hash.
- **Symmetry with ADR-0003.** Two sensitive-data site_classes,
  two ADRs, same policy: reduce to the analytically-useful
  fingerprint, throw away the raw material.

## Consequences

- **Cannot detect hash changes.** If an attacker compromises an
  account and replaces its hash with one they know (same scheme,
  same status), the agent emits the same `content_norm_sha256`
  before and after. Hash rotation is invisible to LFA stacking.
  The mitigation is `lastchg` -- the timestamp in the shadow line
  changes when the hash is rewritten by `passwd(1)`. An attacker
  who edits `/etc/shadow` directly without updating `lastchg`
  defeats this. We accept this as out-of-scope for v0.1.0; a
  future enhancement could add a secondary content_sha256 over
  the raw line under an opt-in flag, but the default must remain
  hash-free.
- **Cannot recover the hash to assist password rotation.** If the
  operator wants to "find every host where account X has hash Y",
  they cannot do it from NDJSON alone. They need to access the
  hosts (which they typically can, given they operate the fleet)
  or compute `sha256(<username>:<status>:<lastchg>...)` themselves
  and join.
- **Reversal is a BREAKING SCHEMA CHANGE.** Adding a `password_hash`
  field later would expand the surface every operator has to
  reason about. If a future release wants to expose hashes it
  MUST be opt-in via an explicit CLI flag (e.g.
  `--passwd-emit-hash`) and the flag MUST default to off. The
  flag must NEVER be implied by `--include-hostname` or other
  privacy-relaxation flags; the two decisions are independent.

## Alternatives rejected

- **Emit the raw hash field.** Maximum analytical convenience,
  maximum exfiltration risk. Rejected: the convenience does not
  outweigh the risk and the LFA queries do not require the hash.
- **Emit a hash of the hash (sha256 of crypt output).** Provides
  no analytical value (two hosts with the same password hash to
  the same shadow output anyway, so the layered sha256 just adds
  one indirection). Rejected.
- **Emit first 8 bytes of the hash.** Leaks identifying material
  (recognizable crypt scheme prefix) AND breaks LFA. Worst of
  both worlds. Rejected.
- **Emit hash behind an opt-in flag.** Tempting but creates a
  configuration that ships full credentials to disk. Better to
  make hash emission impossible at the v0.1.0 surface and
  revisit only when a concrete operator workflow needs it.

## References

- shadow(5) man page (hash field format).
- crypt(5) man page (crypt scheme identifiers).
- MITRE ATT&CK T1136.001 (Local Account creation):
  https://attack.mitre.org/techniques/T1136/001/
- ADR-0003 (SSH blob handling) -- parallel decision for SSH keys.
