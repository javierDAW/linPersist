# ADR-0004: sshd.config Match block scoping in canonical form

- Status: Accepted
- Date: 2026-05-13
- Related: ADR-0002 (record granularity), `internal/modules/sshd`,
  `docs/schema-v1.md`, MITRE ATT&CK T1098.004 + T1556.

## Context

OpenSSH's `sshd_config` file uses `Match` blocks to scope a subset
of directives to a specific set of connections (by user, group,
host, address, or local port):

```
PermitRootLogin no
PasswordAuthentication no

Match User alice
    AuthorizedKeysFile /custom/path/alice
    PermitRootLogin yes
```

The `PermitRootLogin yes` inside `Match User alice` applies ONLY
when alice connects; `PermitRootLogin no` at top level applies to
everyone else. Semantically they are different settings even though
the byte content of the directive line is identical.

ADR-0002 established per-line record granularity as the project
default. Naive application to `sshd_config` would hash every
directive line independently of its surrounding Match context.
That breaks LFA stacking in the wrong direction: two
`PermitRootLogin yes` lines that live in different Match blocks
would collapse to the same `content_norm_sha256` even though they
configure two different scopes of access.

The same problem appears on `sshd_config.d/*.conf` drop-in files
which may or may not start their own Match blocks.

## Decision

**The canonical form of a directive emitted from inside a Match
block prepends the canonicalized Match line.**

Concretely, the `sshd` module maintains a current-Match-context
state as it scans a file top to bottom. The canonical form fed into
`content_norm_sha256` is:

| Position | Canonical form |
|----------|----------------|
| Top-level (no active Match) | `<directive-lc> <value>` |
| Inside a Match block | `<match-line-canonical> : <directive-lc> <value>` |
| The `Match` line itself | `<match-line-canonical>` |

Where `<match-line-canonical>` is the Match line with the keyword
lower-cased and arguments preserved verbatim, e.g.
`match user alice`, `match group wheel,sudo address 10.0.0.0/8`.

Directive names are lower-cased in the canonical form because
sshd_config matches them case-insensitively
(`PermitRootLogin` == `permitrootlogin`). The directive value is
preserved verbatim.

The literal ` : ` (space-colon-space) separator was chosen because
colon is not legal in sshd_config directive names or Match
arguments, so the separator can never collide with content.

The `Match` line itself is also emitted as its own Record. It
carries `signals: [sshd_match_block_directive]`. Each subsequent
directive inside that Match block ALSO carries
`sshd_match_block_directive` so backend queries can filter on
"directives inside any Match" without parsing Match-context
strings.

Block boundaries:
- A new `Match` line ends the previous Match block (if any) and
  starts a new one.
- A new top-level directive (any line whose keyword is recognized
  AND has no leading whitespace AND is not `Match`) inside a Match
  block is per sshd(8) ambiguous; we accept the manpage's
  "indentation is for readability only, not semantic" interpretation
  and treat ANY directive AFTER a Match line as still in that
  Match block until the next Match line or end of file.
- End of file closes the active block.

The decision applies to `sshd_config` and `sshd_config.d/*.conf`
identically; drop-in files inherit no Match context from
`sshd_config` (each file is parsed standalone).

## Rationale

- **Stacking correctness.** Two `PermitRootLogin yes` lines in
  different Match scopes are semantically different settings; they
  MUST hash differently to surface that difference under LFA. A
  fleet where 99 hosts have `PermitRootLogin yes` only under
  `Match User backup` but 1 host has it under `Match User alice`
  should produce a singleton for the alice variant.
- **No new schema fields.** Encoding context in the canonical
  form keeps the Record schema unchanged. The backend does not
  need to parse a separate `match_context` column.
- **No information loss.** The `Match` line itself is preserved as
  its own record, so the backend can reconstruct the relationship
  by grouping per locus + sort by source order if needed (file
  byte offset is not currently emitted; if a future use case
  demands it, ADR-0002 already established that per-line records
  do not carry line numbers).
- **Symmetry with ldso.** ldso emits `include` directives verbatim
  without expanding the glob; sshd emits `Match` lines verbatim as
  their own records without flattening the block. The pattern is
  the same: structural lines are records, content lines are
  records, the backend joins them.

## Consequences

- **Backends that want "flatten to effective config" must
  post-process.** The records carry enough information (locus,
  signals, canonical form) to reconstruct effective per-user config
  but linpersist does not compute it. This is consistent with the
  project tenet: the agent collects, the backend decides.
- **A Match line and its block share `sshd_match_block_directive`
  signal.** Backend queries that want "show me every directive in
  any Match" use `list_contains(signals,
  'sshd_match_block_directive')`. Queries that want "show me only
  Match preambles" filter additionally on the canonical form
  starting with `match `.
- **Misordered files mislead.** If a user writes `Match User
  alice` followed by a directive intended for top-level (a sshd
  bug or a typo), the module will tag that directive as inside
  the Match block. This matches sshd's own behavior; we are not
  smarter than the reference parser on this point.
- **Reversal is a BREAKING SCHEMA CHANGE.** Removing the Match
  prefix from `content_norm_sha256` would collapse semantically
  distinct entries. Any future deviation requires a major schema
  version bump and explicit migration documentation.

## Alternatives rejected

- **Add a `match_context` field to Record.** Cleaner separation but
  bloats the schema for one module's needs. Per the project's
  fields-minimization tenet, encoding context into the canonical
  form is preferred until a second module needs the same concept.
- **Use a separate site_class for Match-block directives
  (`sshd.match`).** Fragments the same configuration concept
  across two site_class values; backend queries become more
  verbose without analytical benefit. Rejected.
- **Hash directive only; rely on locus + source order for
  context.** Loses the per-line content_norm_sha256 stacking key.
  Two `PermitRootLogin yes` on different hosts under different
  Match blocks collapse together. Defeats the LFA purpose.
  Rejected.

## References

- `man 5 sshd_config` (Match keyword semantics).
- ADR-0002 (per-line record granularity).
- MITRE ATT&CK T1098.004 (SSH Authorized Keys),
  T1556 (Modify Authentication Process).
