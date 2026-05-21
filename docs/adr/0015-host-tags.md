# ADR-0015: host tags via `--tag key=value`

- Status: Accepted
- Date: 2026-05-21
- Related: `cmd/linpersist/main.go`,
  `internal/core/record.go` (`HostMeta.Tags` already declared),
  `internal/core/tags.go` (this ADR creates this package),
  `cmd/linpersist-report/stats.go` (Q3 peer-group consumer),
  ADR-0006 (hostname policy — same opt-in model for sensitive
  fields).

## Context

The v0.2.0 benchmark exposed a class of false positives that pure
LFA cannot disambiguate: a fleet with 30 build hosts each
shipping `/etc/sudoers.d/20-jenkins` (`%jenkins ALL=(ALL)
NOPASSWD: ALL`) generates 30 single-host Q1 singletons. They are
not malicious -- they are CI tooling -- but they look identical
to a `zz_cibot` implant.

The fix discussed across v0.2.x is to peer-group hosts on more
than `os_id`. The natural axis is operator-supplied: `role:build`,
`env:prod`, `tier:edge`. With tags, the 30 build-host singletons
collapse to one Q3 peer-group row.

`host_meta.tags` has been in the schema since v0.1.0 as an empty
slice ready for this moment. This ADR documents how the agent
populates it, the validation contract, and how Q3 consumes it.

## Decisions

### Flag surface: `--tag key=value`, repeatable

```
linpersist --tag role=build --tag env=prod --tag tier=ci
```

The flag is parsed via a custom `flag.Value` implementation that
appends to a slice on each invocation. Order of `--tag` flags is
NOT significant -- the final slice is sorted before landing in
`host_meta.tags` so the same agent invocation with the same tags
in any order produces the same NDJSON. Determinism matters for
LFA (`content_norm_sha256` is unaffected, but downstream
joins on `host_meta.tags` benefit).

### Format: K8s-style strict validation

A tag is two strings separated by exactly one `=`. The grammar
mirrors Kubernetes label keys / values, slimmed:

```
key   = [a-z] ( [a-z0-9_-]* )?   ; len in [1, 63]
value = ε  |  [a-z0-9] ( [a-z0-9_.-]* [a-z0-9] )?   ; len in [0, 63]
```

The flag rejects malformed tags at parse time with a non-zero
exit. A space in the value (`role=build server`) is the kind of
typo that silently corrupts LFA grouping if accepted; the
strict-fail-fast approach surfaces the typo immediately.

Empty values are permitted (`--tag has_cuda=`) so an operator
can encode boolean "tag present" semantics without ceremony.

Justification for strict over permissive: ergonomy of typo
detection beats flexibility for the operator who knows what
they are doing. An escape hatch can be added later if a real use
case surfaces; the reverse migration (permissive -> strict
without breaking deployments) is impossible.

### Multi-value: same key may appear multiple times

```
linpersist --tag role=build --tag role=ci
```

Produces `host_meta.tags = ["role=build", "role=ci"]` (sorted
alphabetically). This mirrors Kubernetes label semantics for
multi-arity values and supports hosts that legitimately serve
two roles or are mid-migration between environments.

Duplicate `key=value` pairs (the same literal string twice) are
deduplicated -- they would be a no-op anyway and producing a
slice with `["role=build", "role=build"]` is just noise.

The implication for Q3 (see below) is that the peer-group key
is the sorted, deduplicated set of tags as a single canonical
string -- not the multiset.

### Reserved keys: rejected at parse

The following keys are reserved because they already exist as
top-level fields in `HostMeta` and accepting them as tags would
create confusion downstream:

```
hostname, hostname_hash, os_id, os_version, kernel, arch,
boot_id, host_id
```

Tags using these keys are rejected with a clear error message
pointing at the canonical field.

### Q3 peer-group: exact match of the canonical tag set

Peer-group identity is `(os_id, canonical_tag_set)` where
`canonical_tag_set` is the sorted, comma-joined sequence of all
tags (e.g. `env=prod,role=build`). Hosts with byte-identical
canonical tag sets form one peer-group; hosts with any
difference (extra tag, missing tag, different value for any
key) form a separate peer-group.

Hosts with zero tags form the "untagged" peer-group within their
`os_id` family. This preserves the v0.2.0 Q3 behavior as a
fallback when no operator has tagged the fleet yet.

Exact-match chosen over subset-match because subset-match
creates overlapping peer-groups (host A in peer-group `{env=prod}`
AND in peer-group `{env=prod, role=build}`) which makes
"singleton in peer-group of N" ambiguous. Operators who want a
looser grouping can re-tag instead of asking the analyzer to be
clever.

Trade-off: a host with an unusual tag set ("role=build,
env=staging" while every other build host is "role=build,
env=prod") forms its own peer-group of one. That is the correct
behavior -- it IS unusual -- but means the floor `peer_hosts > 2`
in v0.2.0 may need re-tuning per fleet. We keep the floor for now
and document it.

### --diff host disappearance: host-level row, suppress individuals

When a host present in `prev.ndjson` is absent in `curr.ndjson`
(decommissioned, offline, container churn), `linpersist-report
--diff` emits a single host-level annotation `host X disappeared
(N records lost)` rather than enumerating every dropped record
as a `−` line. The inverse (host new) emits `host X appeared (N
records gained)`.

Records of hosts present in both `prev` and `curr` get the
per-record `+`/`−`/`Δ` treatment.

Rationale: a fleet with container churn would saturate the diff
with hundreds of `−` lines per restart. The host-level summary
is the actionable abstraction; the analyst who needs the detail
runs the dossier on the missing host from `prev`.

## Schema versioning

`schema_v` stays at `1`. `host_meta.tags` is an additive use of
an already-declared field; no breaking change. The wire format
is unchanged.

## Validation surface

A tag string `s` is valid iff:

1. It contains exactly one `=`.
2. The substring before `=` matches the key grammar.
3. The substring after `=` matches the value grammar (or is empty).
4. The key is not in the reserved set.

The validation lives in `internal/core/tags.go::ParseTag` and is
exported so other consumers (matrix-audit one day, the report's
own tag filters another day) can reuse it.

## Consequences

- Operators get a triage axis that turns 30-host CI sudoers
  singletons into one Q3 row, finally putting `zz_cibot`-style
  implants in the foreground without role-tag-based filtering on
  the backend side.
- `tools/stack_demo.sql` Q3 query is hand-edited to match the Go
  implementation. We do NOT add a Q3-equivalent release gate
  yet (the SQL is short and reviewed visually); revisit if Q3
  diverges more in v0.3.x.
- Documentation: `docs/stacking-cookbook.md` Q3 section gains a
  "peer-group axes" subsection. Existing v0.2.0 prose stays.
- The `--include-hostname` flag (ADR-0006) and the new `--tag`
  flag are independent. Hosts with `--include-hostname` set still
  use the same tag-based peer-group logic in Q3.

## Out of scope

- **Tag inheritance from the environment** (read `LINPERSIST_TAGS`
  env var, parse `/etc/linpersist/tags.yaml`). The `--tag` flag
  is the single source of truth for v0.3.1; environment-based
  configuration is a v0.3.x candidate.
- **Tag-aware detections** (`detections.yaml` rules that fire only
  for hosts with a specific tag). Possible but not asked for. The
  current rule format does not reference `host_meta` at all.
- **Tag-based subset queries in the report** (`linpersist-report
  --tag-filter role=build`). Useful but a v0.3.x candidate.
