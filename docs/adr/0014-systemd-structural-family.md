# ADR-0014: systemd structural-family modules (linger, tmpfiles, sysusers)

- Status: Accepted
- Date: 2026-05-20
- Related: `internal/modules/linger/`, `internal/modules/tmpfiles/`,
  `internal/modules/sysusers/`, `matrix.yaml`, `detections.yaml`,
  ADR-0007 (systemd canonical form for unit files).

## Context

The existing `systemd` module covers `.service` / `.timer` units —
the loudest persistence vector in the systemd family. Three sibling
mechanisms also persist execution across reboots and are
under-audited in DFIR practice:

- **`systemd.linger`** (`/var/lib/systemd/linger/<user>`). Enables
  user-mode systemd units for `<user>` to keep running without an
  interactive session. Documented in PANIX, Mandiant Linux IR
  reports.
- **`systemd.tmpfiles`** (`/etc/tmpfiles.d/*.conf`,
  `/usr/lib/tmpfiles.d/*.conf`, `/run/tmpfiles.d/*.conf`). systemd-
  tmpfiles runs at boot and on demand; a directive that creates an
  executable under `/tmp` at boot effectively restores a payload
  across reboots without touching any other persistence site.
- **`systemd.sysusers`** (`/etc/sysusers.d/*.conf`,
  `/usr/lib/sysusers.d/*.conf`). Declarative user/group creation at
  boot. A uid-0 user declared via sysusers does not require a direct
  edit to `/etc/passwd` — the `passwd` module sees the result, but
  the source of truth (and the implant) lives elsewhere.

None of the three is large enough to justify its own ADR; together
they form a coherent "systemd structural" family. This ADR documents
the design choices they share.

## Decisions

### Three separate Go packages, not one

Each module owns one `site_class`, one parser, and one signal
specific to it (`systemd_linger_non_root`,
`tmpfiles_creates_under_tmp`, `sysusers_uid_zero`). They share zero
state and zero parsing code; a unified package would be larger than
the three combined and obscure which file maps to which directive
family. Aligns with the existing convention (one Go package per
module under `internal/modules/<name>/`).

### Mapping site_class -> Go package name

The Go package names (`linger`, `tmpfiles`, `sysusers`) do not carry
the `systemd.` prefix the site_class does. Rationale: the `systemd`
prefix is purely a taxonomical group inside `matrix.yaml`; the Go
import path stays terse and matches the established pattern (`cron`
emits `cron.d`, `ldso` emits `ldso.preload`, etc.). The
matrix-audit release gate verifies the correspondence at build
time.

### Canonical form per directive family

- **linger**: the file body is systemd-managed and always empty.
  `content_norm_sha256` is computed over the username (the only
  stable discriminator for LFA stacking). Two files at
  `/var/lib/systemd/linger/alice` on two different hosts collapse
  to the same hash, surfacing as Q1/Q2 baseline if both hosts have
  linger enabled for `alice`.
- **tmpfiles**: whitespace outside double-quoted segments collapses
  to a single space; type letter and target path stay verbatim. The
  rule's semantic intent (what tmpfiles.d does to which path)
  becomes the LFA grouping key.
- **sysusers**: same whitespace collapse as tmpfiles. The directive
  grammar `type name id "gecos" home shell` is preserved verbatim;
  uid declarations stay byte-stable across hosts.

The three parsers share the same `parseFields` shape (whitespace-
separated tokens respecting `"..."` quoting) but live in their own
packages to avoid coupling. If a fourth structural module appears,
a shared helper in `internal/core/` is reasonable; with three the
duplication is cheaper than the abstraction.

### Per-module signal, no shared "systemd structural" tag

Each module emits exactly one module-specific signal that fires
only when the implant pattern is present:

| Module    | Signal                          | Trigger                                              |
|-----------|---------------------------------|------------------------------------------------------|
| linger    | `systemd_linger_non_root`       | username != "root" (root linger is baseline)         |
| tmpfiles  | `tmpfiles_creates_under_tmp`    | create-class type letter targeting a tmp-class path  |
| sysusers  | `sysusers_uid_zero`             | type=u, id=0, name != "root"                         |

The corresponding detection rules in `detections.yaml`
(`systemd_linger_non_root_account`,
`tmpfiles_creates_payload_at_boot`,
`sysusers_second_uid_zero`) consume only the module-specific signal
— the core enrichment (recent_mtime, world_writable, etc.) is still
emitted but not required by the rules. Reason: any non-baseline
match in these three site_classes is high-signal on its own; the
core enrichments are bonus context rather than a precision filter.

### MITRE mapping

- linger → T1546 (Event Triggered Execution, parent). No Linux-
  systemd-linger sub-technique in ATT&CK as of May 2026.
- tmpfiles → T1543.002 (Systemd Service is the closest documented
  sibling; tmpfiles is a related-but-distinct vector with no
  dedicated MITRE id).
- sysusers → T1136.001 (Local Account creation). The passwd module
  already uses this id; sysusers is the declarative-path variant.

Documenting the MITRE gap in `matrix.yaml` rather than
misclassifying under an unrelated sub-technique stays consistent
with the policy from ADR-0007 / ADR-0008.

## Consequences

- Three new modules registered in `cmd/linpersist/main.go` and
  `cmd/matrix-audit/main.go`. Build matrix unchanged (cross-
  compiles to all four target arches).
- Three new entries in `matrix.yaml`, audit passes
  (`32 implemented, 0 drift`).
- Three new signals in the catalog (`signals.go` const +
  `signals_catalog.go` SignalDef + `EmittedBy` updates for the
  shared baseline signals).
- Three new detection rules in `detections.yaml`; `stack_demo.sql`
  Q7 regenerated to 23 disjuncts. `make detgen-verify` clean.
- No new dependencies. All three modules are stdlib + the
  existing `core` package.
- Lab-realistic NDJSON unchanged in counts (the synthetic fleet
  does not exercise linger / tmpfiles / sysusers); rules pre-armed
  for real-fleet deployments.

## Alternatives rejected

- **One unified `systemd-structural` module** with three
  site_classes. Rejected: parsers share no logic, the file would
  cross 600 LOC, and the matrix-audit / catalog audits would have
  to special-case the multi-emitter shape (every other module
  emits one or two site_classes that share a parser; these would
  emit three with three independent parsers).
- **Add the directives to the existing `systemd` module**. Same
  unification problem plus a 1500-LOC module to read.
- **Defer until cloud-init / dbus.services land** to design a
  more general "systemd-adjacent declarative configs" package.
  Rejected: each of the three is needed independently in
  fleet-real triage today; abstracting prematurely would slow down
  v0.3.0-coverage.

## References

- `internal/modules/linger/linger.go` — 188 LOC, the simplest.
- `internal/modules/tmpfiles/tmpfiles.go` — 385 LOC, the parser-
  heavy one.
- `internal/modules/sysusers/sysusers.go` — 349 LOC.
- `man 5 tmpfiles.d`, `man 5 sysusers.d` — primary references for
  the directive grammars.
- PANIX (`Aegrah/PANIX`) — offensive catalog that documents
  systemd-linger as a persistence technique.
- Mandiant Linux IR reports — operational examples of all three
  vectors observed in the wild.
