# ADR-0013: `detections.yaml` as the single source of truth for Q7 clauses

- Status: Accepted
- Date: 2026-05-20
- Related: `internal/detections/`, `cmd/detgen/`,
  `internal/detections/detections.yaml`,
  `tools/stack_demo.sql` (Q7 block), `cmd/linpersist-report/stats.go`,
  ADR-0001 (matrix-audit release gate), ADR-0011 (signals catalog).

## Context

Q7 "Implant roll-call" is the highest-signal query in the cookbook —
the one that maps records to documented offensive patterns
("orphan + tmp", "sudoers backdoor", "uid 0 non-root account", etc.).
It lives in two places, in two languages:

- `cmd/linpersist-report/stats.go` `rollCallMatches` — Go predicates
  driving the report binary's Q7 rows.
- `tools/stack_demo.sql` Q7 — a SQL `WHERE` clause for analysts who
  prefer DuckDB.

The two were maintained by hand. `[Unreleased] D1` in the
`CHANGELOG` literally documents an instance of the resulting
maintenance burden:

> "Applied to both `tools/stack_demo.sql` Q7 and
> `cmd/linpersist-report/stats.go` `rollCallMatches` so the SQL and
> Go-native paths stay in sync."

That note is the symptom. Every clause edit was a two-place change
the reviewer had to remember to check; nothing in the build pipeline
caught divergence. Three secondary problems:

- **No structural place for new detection rules.** Adding a clause
  meant editing Go control flow and a SQL `WHERE` body. Contributors
  outside the project's Go stack had no path in.
- **Q7 row output was lossy.** The report showed a curated set of
  "triage signals" (`exec_target_orphan`, `interpreter_in_tmp`,
  `sudoers_nopasswd`, ...) but did not tell the analyst *which*
  clause matched. A row with `sudoers_nopasswd,sudoers_all_commands`
  could be the sudoers backdoor pattern, but the analyst had to
  re-derive the clause from the signal set.
- **Catalog drift between the agent's signal universe and Q7's
  signal references was undetectable at build time.** ADR-0011 closed
  the catalog gap for emission; Q7 references stayed string-literal
  for both backends.

## Decision

Promote Q7's clauses to declarative data in
`internal/detections/detections.yaml`. Two consumers read the same
file:

1. `cmd/linpersist-report` — embeds the YAML at build time via
   `go:embed`, parses it once at `init()`, evaluates it against
   every record. The clause that fired is surfaced in the Q7
   output as a new `matched_detections` column.
2. `cmd/detgen` — regenerates the Q7 `WHERE` block in
   `tools/stack_demo.sql` from the same YAML. `--verify` mode is
   wired as a release gate in the `Makefile` (`make detgen-verify`),
   matching the model `cmd/matrix-audit` already uses for
   `matrix.yaml`.

### Schema (v1, with v0.2.x-tune additive extension)

```yaml
schema_version: 1

detections:
  - id: <snake_case_unique_id>
    description: <one-line free text>
    severity: info | low | medium | high | critical
    mitre: [T####, T####.###, ...]
    when:
      signals_all:          [a, b, ...]   # every signal must be present
      signals_any:          [a, b, ...]   # at least one must be present
      signals_none:         [a, b, ...]   # no signal in the list may be present (FP suppression)
      module_in:            [a, b, ...]   # record.module ∈ list
      content_contains_any: ["a", "b"]    # snippet contains at least one
```

Semantics: positive predicates in `when:` are AND-joined within a
detection; detections OR across each other in the rule set as a
whole. `signals_none` short-circuits the entire `when:`: if any
signal in that list is present on the record, the detection does
not fire regardless of the rest. A detection populated only with
`signals_none` is rejected at load time (it would behave as a
blanket-positive rule disguised as a negative). A signal listed
under both `signals_none` and one of the positive predicates is
also rejected (the rule could never fire).

`signals_none` was added in v0.2.x-tune as an additive extension to
schema v1. The wire format is unchanged (`schema_version: 1`); rule
files that don't use the field continue to parse exactly as before.
The predicate is the main FP-suppression knob — see the
v0.2.x-tune changelog entry for examples.

### Predicate set rationale

The four operators above were chosen to cover the current 7-clause
Q7 set with **zero leftover expressivity**:

| Q7 clause                          | Maps to                                                              |
|------------------------------------|----------------------------------------------------------------------|
| orphan + tmp                       | `signals_all: [exec_target_orphan, interpreter_in_tmp]`              |
| sudoers NOPASSWD + ALL             | `signals_all: [sudoers_nopasswd, sudoers_all_commands]`              |
| uid 0 non-root                     | `signals_any: [passwd_uid_zero]`                                     |
| kmod install directive             | `signals_any: [kmod_install_directive]`                              |
| profile curl/wget                  | `module_in: [profile]` + `content_contains_any: [curl, wget]`        |
| sysv /tmp/ reference               | `module_in: [sysv]` + `content_contains_any: ["/tmp/"]`              |
| motd curl/wget                     | `module_in: [motd]` + `content_contains_any: [curl, wget]`           |

Anything richer (regex, glob, signal counts, exec_target prefix
match, negation) is deliberately out of scope for v1. The principle
matches ADR-0011: small surface, explicit fields, no DSL. We'll
extend the schema field-by-field when a concrete clause needs more.

### Loader validation

`internal/detections.Load` rejects ill-formed input at parse time
rather than silently passing it through to the matcher:

- `schema_version` must equal `1`.
- Every `id` matches `^[a-z][a-z0-9_]*$` (snake_case) and is unique.
- Every `mitre` entry matches `T####(\.[0-9]{3})?`.
- `severity`, when present, is one of `info|low|medium|high|critical`.
- Every signal name in `signals_all`/`signals_any` is in
  `core.KnownSignalSet()` (the ADR-0011 catalog).
- Every `module_in` entry is a known module name (if the caller
  passes the module set; nil disables this check, useful for
  tests).
- Every `content_contains_any` entry is free of SQL-unsafe
  characters (`'`, `%`, `_`, `\`). The SQL backend would otherwise
  need per-character escaping per backend; we reject up front.
- Every `when:` block has at least one populated predicate (an
  empty `when:` is ambiguous and the loader has no way to guess
  the contributor's intent).

### Location of the YAML

`internal/detections/detections.yaml`, not the repo root. `go:embed`
forbids `..` patterns, so the YAML must live somewhere the package
can reach via a direct child path. Putting it inside the package
keeps it next to the loader and the SQL generator that consume it,
and keeps the `go:embed` pattern trivial (`//go:embed detections.yaml`).
The trade-off is loss of the "all source-of-truth lives in the repo
root" convention that `matrix.yaml` set; we accept it because
detections.yaml is fundamentally tied to Go consumers, while
matrix.yaml is read by `matrix-audit` from the filesystem and has
no embed contract.

### SQL generation

`internal/detections.RuleSet.RenderSQL` emits one disjunct per
detection. Each disjunct is annotated with the detection id as an
inline comment so an analyst reading the SQL can match an output row
back to the rule:

```sql
  /* payload_under_tmp_via_persistence */ (list_contains(signals, 'exec_target_orphan') AND list_contains(signals, 'interpreter_in_tmp'))
  OR /* sudoers_nopasswd_all_backdoor */ (list_contains(signals, 'sudoers_nopasswd') AND list_contains(signals, 'sudoers_all_commands'))
  OR /* second_uid_zero_account */ list_contains(signals, 'passwd_uid_zero')
  ...
```

The generator output is bit-deterministic given the same input:
fixed iteration order, fixed whitespace, fixed comment style. The
release gate (`make detgen-verify`) byte-compares the regenerated
output against the committed file.

### Release gate

`Makefile` `all` now runs `lint test audit detgen-verify build`.
`make detgen-verify` fails if the committed `tools/stack_demo.sql`
Q7 block does not match what `go run ./cmd/detgen` would write.
Catches the realistic failure mode: contributor edits
`detections.yaml`, forgets to run `detgen`. Same pattern as
ADR-0001 (`matrix-audit`).

### Q7 row output gains a new column

`RollCallRow` now carries `MatchedDetections []string` alongside
the existing `TriageSignals []string`. The text and HTML
renderers emit it as a new `matched_detections` column. The
analyst sees, on every row:

```
host                  module   site_class  locus               matched_detections                triage_signals
r-build-server-ubu-02 passwd   passwd.user /etc/passwd         second_uid_zero_account           passwd_uid_zero
r-db-amzn-03          systemd  systemd.unit /etc/systemd/...   payload_under_tmp_via_persistence exec_target_orphan,interpreter_in_tmp
```

`triage_signals` is preserved unchanged for back-compat with
existing operator scripts that parse Q7 text output. `matched_detections`
is additive.

## Consequences

- New files:
  - `internal/detections/detections.yaml` (~85 lines) — source
    of truth for 7 current detections, paritary with v0.2.0-polish Q7.
  - `internal/detections/loader.go` (~200 LOC) — parse + validate.
  - `internal/detections/matcher.go` (~115 LOC) — predicate engine.
  - `internal/detections/sql.go` (~115 LOC) — SQL `WHERE` generator.
  - `internal/detections/embedded.go` (~55 LOC) — `go:embed`
    wrapper + `MustLoadEmbedded`.
  - `internal/detections/detections_test.go` (~270 LOC) — golden
    tests for every clause + loader error paths (15 test cases).
  - `cmd/detgen/main.go` (~150 LOC) — SQL regenerator + `--verify`.
  - This ADR.
- Modified files:
  - `cmd/linpersist-report/stats.go` — `rollCallMatches` reduced
    from ~55 LOC of hand-written switch to a one-line
    `detectionRules.MatchAny(r)`. New `MatchedDetections []string`
    field on `RollCallRow`. Init-time load via
    `detections.MustLoadEmbedded()`.
  - `cmd/linpersist-report/render_text.go` — Q7 table grows a
    `matched_detections` column.
  - `cmd/linpersist-report/report.tmpl` — Q7 HTML table grows the
    same column, with warn-styled pills for the detection ids.
  - `tools/stack_demo.sql` — Q7 `WHERE` body lives between BEGIN /
    END GENERATED markers; comments inside the block carry the
    detection ids for SQL readers.
  - `Makefile` — new `detgen` and `detgen-verify` targets;
    `detgen-verify` added to the `all` chain.
- One known follow-up: an obsolete copy of `detections.yaml`
  remains at the repo root from an earlier attempt to put the YAML
  there. The sandbox running this work lacks `rm` permission, so
  the file should be deleted by hand with `git rm detections.yaml`
  before commit. The package's `internal/detections/detections.yaml`
  is the only file consumed by code or tests.
- No new dependencies. `gopkg.in/yaml.v3` was already in `go.sum`
  via the matrix-audit tooling; the rest is stdlib.
- Behaviour parity preserved end-to-end against
  `lab-realistic/out/fleet-realistic.ndjson` (75 hosts, 31 433
  records): Q7 still produces exactly 22 rows; Q1=22, Q4=6, Q8=42,
  Q11=6 unchanged.

## Alternatives rejected

- **Generate Go code at build time from the YAML.** The
  alternative to runtime embed: a `go generate` step that writes a
  `rollcall_generated.go` with the clauses inlined. Faster at
  runtime (no parse) but adds a build step and a generated file in
  source control that nobody reads. The runtime parse takes ~1 ms
  at init; not worth the maintenance trade-off.
- **Use an existing detection DSL (Sigma, CEL, OPA Rego, jq).**
  All overkill for the current 4-operator surface. The simplest
  thing that works (snake_case YAML, fixed fields) keeps barrier-to-
  contribute at zero. Re-evaluate when expressivity demand outgrows
  the field list.
- **Keep the SQL block hand-edited, generate only the Go path.**
  Same drift problem in the other direction. The point of this ADR
  is single source of truth; one-sided generation does not solve it.
- **Put the YAML at the repo root anyway and use `os.ReadFile` at
  runtime.** Loses `go:embed`'s single-binary contract; if the YAML
  ships separately the deployment story doubles.
- **Add `signals_none` (negation) as a v1 predicate.** Not used by
  any current clause; would have added a small amount of code and
  a non-zero amount of "is this a noisy false-negative pattern?"
  reasoning that we don't have to do today. Add when a clause
  needs it.

## References

- `internal/detections/detections.yaml` — current rule set (7 detections).
- `internal/detections/loader.go`, `matcher.go`, `sql.go`,
  `embedded.go` — engine.
- `cmd/detgen/main.go` — SQL regenerator + release gate.
- `tools/stack_demo.sql` Q7 — generated `WHERE` block (between
  BEGIN/END GENERATED markers).
- `cmd/linpersist-report/stats.go` `rollCallMatches`,
  `computeQ7` — consumers.
- ADR-0001 — `matrix-audit` (precedent for source-of-truth +
  release-gate pattern).
- ADR-0011 — signals catalog (consumed by the loader for signal
  name validation).
- `[Unreleased] D1` in `CHANGELOG.md` — the maintenance-burden
  data point that motivated this work.
