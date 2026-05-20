# ADR-0012: `linpersist-report --host <id>` as a separate single-host mode

- Status: Accepted
- Date: 2026-05-20
- Related: `cmd/linpersist-report/host_stats.go`,
  `cmd/linpersist-report/render_host.go`,
  `cmd/linpersist-report/render_host_text.go`,
  `cmd/linpersist-report/host_dossier.tmpl`,
  ADR-0008 (dual rendering policy for the fleet report).

## Context

The fleet report (`Q1..Q11`) answers "what is going on across the
fleet". Operators consistently ask a different question once they
have a candidate host from one of those queries:

> Q4 says `r-db-amzn-03` has an implant in
> `/etc/systemd/system/rsync-cache.service`. Tell me everything about
> that host.

Filtering the fleet report by hostname does not answer that question:
- `Q3` peer-group, `Q5` fleet signal histogram, `Q6` worm pattern and
  `Q10` host-coverage table are aggregates over the fleet. Restricted
  to one host they become either trivial (one row) or meaningless.
- The fleet view does not show modules a host is *missing*. A host
  that emitted zero `cron` records when 70 of 75 peers did is a
  silent-collection-failure signal; the fleet view has no place for
  it.
- The signal-rarity context the analyst wants — "this host fires
  `ld_preload_set` and only 2/75 peers do" — needs the fleet
  population as a baseline. It can't be reconstructed from a filtered
  fleet view.

Three shapes were considered:

1. **Tab per host in the fleet report.** Rejected immediately on
   scaling grounds: a 1 000-host fleet would produce 1 000 tabs and
   blow up the HTML to tens of megabytes. The fleet report is
   designed to stay compact regardless of fleet size; embedding
   per-host detail breaks that contract.
2. **Inline drill-down (`<details>` per host) in the fleet report.**
   Same scaling problem with a smaller constant. Also obscures the
   fleet-wide stacking views that are the actual purpose of that
   binary.
3. **Separate single-host dossier mode.** The analyst invokes
   `linpersist-report --host <id>` for the host they're investigating,
   gets one artefact (HTML or text), and moves on. For multiple
   hosts, shell loop.

## Decision

Adopt option 3. `linpersist-report` gains a `--host` flag. When set,
the binary skips the fleet `build()` and runs `buildDossier()`
instead. Output goes through `renderHost()` (HTML) or
`renderHostText()` (text). The same `--format` / `--color` / `-o`
flags apply identically across the two modes.

### Layout of the dossier

The dossier is a single-page document (no tabs — there is only one
host to view) with these sections, in order:

1. **Host header.** `hostname`, `host_id`, `os` + version, `kernel`,
   `arch`, `boot_id`, `tags`, `collected_at`. First non-empty value
   across the host's records wins.
2. **Summary card.** Headline counts: records on this host vs fleet,
   modules covered, distinct signals fired, the dossier's per-Q
   counts (Q4, Q7, Q1, Q11, Q8) and the module-gap count.
3. **Signal panel.** Every signal this host fires, with its
   fleet-wide rarity context (`host_records`, `fleet_hosts`,
   `fleet_pct`, `description`). Sorted ascending by `fleet_hosts` so
   the rarest signal in the fleet bubbles to the top. The
   `Description` column comes from `core.SignalByName(...)` via the
   ADR-0011 catalog; an emitted signal that is not in the catalog
   surfaces as `(unknown)` rather than empty — drift detection at
   render time.
4. **Per-Q sub-tables**, filtered to this host:
   - Q4 implants (orphan + tmp).
   - Q7 implant roll-call.
   - Q1 fleet-unique records — records on this host whose
     `(module, site_class, content_norm_sha256)` appears on no other
     fleet host. Computed against the full fleet, not just the host's
     own records.
   - Q2 per-locus fleet-unique records.
   - Q9 exec targets in tmp-class directories.
   - Q11 orphan exec_target outside tmp-class (host-scoped, no LFA
     sort — singletons-first is meaningless for one host).
   - Q8 recent-mtime concentration per module (threshold matches the
     fleet Q8: >= 5 records carrying `recent_mtime_7d`).
5. **Module coverage / gap detector.** One row per module observed
   anywhere in the fleet, with `Records` (this host) vs
   `FleetMedian`. Rows where the host emitted zero but the module
   has fleet median > 0 are flagged as `IsGap` and bubble to the top.

### Q3 / Q5 / Q6 / Q10 are intentionally absent

These are fleet aggregates with no per-host insight:
- Q3 peer-group LFA: needs > 2 peers in the OS bucket.
- Q5 signal-distribution table: already represented in the dossier
  signal panel.
- Q6 worm pattern: cross-host by definition.
- Q10 host-coverage table: would be one row.

Including them would dilute the dossier without informing the
analyst.

### `--host` semantics

- Accepts exactly one value. Multiple `--host a --host b` would
  reintroduce the "N tabs / sections" anti-pattern. For multiple
  hosts use a shell loop:
  ```sh
  for h in $(cat suspects.txt); do
    linpersist-report -i fleet/ --host "$h" -o "$h.html"
  done
  ```
- Matches against `host_meta.hostname` OR `host_id` — same precedence
  as the existing `hostKey()` helper. The analyst can use whichever
  identifier the fleet report or NDJSON gave them.
- Empty match: exit 1, print the dataset's available hosts (top 20
  alphabetical + "... and N more"), so a typo produces a friendly
  recovery path.

### Renderers share assets, not template

The HTML dossier embeds `assets/style.css` directly. Both renderers
(fleet `render.go` and dossier `render_host.go`) reference the same
`cssBlob`, so a single CSS edit propagates to both views — visual
idiom stays consistent without duplication.

The dossier intentionally does NOT load `assets/ui.js`:
- No tabs to navigate (single view).
- Tables are small enough that Ctrl-F replaces the fleet report's
  sort/filter.
- Keeping the dossier free of JavaScript means it renders in any
  text-mode browser, in an email preview pane, or in a sandboxed
  ticketing system viewer.

The text renderer reuses `ansi`, `textSection`, `maybeRed`,
`commaInt`, `barWidth`, `snippetTrim` from `render_text.go`. The
ANSI policy in ADR-0008 (gate on TTY, three colours: bold headings,
red on positive Q4 counts, orange for tail-class indicators) carries
over unchanged to the dossier.

### Scalability contract

The fleet report is O(queries × records_visibly_per_query). Q1, Q2,
Q4, Q7, Q11 are LFA-filtered to anomalous rows; the HTML stays in
the ~200 KB range regardless of whether the input is 25 or 25 000
hosts.

The dossier is O(records_on_this_host). A real-world host in the
lab-realistic 75-host fleet (`r-db-amzn-03`, 703 records) produces a
21 KB HTML. Generating 100 dossiers is 100 files of ~20 KB each —
2 MB total, but the fleet report stays compact at ~200 KB. The two
modes scale on orthogonal axes.

## Consequences

- New files:
  - `cmd/linpersist-report/host_stats.go` (~590 LOC): `HostDossier`
    struct, `buildDossier`, per-section compute helpers
    (`computeHostSignalPanel`, `computeHostSingletons`,
    `computeHostLocusSingletons`, `computeHostOrphanOutsideTmp`,
    `computeHostMtimeSpikes`, `computeHostModuleCoverage`).
  - `cmd/linpersist-report/render_host.go` (~55 LOC): HTML renderer
    + `pctInt` template helper.
  - `cmd/linpersist-report/render_host_text.go` (~300 LOC): text
    renderer.
  - `cmd/linpersist-report/host_dossier.tmpl` (~220 LOC): template.
- Modified files:
  - `cmd/linpersist-report/main.go`: new `--host` flag, forked
    dispatch through dossier vs report builders,
    `printHostCandidates` helper for the "did you mean?" path. Same
    `--format` / `--color` / `-o` semantics.
  - Package doc updated with the new mode's usage examples.
- No new dependencies. Both renderers use stdlib only.
- Fleet report path is unchanged: `linpersist-report -i fleet/` with
  no `--host` still produces the same output as before.
- `lab-realistic` 75-host dataset round-tripped through both modes:
  fleet output is byte-identical to v0.2.0-polish (Q1=22, Q4=6, Q7=22,
  Q8=42, Q11=6); dossiers for the three Q4 hosts surface their
  implant + orphan-outside-tmp + module gaps correctly.

## Alternatives rejected

- **Embed dossiers in the fleet report via per-host `<details>`
  blocks.** Same N-host scaling problem with smaller constant. Also
  buries the LFA stacking views the fleet report exists to show.
- **`--host a --host b` multi-host invocation producing one HTML
  with one section per host.** Reintroduces the tab-per-host
  anti-pattern by another name; encourages the analyst to drag
  inputs to the tool instead of letting the shell compose
  invocations.
- **Auto-generate per-host links in the fleet report HTML.** Requires
  a predictable naming convention for the per-host HTMLs and a
  layout decision the operator may not want to commit to. Punted to
  a follow-up issue when (and if) a concrete demand surfaces.
- **TUI / browser-app for live navigation.** Same reasoning as
  ADR-0008: narrower audience, no shareable artefact, heavier
  dependency. The dossier's "single-file, openable anywhere" stance
  matches the rest of the binary's ethos.

## References

- `cmd/linpersist-report/host_stats.go` — buildDossier and compute
  helpers.
- `cmd/linpersist-report/render_host.go` — HTML renderer.
- `cmd/linpersist-report/render_host_text.go` — text renderer.
- `cmd/linpersist-report/host_dossier.tmpl` — template.
- ADR-0008 — dual-rendering policy for the fleet report.
- ADR-0011 — signals catalog (consumed by the dossier's signal panel
  for `Description` and unknown-signal detection).
