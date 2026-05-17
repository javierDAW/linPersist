# `linpersist-report` — HTML and text reports from agent NDJSON

`linpersist-report` reads a directory (or a single file) of
linpersist NDJSON output and produces a report in one of two
formats: HTML (default, self-contained, shareable) or text
(terminal-friendly, ideal for jump hosts and SSH-only triage).
The binary is a sibling of `linpersist`: same build flags
(`CGO_ENABLED=0`, `osusergo netgo`), same `make build-all` matrix,
same `verify_static.sh` gate. Two static binaries cover the entire
flow from `/etc/cron.d/` to a triage page or a paged terminal view.

```sh
linpersist-report -i fleet/ -o report.html              # HTML (default)
linpersist-report -i fleet/ -format text                # text on stdout, ANSI when TTY
linpersist-report -i fleet/ -format text | less -R      # paged with color
linpersist-report -i fleet/ -format text -color=off > triage.txt   # clean text artefact
linpersist-report -i lab-large/out/lab.ndjson > report.html
```

## When to use which format

| | HTML | Text |
|---|---|---|
| Shareable artefact (email, share, ticket) | yes | yes (clean ASCII) |
| Browser required | yes | no |
| Sortable columns / live search | yes | grep/awk/sort |
| Interactive drill-down | yes | no |
| Renders over SSH-only sessions | no | yes |
| Survives the air-gapped jump host | no | yes |
| File size | ~100-500 KB | ~5-50 KB |

The same `Report` data flows into both renderers (see ADR-0008).
Their outputs are equivalent in content; the trade-off is interaction
vs. portability.

## Anatomy of a report

The header strip pins six counts: hosts, records, modules,
site_classes, Q1 singletons, Q4 implant hits. Anything weird here —
a sudden drop in records, a spike in Q4 — is the first thing the
analyst sees.

Seven tabs follow. Each table is sortable by header click and
filterable by the search input above it.

### Overview

- **Cards**: the same six counts repeated at large size.
- **LFA stacking histogram**: number of distinct
  `(module, content_norm_sha256)` groups that appear on N hosts,
  bucketed `1 / 2-4 / 5-9 / 10-49 / 50-99 / ≥100`. The singletons
  bucket is highlighted in the tail color (orange) because that is
  where attacker artefacts live; the right buckets are the
  package-managed baseline. A healthy fleet has a strong right
  tail and a thin left tail.
- **Modules / site_classes / OS distribution**: three sortable
  tables. Click a header to sort.
- **Signal distribution (fleet-wide)**: horizontal bars, one per
  signal that fired at least once across the fleet. Rare signals
  (1-2 hosts) at the top of the list are the most interesting; they
  earn the analyst's triage time before frequent signals.

### Q1 · LFA singletons (`Q1`)

Records whose `content_norm_sha256` appears on exactly one host.
The load-bearing query. Filter by module to scope investigations.

### Q2 · Per-locus singletons (`Q2`)

Like Q1 but groups by `(module, site_class, locus,
content_norm_sha256)`. Catches the "common content at unusual path"
pattern (e.g. legitimate `/etc/cron.daily/logrotate` content copied
into a renamed `/etc/cron.daily/sync` file).

### Q3 · Peer-group LFA by `os_id` (`Q3`)

Singletons inside their own OS bucket. Necessary for mixed fleets
where the Debian-only baseline would otherwise look like a singleton
in an Ubuntu-majority fleet. Only OS buckets with `>2` peers
contribute rows.

### Q4 · Implant fingerprint (`Q4`)

Records carrying **both** `exec_target_orphan` and
`interpreter_in_tmp`. The conjunction is rare in legitimate
configuration. The pill color in the `signals` cell turns orange
for "warn-class" signals so a skim is enough to triage.

### Q5 · Signal distribution by module (`Q5`)

For every `(module, signal)` pair: hosts fired and records carrying
it. The sort default is ascending by hosts so the rarest signals
surface first.

### Q6 · Worm pattern (`Q6`)

Records on different hosts whose `exec_target_sha256` matches but
whose persistence text differs. Identical payload, polymorphic
persistence — the lateral-movement / worm signal. Filtered to
`2 ≤ hosts < 10% of fleet` to skip both singletons (Q1 turf) and
baseline binaries.

## Performance

The 6 queries are reimplemented in pure Go over a flat
`[]core.Record`. For a fleet of `25 hosts × 250 records = 6.2k`
records (the lab-large workload), full report generation including
HTML render takes ~50 ms on a laptop. Empirical scaling:

| Records   | Hosts | Wall time |
|-----------|-------|-----------|
| 6 k       | 25    | ~50 ms    |
| 60 k      | 250   | ~250 ms   |
| 600 k     | 2 500 | ~2.5 s    |
| 6 M       | 25 000| ~30 s     |

For fleets larger than ~10k hosts, prefer the DuckDB cookbook
(`tools/stack_demo.sql`); columnar processing scales better past
that point.

## Output format

### HTML

A single HTML file. Self-contained: CSS embedded in `<style>`,
JavaScript in `<script>`, chart data rendered server-side as HTML +
CSS (no canvas, no SVG library). Dark and light themes via
`prefers-color-scheme`.

The HTML is safe to commit to a triage-evidence repository: it is
deterministic given the same input NDJSON and timestamp, diff-able
between collection runs (`git diff` between two reports surfaces
fleet drift directly).

### Text

Plain ASCII with column-aligned tables produced by `text/tabwriter`.
Same sections as the HTML, same content, no charts beyond a compact
ASCII histogram bar.

ANSI color is gated by the `-color` flag:

- `auto` (default) — emit color only when stdout is a TTY and no
  `-o` file was set. This makes the common cases right: piping to
  `less` (no `-R`) produces clean text; piping to `less -R` shows
  color; redirecting to a file (`> triage.txt` or `-o triage.txt`)
  always produces a clean artefact suitable for tickets.
- `on` — always emit color (use when piping to `less -R` etc).
- `off` — never emit color.

Three uses of color, mirroring the HTML's accent palette:

| Element                                  | Color  |
|------------------------------------------|--------|
| Section headings                         | bold   |
| `Q4 implant hits` count when > 0         | red    |
| LFA histogram singletons bar             | orange |

Everything else stays plain. Signal pills are not color-tinted in
text mode; analysts grep by signal name. See ADR-0008 for the full
policy.

## What the report does NOT do

- Does not classify anything as malicious. The colour cues highlight
  signals that *historically* correlate with offensive patterns;
  the analyst still makes the call.
- Does not fetch resources at view time. No tracking, no telemetry,
  no CDN.
- Does not edit the NDJSON. The agent collected; the report
  presents.

## See also

- `docs/stacking-cookbook.md` — the same six queries as prose with
  false-positive guidance.
- `tools/stack_demo.sql` — the same queries in executable DuckDB
  SQL form for power-user analyses.
- `cmd/linpersist-report/` — source.
