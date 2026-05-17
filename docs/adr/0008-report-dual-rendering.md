# ADR-0008: `linpersist-report` ships two output formats

- Status: Accepted
- Date: 2026-05-17
- Related: `cmd/linpersist-report/`, `docs/report.md`.

## Context

`linpersist-report` was conceived as a self-contained HTML page. The
analyst runs the binary against a directory of NDJSON, gets one HTML
file, opens it in any browser, sees the six stacking queries plus an
overview, and can share that file by email or via an internal page
share. That design — adopted in the previous iteration of this
component — assumes the analyst can run a browser.

The realistic DFIR workflow does not always give the analyst that
luxury. Common cases where there is no browser available:

- A jump host or bastion reachable only via SSH, with no X forwarding
  and no port forwarding to a developer laptop.
- An air-gapped triage workstation with policy that forbids opening
  HTML files of unknown provenance.
- A response engineer working in `tmux` over a terminal with the same
  tooling discipline as the agent itself: pure CLI, no GUI.
- Quick over-the-shoulder pair triage where two engineers want to
  read the same window via `script`/`asciinema` recording.

For these the HTML report is unreachable. Without a terminal-native
view of the same data the report is unusable in a large fraction of
real incident-response settings.

Three options were considered:

1. **HTML only.** Tell the analyst to scp the HTML to a workstation
   that has a browser. Friction we control: high. Acceptable only
   if the analyst always has that option, which they don't.
2. **Markdown only.** Drop HTML, emit Markdown that renders in the
   terminal via `glow`/`mdcat` and renders identically on GitHub /
   GitLab when committed as evidence. Loses the rich charts and
   sortable tables of the HTML; adds a soft dependency on whatever
   renders the Markdown.
3. **Dual rendering.** Keep HTML for the shareable / browser-ready
   path; add a parallel text renderer for terminals; both produced
   by the same binary from the same `Report` data structure.

## Decision

Adopt option 3. `linpersist-report` accepts a `-format` flag with
two values: `html` (default, current behavior) and `text`. The two
renderers share the upstream `load → build *Report` pipeline; only
the final serialization differs.

### Text-mode contract

- **Width target: 120 columns.** Tables are formatted with
  `text/tabwriter` to align column widths. Long values (locus paths,
  exec_target strings, content snippets) wrap with overflow rather
  than break the alignment; the analyst gets the same view whether
  they're on a 80-col terminal, a 120-col terminal, or piping to
  `less -S`.
- **Section structure mirrors the HTML.** Header → Overview →
  six Q-sections. Each Q-section starts with a clear divider so the
  analyst can grep with `awk '/^Q4/,/^Q5/'` or jump with
  `less +/Q4`.
- **Empty queries are explicit.** "no rows" appears under every
  Q-heading that produced no rows, not silence. Silence reads as
  "the renderer broke".
- **Counts on every heading.** `Q4 · Implant fingerprint (5)`
  rather than `Q4 · Implant fingerprint` so the eye lands on
  cardinality without reading.

### ANSI color policy

ANSI escape sequences ship only when `os.Stdout.Stat().Mode() &
os.ModeCharDevice != 0` — i.e., stdout is a TTY. Piping to a file
or to `less` (without `-R`) produces clean text. A user piping to
`less -R` opts into colored output.

Three color uses, conservative:

| Element              | Color  | Why |
|----------------------|--------|-----|
| Section headers      | bold   | Skim aid; works in any terminal that respects SGR. |
| `Q4 implant hits` count when > 0 | red    | Singular high-signal callout; the only "alert" colour the report ever emits. |
| LFA-tail histogram bar (singletons bucket) | orange (38;5;208) | Mirrors the same highlight in HTML. |

Signal pills, table cells, and prose are deliberately uncoloured.
The text renderer is a faithful transcription of the data, not a
visual editorial.

### What text mode does NOT try to do

- It is not interactive: no tab navigation, no live filtering, no
  click-to-expand. The analyst pipes to `grep` / `awk` / `less`
  to drill in.
- It is not a TUI: no ncurses, no key bindings, no full-screen
  redraws. The decision matrix in option 3 of the earlier dashboard
  proposal already ruled TUI out.
- It is not a Markdown emitter. The text format is meant to be read
  in a terminal; rendering it on GitHub/GitLab as Markdown was a
  considered alternative (option 2) but rejected because it loses
  the alignment that `tabwriter` provides and because most readers
  in the DFIR audience already work with terminal output.

A Markdown emitter (`-format markdown`) is allowed as a future
extension when a concrete consumer (evidence repository, ticketing
system) shows up that demands it. v0.1.x does not include it.

## Consequences

- The CLI gains one flag (`-format`). The default stays `html` so
  existing scripted invocations don't change behavior.
- `cmd/linpersist-report/` gains `render_text.go` (~250 LOC) next
  to the existing `render.go`.
- The `Report` data structure does not need to change. Both renderers
  consume the same shape.
- Documentation grows: `docs/report.md` now covers both formats with
  a "when to use which" matrix.
- The static-build contract is preserved. `text/tabwriter` is
  stdlib; the TTY-detection helper is a one-liner against
  `os.ModeCharDevice`; no new dependencies, no CGO.
- Long-term, the text renderer is the lower-maintenance one: it
  serialises through `tabwriter` without any HTML/CSS/JS surface
  to drift. If HTML rendering breaks (browser quirk, CSS regression
  on a particular release of Chromium) the text renderer is the
  fallback.

## Alternatives rejected

- **HTML only, document `scp ... && xdg-open`.** Increases the
  friction every time and breaks for the jump-host workflow.
  Doesn't survive contact with the actual analyst.
- **Markdown only.** Markdown is great for documents you commit to
  a repo and read on a web UI later. It loses the column alignment
  of `tabwriter` and depends on a Markdown renderer being available
  in the analyst's environment, which it often isn't.
- **TUI (`bubbletea`/`tview`) instead of HTML or text.** Already
  rejected in the dashboard proposal — narrower audience, no
  shareable artefact, heavier dependency. Worth revisiting when
  there's a clear request from a power user.
- **Server-side rendering with a separate `linpersist-serve`.**
  Same shareability problem as HTML, plus exposes a port. Out of
  scope for a tool whose ethos is "single static binary, no
  daemons".

## References

- `cmd/linpersist-report/` — the report binary.
- `docs/report.md` — analyst-facing reference for both output formats.
- `text/tabwriter` — Go stdlib package used for column alignment.
- ECMA-48 (ANSI X3.64) — the colour escapes used by the text
  renderer.
