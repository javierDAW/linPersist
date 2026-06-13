# Report scaling benchmarks

`linpersist-report` (fleet mode) loads the entire fleet's NDJSON into one
in-RAM `[]core.Record` and runs the twelve queries over it. The query
*outputs* aggregate, but the working set does not stream — so resident
memory grows with total record count and some queries (LFA stacking,
cross-host joins) are super-linear in wall time. This is the measured
ceiling and the Go-vs-DuckDB crossover.

## Method

Synthetic fleets were fanned out from one real booted-host capture
(`lab-nspawn/out/round-1/lab-r1-h01.ndjson`, 1,117 records/host) by
replicating it N times with rewritten `host_id` / `hostname_hash`. The
report was run with `/usr/bin/time -v` (text format) on a WSL2 dev box.
The per-host record count (1,117) is representative of a real server;
lighter hosts shift the absolute numbers down but not the shape.

## Results

| Hosts | Records | Wall clock | Max RSS |
|------:|--------:|-----------:|--------:|
| 100   | 111,700 | ~10 s      | ~0.30 GB |
| 1,000 | 1,117,000 | ~3 min 50 s | ~3.2 GB |

Scaling shape (100 → 1,000, a 10× record increase):
- **Memory: ~linear** (0.30 → 3.2 GB, ≈10.8×).
- **Wall time: super-linear** (~10 s → ~230 s, ≈23×).

Extrapolation (not run — it would OOM the box): **~10,000 hosts ≈ 32 GB
RSS and tens of minutes of wall time**, beyond a typical analyst box.

## Practical ceiling & crossover

- **Go report: usable to ~1,000 hosts** (3.2 GB / ~4 min is the edge of
  comfortable on a 16 GB box). The binary prints a `WARNING` at/over
  1,000 hosts pointing at the DuckDB path.
- **DuckDB companion (`tools/ingest.sh`, `tools/stack_demo.sql`):** the
  route for tens of thousands of hosts — columnar, spills to disk, does
  not hold the fleet in RAM. Bundle the `duckdb` CLI in the engagement
  kit for fleets past ~1k hosts.

## If you need the Go report past the ceiling

There is no need to fix the super-linear queries for the supported range;
past it the columnar path is the right tool. If a future need arises, the
two levers are (a) stream/shard the load by `os_id` cohort and merge query
outputs, and (b) replace the per-query full scans with a single grouped
pass. Neither is on the roadmap while DuckDB covers the large-fleet case.
