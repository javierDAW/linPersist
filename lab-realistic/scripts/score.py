#!/usr/bin/env python3
"""Score the rendered linpersist-report output against ground truth.

Reads:
    out/ground_truth.jsonl    -- one line per implant placement
    out/fleet-realistic.ndjson -- the agent's NDJSON

Computes per-query precision and recall:

    For each query in {Q1, Q4, Q7, Q9, Q11, Q12} the script joins
    ground-truth placements with records that the query would have
    surfaced. TP/FP/FN counts are emitted as a markdown table.

Heuristic: the script does NOT re-render Q1..Q12, but the catch-test
is signal-exact. For each expected (host, module, site_class) key it
checks whether every name in the catalog's `expected_signals` list
was actually emitted on a record at that key. An implant catches a
query when ALL its listed expected_signals are observed; missing
signals are reported as FNs with the specific gaps named.

The pre-v0.5.x heuristic was presence-based ("ANY signal fires at
the key") and routinely under-reported FNs — a record emitting only
`non_package_path` when the catalog expected
`[interpreter_in_tmp, exec_target_orphan]` was scored as TP because
SOMETHING fired. The catalog and core signal vocabularies are now
aligned (see commit 15f43a1), so exact matching is the right floor.

Usage: python3 scripts/score.py [-i ndjson_path] [-g ground_truth_path]
"""
from __future__ import annotations
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path


def load_jsonl(path):
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--ndjson", default="out/fleet-realistic.ndjson")
    ap.add_argument("-g", "--ground-truth", default="out/ground_truth.jsonl")
    args = ap.parse_args()

    gt = load_jsonl(args.ground_truth)
    records = load_jsonl(args.ndjson)

    # Build expected sets by query: (host, module, site_class) -> implant_id
    expected_by_q = defaultdict(set)   # q -> set((host, module, site_class))
    expected_meta = {}                  # (host, m, sc) -> {implant_id, expected_signals}
    for g in gt:
        key = (g["host"], g["module"], g["site_class"])
        expected_meta[key] = {
            "implant": g["implant"],
            "expected_signals": set(g.get("expected_signals", []) or []),
        }
        for q in g.get("expected_caught_by", []):
            expected_by_q[q].add(key)

    # Build the observed signals per record key.
    record_signals = defaultdict(set)
    for r in records:
        host = r.get("host_meta", {}).get("hostname") or r.get("host_id")
        key = (host, r.get("module"), r.get("site_class"))
        for s in r.get("signals", []) or []:
            record_signals[key].add(s)

    # For each query, decide whether the expected key was surfaced.
    # Signal-exact: every name in expected_signals must appear on at
    # least one record at the key. Missing signals are FNs and the
    # specific gap is named in the "misses" block after the table.
    queries = ["Q1", "Q4", "Q7", "Q9", "Q11", "Q12"]
    print("# Lab-realistic v2 scoring report\n")
    print("| query | TP | FN | recall |")
    print("|---|---:|---:|---:|")
    misses_by_q = {}
    for q in queries:
        expected = expected_by_q.get(q, set())
        if not expected:
            print(f"| {q} | -- | -- | (no implants target this query) |")
            continue
        tp = 0
        misses = []
        for key in expected:
            meta = expected_meta[key]
            seen = record_signals.get(key, set())
            gaps = meta["expected_signals"] - seen
            if not gaps:
                tp += 1
            else:
                misses.append((meta["implant"], key, sorted(gaps), sorted(seen)))
        fn = len(expected) - tp
        recall = tp / len(expected) if expected else 0.0
        print(f"| {q} | {tp} | {fn} | {recall:.2f} |")
        if misses:
            misses_by_q[q] = misses

    if misses_by_q:
        print("\n## FN details (signal-exact)\n")
        for q, misses in misses_by_q.items():
            print(f"### {q}")
            for implant, key, gaps, seen in misses:
                host, mod, sc = key
                print(f"- `{implant}` on `{host}` ({mod}/{sc})")
                print(f"  missing: {gaps}")
                print(f"  observed: {seen}")

    print("\nNotes: precision is not computed here -- it requires "
          "re-running the report queries and comparing each row against "
          "ground truth. Recall is the actionable metric for the "
          "current pass.")


if __name__ == "__main__":
    main()
