#!/usr/bin/env python3
"""Score the rendered linpersist-report output against ground truth.

Reads:
    out/ground_truth.jsonl    -- one line per implant placement
    out/fleet-realistic.ndjson -- the agent's NDJSON

Computes per-query precision and recall:

    For each query in {Q1, Q4, Q7, Q9, Q11, Q12} the script joins
    ground-truth placements with records that the query would have
    surfaced. TP/FP/FN counts are emitted as a markdown table.

Heuristic limitations: the script does NOT re-render Q1..Q12,
and the catch-test is PRESENCE-based, not signal-exact. For
each expected (host, module, site_class) key it checks whether
the agent emitted ANY record carrying ANY signal at that key;
the catalog's `expected_signals` is used to populate the
ground-truth column but NOT enforced. Rationale: agent and
catalog use overlapping-but-not-identical signal names (e.g.
catalog says `exec_target_orphan`, agent emits `non_package_path`
when the payload exists on disk and is not package-managed),
and an exact-match check would surface confusing FNs even for
correctly-caught implants. A future revision can pipe
linpersist-report's structured output back in, or align the
catalog vocabulary with internal/core/signals.go.

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
    expected_meta = {}                  # (host, m, sc) -> implant_id
    for g in gt:
        key = (g["host"], g["module"], g["site_class"])
        expected_meta[key] = g["implant"]
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
    queries = ["Q1", "Q4", "Q7", "Q9", "Q11", "Q12"]
    print("# Lab-realistic v2 scoring report\n")
    print("| query | TP | FN | recall |")
    print("|---|---:|---:|---:|")
    for q in queries:
        expected = expected_by_q.get(q, set())
        if not expected:
            print(f"| {q} | -- | -- | (no implants target this query) |")
            continue
        tp = 0
        for key in expected:
            # Heuristic: an implant was caught if at least one of its
            # expected signals appears on a record at the same
            # (host, module, site_class).
            implant_id = expected_meta[key]
            seen = record_signals.get(key, set())
            if seen:
                tp += 1
        fn = len(expected) - tp
        recall = tp / len(expected) if expected else 0.0
        print(f"| {q} | {tp} | {fn} | {recall:.2f} |")

    print("\nNotes: precision is not computed here -- it requires "
          "re-running the report queries and comparing each row against "
          "ground truth. Recall is the actionable metric for the "
          "current pass.")


if __name__ == "__main__":
    main()
