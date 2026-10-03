"""Offline audit of completed Joern results; never launches an analyzer or reads corpora.

Missing results stay in coverage, not signal denominators. Observed non-path rows
score zero for path features. Sink kinds are one-hot indicators, never ordinal
category IDs. Both signed and best-direction metrics expose reversed shortcuts.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from slice_leak_audit import THRESHOLD, complete_pairs, metrics

ROOT = Path(__file__).resolve().parents[2]
UNITS = ROOT / "plane/experiments/exp-005-graph-slice.units.jsonl"
RESULTS = Path.home() / "ousast-results/plane/engine-trace"
OUTPUT = ROOT / "benchmarks/measurements/2026-10-04-joern-slice-leak-audit/record.json"
STATUSES = ("path", "asked-nothing", "failed", "timeout", "unsupported", "missing")
ASKED = {"path", "asked-nothing"}
SIGNALS = ("has_path", "shortest_path_steps", "sanitized", "guard_present", "asked")
ASYMMETRY = ("vulnerable_only", "fixed_only", "both", "neither", "not_both_asked")


def materialization_version():
    # Read the producer's literal without importing its execution dependencies.
    tree = ast.parse(Path(__file__).with_name("engine_trace.py").read_bytes())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "MATERIALIZATION_VERSION" for t in node.targets):
            return ast.literal_eval(node.value)
    raise ValueError("Producer has no materialization version")


def features(row):
    path = row["status"] == "path"
    traces = row.get("traces", []) if path else []
    candidates = [(i, t) for i, t in enumerate(traces) if t.get("steps")]
    index, trace = min(candidates, key=lambda it: len(it[1]["steps"])) if candidates else (None, {})
    witnesses = row.get("witness_rows", [])
    witness = witnesses[index] if index is not None and index < len(witnesses) else {}
    guard = trace.get("guard", {})
    sink = witness.get("sinkKind")
    if not sink:
        # Retain only the call target: arguments, literals and code are not kinds.
        match = re.search(r"([\w:$>.\\-]+)\s*\(", str(witness.get("sink", "")))
        sink = match[1] if match else "unknown"
    return {
        "has_path": int(path),
        "shortest_path_steps": len(trace["steps"]) if trace else None if path else 0,
        "sanitized": int(bool(trace.get("sanitized", witness.get("sanitized", False)))) if trace else None if path else 0,
        "guard_present": int(
            bool(guard.get("text") or guard.get("bounded") or witness.get("bound") or witness.get("bounded"))
            or any("guard" in s.get("roles", []) for s in trace.get("steps", []))
        )
        if trace
        else None
        if path
        else 0,
        "sink_kind": str(sink) if path else "no-path",
        "asked": int(row["status"] in ASKED),
    }


def scored(rows, signal):
    eligible = [r for r in rows if r[signal] is not None]
    result = metrics(eligible, signal)
    result["excluded_rows"] = len(rows) - len(eligible)
    result["flagged"] = (result["pairs"] >= 10 and (result["best_direction_within_pair_accuracy"] or 0) >= THRESHOLD) or (
        result["rows"] >= 10 and (result["best_direction_pooled_auc"] or 0) >= THRESHOLD
    )
    return result


def signal_metrics(rows, kinds):
    return {
        **{s: scored(rows, s) for s in SIGNALS},
        "sink_kind": {kind: scored([{**r, "is_kind": int(r["sink_kind"] == kind)} for r in rows], "is_kind") for kind in kinds},
    }


def scope_report(rows, kinds):
    pairs = complete_pairs(rows)
    asymmetry = Counter()
    honest = []
    for v, f in pairs:
        if not (v["asked"] and f["asked"]):
            asymmetry["not_both_asked"] += 1
        else:
            honest.extend((v, f))
            asymmetry[
                "both"
                if v["has_path"] and f["has_path"]
                else "vulnerable_only"
                if v["has_path"]
                else "fixed_only"
                if f["has_path"]
                else "neither"
            ] += 1
    observed = [r for r in rows if r["status"] != "missing"]
    return {
        "rows": len(rows),
        "coverage": {s: sum(r["status"] == s for r in rows) for s in STATUSES},
        "complete_pairs": len(pairs),
        "pair_asymmetry": {s: asymmetry[s] for s in ASYMMETRY},
        "both_asked_pairs": len(honest) // 2,
        "signals": signal_metrics(observed, kinds),
        "both_asked_signals": signal_metrics(honest, kinds),
    }


def audit(units, results, *, expected_rows=501, expected_pairs=195):
    if len(units) != expected_rows or len({u["unit"] for u in units}) != expected_rows:
        raise ValueError(f"Expected {expected_rows} unique units")
    if len(complete_pairs(units)) != expected_pairs:
        raise ValueError(f"Expected {expected_pairs} complete pairs")
    if not results.is_dir():
        raise ValueError(f"Results directory is unreadable: {results}")
    version = materialization_version()
    unit_index = {u["unit"]: u for u in units}
    matched = {}
    files = []
    counts = Counter()
    for path in sorted(results.glob("*.json")):
        raw = path.read_bytes()
        record = json.loads(raw)  # Corruption fails loudly; producer uses atomic replace.
        if not isinstance(record, dict) or "repo" not in record or "pin" not in record:
            continue
        stale = record.get("materialization_version") != version
        unfinished = record.get("done") is not True
        counts["stale"] += stale
        counts["unfinished"] += unfinished
        counts["skipped"] += stale or unfinished
        files.append(
            {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "stale": stale, "unfinished": unfinished}
        )
        if stale or unfinished:
            continue
        counts["accepted_files"] += 1
        counts["result_rows_read"] += len(record["units"])
        for row in record["units"]:
            if row["unit"] not in unit_index:
                continue
            unit = unit_index[row["unit"]]
            if any(row.get(k) != unit.get(k) for k in ("family", "label", "pair")):
                raise ValueError(f"Result metadata mismatch: {row['unit']}")
            if row["status"] not in STATUSES[:-1] or not row.get("source"):
                raise ValueError(f"Invalid result status/source: {row['unit']}")
            if row["unit"] in matched:
                raise ValueError(f"Duplicate current result: {row['unit']}")
            matched[row["unit"]] = {
                **unit,
                "source": row["source"],
                "status": row["status"],
                "repo": record["repo"],
                "pin": record["pin"],
                "pin_role": row.get("pin_role"),
                **features(row),
            }
    rows = [
        matched.get(u["unit"], {**u, "source": u.get("source", "unknown"), "status": "missing", **features({"status": "missing"})})
        for u in units
    ]
    kinds = sorted({r["sink_kind"] for r in rows if r["status"] != "missing"})
    scopes = {"overall": scope_report(rows, kinds)}
    for field in ("family", "source"):
        scopes[f"by_{field}"] = {
            value: scope_report([r for r in rows if r[field] == value], kinds) for value in sorted({r[field] for r in rows})
        }
    return {
        "cost_usd": 0,
        "materialization_version": version,
        "threshold": THRESHOLD,
        "minimum_samples": 10,
        "unit_rows_read": len(units),
        "matched_rows": len(matched),
        "inputs": {
            **{k: counts[k] for k in ("accepted_files", "result_rows_read", "stale", "unfinished", "skipped")},
            "files_read": len(files),
            "bytes_read": sum(f["bytes"] for f in files),
            "files": files,
        },
        "semantics": {
            "signals": "Shortest nonempty trace (first on ties); its sanitizer, guard and corresponding witness sink call target.",
            "missing": "Coverage only; absent source metadata is unknown. Skipped result units are never consumed.",
            "non_path": "Observed non-path rows score zero; path rows lacking trace evidence have null trace features.",
            "asked": "path or asked-nothing=1; failed, timeout, unsupported=0; missing excluded from metrics.",
            "asymmetry": "Disjoint categories; not_both_asked takes precedence over path asymmetry.",
            "flags": "Best of both directions, >=0.70 with >=10 pairs for pair accuracy or >=10 rows for AUC.",
            "sink_kind": "One binary indicator per observed call target, including no-path/unknown; no ordinal encoding.",
            "limits": "Exploratory associations, not proof of leakage; running input snapshot, no multiple-testing correction.",
        },
        **scopes,
        "units": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=RESULTS)
    parser.add_argument("--units", type=Path, default=UNITS)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    raw = args.units.read_bytes()
    units = [json.loads(line) for line in raw.splitlines() if line.strip()]
    report = audit(units, args.results)
    report["units_input"] = {"path": str(args.units), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    overall, inputs = report["overall"], report["inputs"]
    lines = [
        f"Joern leak audit: $0; materialization_version={report['materialization_version']}",
        f"Units read: {len(units)}; bytes={len(raw)}; file={args.units}",
        f"Result files read: {inputs['files_read']}; bytes={inputs['bytes_read']}; accepted={inputs['accepted_files']}",
        f"Skipped: {inputs['skipped']} (stale={inputs['stale']}, unfinished={inputs['unfinished']}; counts overlap)",
        f"Result rows read: {inputs['result_rows_read']}; matched={report['matched_rows']}",
        f"Coverage: {overall['coverage']}",
        f"Pairs: {overall['complete_pairs']}; both asked={overall['both_asked_pairs']}",
        f"Asymmetry: {overall['pair_asymmetry']}",
    ]
    for signal in (*SIGNALS, "sink_kind"):

        def brief(value, signal=signal):
            if signal == "sink_kind":
                return {k: brief_metric(m) for k, m in value.items()}
            return brief_metric(value)

        lines.append(f"{signal}: all={brief(overall['signals'][signal])}; both asked={brief(overall['both_asked_signals'][signal])}")
    lines.append(f"Family/source metrics and per-file read evidence: {args.output}")
    print("\n".join(lines))


def brief_metric(metric):
    return {k: metric[k] for k in ("rows", "pairs", "within_pair_accuracy", "pooled_auc", "flagged")}


if __name__ == "__main__":
    main()
