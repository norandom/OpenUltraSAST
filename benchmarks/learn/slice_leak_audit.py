"""Read-only, zero-model slice audit. Run: env -u OPENROUTER_API_KEY python benchmarks/learn/slice_leak_audit.py.

Only sources.toml itself is read, never its referenced corpora. Stored source IDs
are the reporting strata (the store merges advisory pair catalogs into `pairs`).
Ties get half credit. Both signed and best-direction scores are recorded; like
learn.leaks, a reversed label shortcut is still a leak. Missing classes/pairs
produce null metrics, not plausible zeros. Unsupported slices score zero for both
indicators and remain separately counted in coverage.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from openultrasast.config import load_dotenv
from openultrasast.learn.examples import load_examples
from openultrasast.learn.labels import load_sources
from openultrasast.learn.slice import function_slice
from openultrasast.plane.memory import MemoryStore, open_store

UNITS = Path("plane/experiments/exp-004-pooled-block-gate.units.jsonl")
OUTPUT = Path("benchmarks/measurements/2026-10-03-graph-slice-leak-audit/record.json")
THRESHOLD = 0.70


def complete_pairs(rows: Sequence[Mapping[str, Any]]) -> list[tuple[Mapping[str, Any], Mapping[str, Any]]]:
    groups: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        if row.get("pair"):
            groups[(row["family"], row["pair"])].append(row)
    pairs = []
    for members in groups.values():
        if len(members) == 2 and {m["label"] for m in members} == {0, 1}:
            v, f = sorted(members, key=lambda m: -m["label"])
            if v["group"] != f["group"] or v["fold"] != f["fold"]:
                raise ValueError("Pair crosses group or fold")
            pairs.append((v, f))
        elif len(members) != 1:
            raise ValueError("Ambiguous pair")
    return pairs


def metrics(rows: Sequence[Mapping[str, Any]], signal: str) -> dict[str, Any]:
    pairs = complete_pairs(rows)
    higher = sum(v[signal] > f[signal] for v, f in pairs)
    lower = sum(v[signal] < f[signal] for v, f in pairs)
    ties = len(pairs) - higher - lower
    pair_score = (higher + 0.5 * ties) / len(pairs) if pairs else None
    positive = [r[signal] for r in rows if r["label"] == 1]
    negative = [r[signal] for r in rows if r["label"] == 0]
    auc = (
        sum((v > f) + 0.5 * (v == f) for v in positive for f in negative) / (len(positive) * len(negative))
        if positive and negative
        else None
    )
    best_pair = max(pair_score, 1 - pair_score) if pair_score is not None else None
    best_auc = max(auc, 1 - auc) if auc is not None else None
    return {
        "rows": len(rows),
        "pairs": len(pairs),
        "positive": len(positive),
        "negative": len(negative),
        "higher_on_vulnerable": higher,
        "higher_on_fixed": lower,
        "ties": ties,
        "within_pair_accuracy": pair_score,
        "pooled_auc": auc,
        "best_direction_within_pair_accuracy": best_pair,
        "best_direction_pooled_auc": best_auc,
        "flagged": any(v is not None and v >= THRESHOLD for v in (best_pair, best_auc)),
    }


def audit(store: MemoryStore, units: Sequence[Mapping[str, Any]], *, expected_rows: int = 501, expected_pairs: int = 195) -> dict[str, Any]:
    if len(units) != expected_rows or len({u["unit"] for u in units}) != expected_rows:
        raise ValueError(f"Expected {expected_rows} unique units, read {len(units)}")
    if len(complete_pairs(units)) != expected_pairs:
        raise ValueError(f"Expected {expected_pairs} complete pairs")
    examples = load_examples(store)
    index = {e.id: e for e in examples}
    if len(index) != len(examples):
        raise ValueError("Duplicate example IDs in memory")
    sources = {s.id for s in load_sources().sources}
    coverage: dict[str, Counter[str]] = defaultdict(Counter)
    rows = []
    excerpt_bytes = 0
    blobs: dict[str, str] = {}
    for unit in units:
        e = index[unit["unit"]]  # missing input is fatal, never counted as no-flow
        if (e.family, e.label, e.group) != (unit["family"], unit["label"], unit["group"]):
            raise ValueError(f"Unit metadata differs from store: {e.id}")
        if e.source not in sources:
            raise ValueError(f"Source absent from sources.toml: {e.source}")
        if e.excerpt_sha not in blobs:
            # MemoryStore.get_blob(verify=True) DELETES corrupt blobs: do not use it.
            data = store.get_blob("excerpts", e.excerpt_sha, verify=False)
            if not data or hashlib.sha256(data).hexdigest() != e.excerpt_sha:
                raise ValueError(f"Missing, empty or corrupt excerpt: {e.id}")
            excerpt_bytes += len(data)
            blobs[e.excerpt_sha] = data.decode("utf-8")
        result = function_slice(blobs[e.excerpt_sha], e.language, e.family)
        status = "not-analysable" if result is None else "flow" if result.steps else "no-flow"
        coverage[e.family][status] += 1
        rows.append(
            {
                **unit,
                "source": e.source,
                "status": status,
                "has_flow": int(status == "flow"),
                "slice_length": len(result.steps) if result else 0,
            }
        )
    pairs = complete_pairs(rows)
    asymmetry = Counter(
        "both" if v["has_flow"] and f["has_flow"] else "vulnerable_only" if v["has_flow"] else "fixed_only" if f["has_flow"] else "neither"
        for v, f in pairs
    )
    scopes = {"all": rows, **{f"source:{s}": [r for r in rows if r["source"] == s] for s in sorted({r["source"] for r in rows})}}
    return {
        "cost_usd": 0,
        "threshold": THRESHOLD,
        "unit_rows_read": len(units),
        "example_rows_read": len(examples),
        "matched_rows": len(rows),
        "excerpts_read": len(blobs),
        "excerpt_units": len(rows),
        "excerpt_bytes": excerpt_bytes,
        "complete_pairs": len(pairs),
        "coverage": {f: {s: c[s] for s in ("flow", "no-flow", "not-analysable")} for f, c in sorted(coverage.items())},
        "pair_asymmetry": {k: asymmetry[k] for k in ("vulnerable_only", "fixed_only", "both", "neither")},
        "signals": {
            signal: {scope: metrics(members, signal) for scope, members in scopes.items()} for signal in ("has_flow", "slice_length")
        },
        "source_strata": "Stored source IDs from sources.toml; advisory pair catalogs are merged into pairs by the example builder.",
        "limitations": (
            "Flat IR: no dominance/guards, textual branch order, potential parameter inputs, conservative call returns; no alias analysis."
        ),
        "units": [
            {k: r[k] for k in ("unit", "pair", "family", "label", "fold", "source", "status", "has_flow", "slice_length")} for r in rows
        ],
    }


def main() -> None:
    load_dotenv(Path(".env"))
    os.environ.pop("OPENROUTER_API_KEY", None)  # dotenv must not restore the removed key
    raw = UNITS.read_bytes()
    units = [json.loads(line) for line in raw.decode().splitlines() if line.strip()]
    report = audit(open_store(), units)
    report["units_bytes"] = len(raw)
    report["units_sha256"] = hashlib.sha256(raw).hexdigest()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    totals = Counter({s: sum(c[s] for c in report["coverage"].values()) for s in ("flow", "no-flow", "not-analysable")})
    lines = [
        f"Slice leak audit: $0; units bytes={len(raw)}",
        f"Rows read: units={len(units)}, examples={report['example_rows_read']}, matched={report['matched_rows']}",
        f"Excerpts read: {report['excerpts_read']}; units={report['excerpt_units']}; bytes={report['excerpt_bytes']}",
        f"Coverage: {dict(totals)}",
        f"Complete pairs: {report['complete_pairs']}",
        f"Pair asymmetry: {report['pair_asymmetry']}",
        f"Has flow: {report['signals']['has_flow']['all']}",
        f"Slice length: {report['signals']['slice_length']['all']}",
        f"Source strata: {', '.join(report['signals']['has_flow'])}; threshold={THRESHOLD}",
        f"Report: {OUTPUT}",
    ]
    print("\n".join(lines))


if __name__ == "__main__":
    main()
