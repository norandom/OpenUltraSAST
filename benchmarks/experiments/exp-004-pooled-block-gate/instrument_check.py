"""Instrument check for exp-004: are the scores real, and how clean is the pooled top of the ranking?

Reads the run's arm_outcome rows from the memory store (OUSAST_MEMORY) and the frozen units file; makes no model call.
usage: python benchmarks/experiments/exp-004-pooled-block-gate/instrument_check.py   (from the repository root)
"""

from __future__ import annotations

import collections
import json
from pathlib import Path

from openultrasast.config import load_dotenv
from openultrasast.learn import experiments as ex
from openultrasast.plane.memory import open_store

EXPERIMENT = "exp-004-pooled-block-gate"
UNITS = Path(f"plane/experiments/{EXPERIMENT}.units.jsonl")


def main() -> None:
    load_dotenv(Path(".env"))
    rows = [r.row for r in open_store(None).rows(repo=ex.experiment_repo(EXPERIMENT), kind="arm_outcome")]
    with UNITS.open() as handle:
        units = {u["unit"]: u for u in (json.loads(line) for line in handle)}
    print("arm_outcome rows", len(rows), "units file", len(units))
    by_family: dict[str, list[tuple[float | None, int, str | None, str]]] = collections.defaultdict(list)
    for row in rows:
        unit = units.get(row.get("unit"))
        if unit:
            by_family[unit["family"]].append((row.get("s"), unit["label"], unit.get("pair"), str(row.get("verdict") or "")))
    for family, xs in sorted(by_family.items()):
        scored = [x for x in xs if x[0] is not None]
        pairs: dict[str, dict[int, float]] = collections.defaultdict(dict)
        for score, label, pair, _ in scored:
            if pair:
                pairs[pair][label] = score
        full = [p for p in pairs.values() if 0 in p and 1 in p]
        wins = sum(1 for p in full if p[1] > p[0])
        ties = sum(1 for p in full if p[1] == p[0])
        top = sorted((x for x in scored if x[2]), key=lambda x: -(x[0] or 0.0))
        first_negative = next((i for i, x in enumerate(top) if x[1] == 0), len(top))
        print(
            f"{family}: n={len(xs)} distinct_scores={len({round(x[0] or 0.0, 4) for x in scored})} "
            f"unsure={sum(1 for x in xs if x[3] == 'unsure')} pairs={len(full)} within_pair_win={wins} tie={ties} "
            f"pos_above_first_neg={first_negative}"
        )
    pooled = sorted((x for xs in by_family.values() for x in xs if x[0] is not None and x[2]), key=lambda x: -(x[0] or 0.0))
    print("pooled raw top-30 labels:", "".join(str(x[1]) for x in pooled[:30]))


if __name__ == "__main__":
    main()
