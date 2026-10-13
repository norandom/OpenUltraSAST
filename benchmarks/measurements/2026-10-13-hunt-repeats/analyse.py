"""Paired comparison of the baseline hunt program (DSPy) and the pilot hunter over 5 repeats on the 12 positives.

Fixed before the runs finished. Unit = (change, repeat). Arm A = pilot hunter (benchmarks/valid/hunter_arm.py,
classifier on), arm B = baseline hunt program (openultrasast.hunt.cli). A hit is `benchmarks.unseen.score.catches`.
Reported: per-change hit rate per arm, overall recall per arm with a Wilson interval over all (change, repeat)
units, the paired difference B - A with a bootstrap that resamples whole changes (each change is its own
repository here), and exact McNemar on the (change, repeat) pairs. Instrument failures and parse failures are
counted and shown, never dropped from the denominator.

    PYTHONPATH=. .venv/bin/python benchmarks/measurements/2026-10-13-hunt-repeats/analyse.py ~/ousast-results/hunt/repeats
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd

from benchmarks.unseen import score
from openultrasast import stats


def load(root: Path) -> pd.DataFrame:
    rows = []
    for arm, prefix in (("hunter", "hunter-"), ("dspy", "dspy-")):
        for run in sorted(root.glob(prefix + "*")):
            if not run.is_dir() or not (run / "inputs.json").is_file():
                continue
            repeat = int(run.name.split("-")[1])
            for record in score.load_records(run):
                if record.get("kind") != "vulnerability":
                    continue
                defects = record.get("push", {}).get("admission", {}).get("defects", [])
                rows.append(
                    {
                        "arm": arm,
                        "repeat": repeat,
                        "change": record["id"],
                        "repo": record.get("repo"),
                        "status": record.get("status", "missing"),
                        "parse_failed": bool(record.get("parse_failed")),
                        "suspicions": len(defects),
                        "hit": int(bool(record.get("done")) and bool(score.catches(record))),
                    }
                )
    return pd.DataFrame(rows)


def main(root: Path) -> dict:
    frame = load(root)
    wide = frame.pivot_table(index=["change", "repo", "repeat"], columns="arm", values="hit").dropna().reset_index()
    out: dict = {"units": len(wide), "repeats": sorted(frame["repeat"].unique().tolist())}
    for arm in ("hunter", "dspy"):
        part = frame[frame["arm"] == arm]
        hits, n = int(part["hit"].sum()), len(part)
        out[arm] = {
            "hits": hits,
            "units": n,
            "recall": hits / n if n else None,
            "wilson95": stats.wilson(hits, n),
            "instrument_failures": int((part["status"] == "instrument_failure").sum()),
            "parse_failures": int(part["parse_failed"].sum()),
            "suspicions_mean": float(part["suspicions"].mean()) if n else None,
        }
    estimate = stats.paired_bootstrap(wide, "change", "hunter", "dspy", resamples=5000, seed=0)
    out["dspy_minus_hunter"] = {"diff": estimate.diff, "ci95": estimate.ci, "changes": estimate.groups}
    mc = stats.mcnemar_exact(list(wide["hunter"].astype(bool)), list(wide["dspy"].astype(bool)))
    out["mcnemar"] = {"only_hunter": mc.b, "only_dspy": mc.c, "concordant": mc.concordant, "p": mc.p_value}
    per_change = frame.groupby(["change", "repo", "arm"])["hit"].mean().unstack("arm").reset_index()
    out["per_change"] = per_change.sort_values("repo").to_dict(orient="records")
    return out


if __name__ == "__main__":
    print(json.dumps(main(Path(sys.argv[1]).expanduser()), indent=2, default=str))
