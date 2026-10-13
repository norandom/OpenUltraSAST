"""Both arms over the frozen access-control training pool (one run each): push recall, location recall, false alarms.

Unit = one push (change). A push is caught when any verified location of its fix is caught
(`benchmarks.unseen.score.catches` on the per-target view, as `benchmarks/valid/metrics.py` does). A location is
caught when its own view is caught. Instrument failures and unparsed hunts stay in the denominators as misses,
and false alarms are counted over the ordinary pushes the arm actually scanned (instrument failures excluded, and
said so). Every suspicion is also written out with a true/false label for feature work.

    PYTHONPATH=. .venv/bin/python benchmarks/measurements/2026-10-14-access-control-hunt/analyse.py ~/ousast-results/hunt/ac-train
"""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

from benchmarks.unseen import score
from openultrasast import stats
from openultrasast.model.endpoint import _PRICES as PRICES


def targets_of(record: dict) -> list[dict]:
    if record["kind"] != "vulnerability":
        return []
    return record.get("targets") or [
        {"case_id": record["case_id"], "path": record["path"], "function": record["function"], "function_lines": record["function_lines"]}
    ]


def view(record: dict, target: dict) -> dict:
    return {**record, **target, "files": [{"path": target["path"], "head_lines": [target["function_lines"]]}]}


def defects(record: dict) -> list[dict]:
    return record.get("push", {}).get("admission", {}).get("defects", [])


def arm_summary(records: list[dict], arm: str) -> tuple[dict, list[dict]]:
    usable = [r for r in records if score.coverage(r) != "instrument_failure"]
    positives = [r for r in records if r["kind"] == "vulnerability"]
    ordinary = [r for r in usable if r["kind"] == "ordinary"]
    push_hits = [int(any(score.catches(view(r, t)) for t in targets_of(r))) for r in positives]
    locations = [(r["repo"], int(bool(score.catches(view(r, t))))) for r in positives for t in targets_of(r)]
    flagged = [r for r in ordinary if score.false_alarm(r)]
    suspicions = []
    for r in records:
        for d in defects(r):
            single = {**r, "push": {"admission": {"defects": [d], "dispositions": []}, "quick_tier": []}}
            hit = any(score.catches(view(single, t)) for t in targets_of(r))
            confidence = d.get("confidence") if arm == "dspy" else (d.get("classifier") or {}).get("confidence")
            location = (d.get("locations") or [[None, None]])[0]
            suspicions.append(
                {
                    "arm": arm,
                    "repo": r["repo"],
                    "change_id": r["id"],
                    "kind": r["kind"],
                    "path": location[0],
                    "line": location[1] if len(location) > 1 else None,
                    "family": d.get("family"),
                    "confidence": confidence,
                    "label": int(hit),
                }
            )
    true_suspicions = sum(s["label"] for s in suspicions)
    summary = {
        "pushes": len(records),
        "instrument_failures": {
            "count": len(records) - len(usable),
            "types": dict(
                collections.Counter(r["instrument"].get("failure") for r in records if score.coverage(r) == "instrument_failure")
            ),
        },
        "parse_failures": sum(bool(r.get("parse_failed")) for r in records),
        "loop_parse_failures": sum(bool(r.get("loop_parse_failed")) for r in records),
        "push_recall": {"hits": sum(push_hits), "n": len(push_hits), "wilson95": stats.wilson(sum(push_hits), len(push_hits))},
        "location_recall": {
            "hits": sum(h for _, h in locations),
            "n": len(locations),
            "wilson95": stats.wilson(sum(h for _, h in locations), len(locations)),
            "per_repository": {
                repo: f"{sum(h for rp, h in locations if rp == repo)}/{sum(1 for rp, _ in locations if rp == repo)}"
                for repo in sorted({rp for rp, _ in locations})
            },
        },
        "false_alarms": {
            "flagged_ordinary_pushes": len(flagged),
            "ordinary_pushes_scanned": len(ordinary),
            "per_100_pushes": 100 * len(flagged) / len(ordinary) if ordinary else None,
            "wilson95_per_100": [100 * v for v in stats.wilson(len(flagged), len(ordinary))] if ordinary else None,
        },
        "suspicions": {
            "total": len(suspicions),
            "true": true_suspicions,
            "precision": true_suspicions / len(suspicions) if suspicions else None,
            "by_family": dict(collections.Counter(s["family"] for s in suspicions)),
            "true_by_family": dict(collections.Counter(s["family"] for s in suspicions if s["label"])),
        },
    }
    return summary, suspicions


def cost(log: Path) -> dict | None:
    for line in log.read_text().splitlines():
        if '"tokens"' not in line:
            continue
        tokens = json.loads(line)["tokens"]
        out = {}
        for model, usage in tokens.items():
            prices = PRICES.get(model.split("/")[-1])
            cached = usage.get("prompt_tokens_details", {}).get("cached_tokens", 0)
            uncached = usage["prompt_tokens"] - cached
            usd = None
            if prices:
                usd = (
                    uncached * prices.input_per_m + cached * prices.cache_hit_per_m + usage["completion_tokens"] * prices.output_per_m
                ) / 1e6
            out[model] = {
                "prompt_tokens": usage["prompt_tokens"],
                "cached_tokens": cached,
                "completion_tokens": usage["completion_tokens"],
                "usd": usd,
            }
        return out
    return None


def main(root: Path) -> dict:
    out: dict = {}
    all_suspicions = []
    for arm, folder in (("dspy", "dspy-1"), ("hunter", "hunter-1")):
        records = score.load_records(root / folder)
        out[arm], suspicions = arm_summary(records, arm)
        all_suspicions.extend(suspicions)
    out["dspy"]["cost"] = cost(root / "dspy-1.log")
    (root / "suspicions.jsonl").write_text("".join(json.dumps(s) + "\n" for s in all_suspicions))
    return out


if __name__ == "__main__":
    print(json.dumps(main(Path(sys.argv[1]).expanduser()), indent=2, default=str))
