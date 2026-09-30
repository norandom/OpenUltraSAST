"""Reference-only since 2026-09-30: the ai-service-plane tasks `plane/tasks/verify.py` and `agree.py`, run on google/ax
through `ousast plane run plane/runs/validation-46.yaml`, replace this script (benchmarks/independent/
plane-increment-2.json). It stays as the reference behaviour the plane was measured against.

Exploratory score of a batched-verifier run against the population's cases (protocol v2 matching).

The batched verifier writes one vulnerable-pin result per case (and a fixed-pin recheck with --fixed), not the
six pins protocol v2 scores, so this applies the same matching rule (`evaluate.matches_v2`) to what exists:
detected when an AGREED finding matches; unstable when only a DISPUTED one does; fixed-side alert when an agreed
finding at the fixed pin matches the fix's new side. The precision sample is every third agreed vulnerable-pin
finding (all if 15 or fewer), to be adjudicated by hand. v2 is spent for tuning: this qualifies nothing.

Usage: python benchmarks/independent/score_batched.py [--results-suffix batched] [--population population-v2.toml]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import evaluate  # noqa: E402


def anchored(result: dict) -> dict:
    """Sites anchored to the candidate asked about (older records used the model's reported location)."""
    for key in ("findings", "disputed"):
        for f in result.get(key, []):
            path, _, function = f["candidate"].partition("::")
            site_path, _, rest = f["site"].partition(":")
            line = rest.split(":")[0] if site_path == path else "0"
            f["site"] = f"{path}:{line}:{function}"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--population", type=Path, default=HERE / "population-v2.toml")
    parser.add_argument("--results-suffix", default="batched")
    args = parser.parse_args()
    evaluate.use(args.population)
    results = evaluate.RESULTS.with_name(evaluate.RESULTS.name + "-" + args.results_suffix)
    scans = results / "scans"
    per_case, pool = [], []
    for case in evaluate.cases():
        path = scans / f"{case['id']}--vulnerable_a.json"
        if not path.is_file():
            per_case.append({"id": case["id"], "status": "incomplete"})
            continue
        vulnerable = anchored(json.loads(path.read_text()))
        old, new = evaluate.hunks(case, "old"), evaluate.hunks(case, "new")
        agreed = [f["site"] for f in vulnerable["findings"] if evaluate.matches_v2(f, case, old)]
        disputed = [f["site"] for f in vulnerable.get("disputed", []) if evaluate.matches_v2(f, case, old)]
        fixed_path = scans / f"{case['id']}--fixed_a.json"
        fixed = anchored(json.loads(fixed_path.read_text())) if fixed_path.is_file() else None
        fixed_alerts = [f["site"] for f in fixed["findings"] if evaluate.matches_v2(f, case, new)] if fixed else None
        per_case.append(
            {
                "id": case["id"], "family": case["family"], "detected": bool(agreed), "detected_sites": agreed,
                "unstable": bool(disputed) and not agreed, "unstable_sites": disputed,
                "agreed_findings": len(vulnerable["findings"]), "disputed_findings": len(vulnerable.get("disputed", [])),
                "triaged_out": vulnerable.get("triaged_out"), "candidates": vulnerable.get("questions"),
                "fixed_side_alerts": fixed_alerts, "fixed_agreed_total": len(fixed["findings"]) if fixed else None,
                "removed_by_fix": fixed.get("removed_by_fix") if fixed else None, "usd": vulnerable.get("usd"), "usage": vulnerable.get("usage"),
            }
        )  # fmt: skip
        pool += [{"case": case["id"], **f} for f in vulnerable["findings"]]
    pool.sort(key=lambda f: (f["case"], f["site"]))
    sample = pool if len(pool) <= 15 else pool[0::3]
    scored = [c for c in per_case if c.get("status") != "incomplete"]
    detected = sum(c["detected"] for c in scored)
    with_fixed = [c for c in scored if c["fixed_side_alerts"] is not None]
    result = {
        "protocol": "protocol-v2.md matching, exploratory (batched verifier, vulnerable + fixed pins only)",
        "cases_scored": len(scored), "cases_incomplete": [c["id"] for c in per_case if c.get("status") == "incomplete"],
        "recall": [detected, len(scored)], "recall_wilson95": evaluate.wilson(detected, len(scored)),
        "unstable_detections": [c["id"] for c in scored if c["unstable"]],
        "fixed_side_alerts": sum(len(c["fixed_side_alerts"]) for c in with_fixed) if with_fixed else None,
        "fixed_pins_rechecked": len(with_fixed),
        "pooled_agreed_findings": len(pool), "precision_sample_size": len(sample),
        "usd": round(sum(float(c.get("usd") or 0) for c in scored), 2),
        "cases": per_case, "precision_sample": sample,
    }  # fmt: skip
    (results / "score.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k not in ("cases", "precision_sample")}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
