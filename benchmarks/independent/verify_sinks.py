"""Stage 2 of source-only, model-driven detection: verify each model-classified sink candidate.

`model_sinks.py` put the vulnerable function among the candidates in 15 of 17 v2 cases, among ~4,800 candidates.
This asks, per candidate, one bounded question with repository tools (the existing tool hunter with its
per-family overrides): can attacker-controlled data reach THIS operation without a sufficient guard? A candidate
is reported only when the model states a concrete source-to-sink path and names no sufficient guard.

Scope: the candidates `model_sinks.py` recorded for each case's vulnerable pin
(~/ousast-results/independent-v2-modelsinks/<case>.json). One run per pin; the fixed pin is rechecked only for
detected sites (`--fixed`). Findings are written in the scan-result shape `evaluate.py` reads. Hard spend
ceiling. EXPLORATORY: v2 is spent for tuning; this qualifies nothing.

Usage: python benchmarks/independent/verify_sinks.py [--only ID,...] [--budget-usd 40] [--fixed]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import shutil
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import evaluate  # noqa: E402
from model_sinks import OPERATIONS, Meter  # noqa: E402

from openultrasast.config import load_config  # noqa: E402
from openultrasast.model.endpoint import DEFAULT_DETECTOR_MODEL  # noqa: E402

SYSTEM = (
    "You are a security reviewer with repository tools (read_file, grep_repo, find_refs). You are given ONE "
    "operation in ONE function. Decide whether data an attacker controls -- HTTP request parameters, body, "
    "headers, cookies, uploaded or imported content, webhook or API payloads, values stored earlier from such "
    "input -- can reach that operation without a sufficient guard (validation or allowlisting, escaping that fits "
    "the exact context, parameterization, or a fixed destination). Use the tools to follow callers and data. "
    "Report it only if you can state the concrete path from the source to the operation. Answer with a JSON array: "
    "one object with path, line, function_name, title, rationale (the source, each hop, and why no guard applies) "
    "if it is vulnerable; [] if it is not, or if you cannot establish the path."
)


def verify(root: Path, candidate: list, family: str, args: argparse.Namespace, meter: Meter, local: threading.local) -> list[dict]:
    from openultrasast import tool_hunter
    from openultrasast.complexity.map import Hotspot

    if not hasattr(local, "client"):
        local.client = tool_hunter.resolve_hunter_client()
        meter.add(local.client)
    if meter.spent() >= args.budget_usd:
        return [{"unverified": "budget"}]
    path, function, line = candidate
    spot = Hotspot(path=path, function_name=function, score=1.0, band="candidate", signals={}, rationale="model-classified sink", test_hint=None, inventory_finding_ids=())
    prompt = (
        f"Operation to judge: in `{path}`, function `{function}`, around line {line}, code that {OPERATIONS[family]}. "
        "The file is below. Trace where the operation's data comes from and whether it is guarded."
    )
    try:
        found = tool_hunter.run_tool_hunter(
            root, [spot], client=local.client, model=args.model, max_steps=args.max_steps,
            system_prompt=SYSTEM, user_prompt=prompt, context_files=[path], tags=("sink-verifier",),
        )  # fmt: skip
    except Exception as error:  # noqa: BLE001 -- recorded; an unverified candidate is not a clean one
        return [{"unverified": f"{type(error).__name__}: {str(error)[:120]}"}]
    return [
        {
            "site": f"{f.path}:{f.line or line}:{f.function_name or function}",
            "family": family,
            "title": f.title,
            "witness": f.rationale[:600],
            "candidate": f"{path}::{function}",
        }
        for f in found
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--population", type=Path, default=HERE / "population-v2.toml")
    parser.add_argument("--only", default="")
    parser.add_argument("--model", default=DEFAULT_DETECTOR_MODEL)
    parser.add_argument("--max-steps", type=int, default=3)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--budget-usd", type=float, default=40.0)
    parser.add_argument("--fixed", action="store_true", help="recheck detected sites at the fixed pin")
    args = parser.parse_args()
    load_config()
    evaluate.use(args.population)
    candidates_dir = evaluate.RESULTS.with_name(evaluate.RESULTS.name + "-modelsinks")
    out_dir = evaluate.RESULTS.with_name(evaluate.RESULTS.name + "-verified") / "scans"
    out_dir.mkdir(parents=True, exist_ok=True)
    only = {c.strip() for c in args.only.split(",") if c.strip()}
    meter, local = Meter(args.budget_usd), threading.local()
    for case in evaluate.cases():
        if only and case["id"] not in only:
            continue
        label = "fixed_a" if args.fixed else "vulnerable_a"
        out = out_dir / f"{case['id']}--{label}.json"
        if out.is_file():
            continue
        record = json.loads((candidates_dir / f"{case['id']}.json").read_text())
        todo = sorted({(p, fn, ln) for p, fn, ln in record["candidates"]}, key=lambda c: (c[0], c[1], c[2]))
        todo = list({(p, fn): (p, fn, ln) for p, fn, ln in todo}.values())  # one question per function
        if args.fixed:
            vulnerable = json.loads((out_dir / f"{case['id']}--vulnerable_a.json").read_text())
            detected = {f["candidate"] for f in vulnerable["findings"]}
            todo = [c for c in todo if f"{c[0]}::{c[1]}" in detected]
        started, before = time.monotonic(), meter.spent()
        checkout = evaluate.export(case, label, case["fixed" if args.fixed else "vulnerable"])
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
                results = list(pool.map(lambda c: verify(checkout, list(c), case["family"], args, meter, local), todo))
        finally:
            shutil.rmtree(checkout, ignore_errors=True)
        findings = [f for rows in results for f in rows if "site" in f]
        unverified = [f["unverified"] for rows in results for f in rows if "unverified" in f]
        result = {
            "root": "/case", "families": [case["family"]], "questions": len(todo), "completed": len(todo) - len(unverified),
            "completed_regions": sorted({f"{p}:{fn}" for p, fn, _ in todo}), "unverified": unverified[:20],
            "usd": round(meter.spent() - before, 4), "seconds": round(time.monotonic() - started, 1),
            "findings": sorted(findings, key=lambda f: f["site"]),
        }  # fmt: skip
        out.write_text(json.dumps(result, indent=1) + "\n")
        print(json.dumps({"case": case["id"], "pin": label, "candidates": len(todo), "findings": len(findings), "unverified": len(unverified), "usd": result["usd"], "total_usd": round(meter.spent(), 4)}), flush=True)
        if meter.spent() >= args.budget_usd:
            print(json.dumps({"stopped": "budget", "spent_usd": round(meter.spent(), 4)}), flush=True)
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
