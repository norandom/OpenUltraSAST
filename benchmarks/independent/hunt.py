"""Run the UNCHANGED tool hunter over an independent population's pins, scoreable by the evaluation protocol.

The hunter (`tool_hunter.run_tool_hunter`, default prompt, default tools, default step budget) is handed the
regions the ranker selects for the case's family -- the same discovery and ranking the static scan starts from,
top `--max-regions` by rank, in groups of `--per-hunt` -- and nothing else: not the fix diff, not the advisory,
not the declared sites. Each pin's result is written in the scan-result shape `evaluate.py score` reads, into
`~/ousast-results/independent-<vN>-hunter/scans/`, so the same pre-registered matching scores it.

Model calls go to the resolved hunter client (DeepSeek when its key is set); the run stops, and says so, when
the recorded spend reaches `--budget-usd`.

Usage:
    python benchmarks/independent/hunt.py --population population-v2.toml [--only ID,...] [--pins a,b]
    python benchmarks/independent/hunt.py --population population-v2.toml --score
    python benchmarks/independent/hunt.py --pilot-root <checkout> --family injection   # a development case
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import shutil
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import evaluate  # noqa: E402

from openultrasast.mapping import analyze_entry_points  # noqa: E402
from openultrasast.model.endpoint import DEFAULT_DETECTOR_MODEL  # noqa: E402
from openultrasast.model.regions import regions_for  # noqa: E402
from openultrasast.model.shipped import declared_sources  # noqa: E402
from openultrasast.preprocess import build_file_target, enumerate_source_files  # noqa: E402

# The model names a family in its own words; the protocol scores three. Fixed before any v2 pin is hunted.
FAMILY_WORDS = {
    "untrusted_destination": ("ssrf", "server-side request", "open redirect", "redirect", "url fetch", "request forgery"),
    "config_secrets": ("cors", "debug", "secret", "hardcoded", "hard-coded", "credential", "misconfig", "configuration", "tls", "certificate"),
    "injection": ("inject", "sql", "sqli", "nosql", "command", "rce", "code execution", "eval", "template", "ssti", "xss", "deserializ", "ldap", "xpath"),
}


def family_of(raw: str, title: str) -> str:
    text = f"{raw} {title}".lower()
    for family, words in FAMILY_WORDS.items():
        if any(word in text for word in words):
            return family
    return "other"


def hotspots_for(root: Path, family: str, max_regions: int) -> list:
    from openultrasast.complexity.map import Hotspot

    files = enumerate_source_files(root)
    if not files or not sum(p.stat().st_size for p in files if p.is_file()):
        raise SystemExit(f"read nothing under {root}")
    targets = [build_file_target(root, p) for p in files]
    regions = [
        dataclasses.replace(r, families=tuple(f for f in r.families if f == family))
        for r in regions_for(analyze_entry_points(root, targets), targets, shipped=declared_sources(root))
    ]
    ranked = sorted((r for r in regions if r.families), key=lambda r: (-r.rank, r.path, r.function or ""))[:max_regions]
    return [
        Hotspot(
            path=r.path,
            function_name=r.function or None,
            score=float(r.rank),
            band="ranker",
            signals={},
            rationale=f"ranked region offering {family}",
            test_hint=None,
            inventory_finding_ids=(),
        )
        for r in ranked
    ]


def _spent(client: object) -> float:
    cost = getattr(client, "cost_usd", None)
    return float(cost()) if callable(cost) else 0.0


def hunt(root: Path, family: str, args: argparse.Namespace, spent: list[float]) -> dict:
    from openultrasast import tool_hunter

    client = tool_hunter.resolve_hunter_client()
    if client is None:
        raise SystemExit("no hunter client: set DEEPSEEK_API_KEY")
    started = time.monotonic()
    hotspots = hotspots_for(root, family, args.max_regions)
    groups = [hotspots[i : i + args.per_hunt] for i in range(0, len(hotspots), args.per_hunt)]
    findings, done, errors = [], 0, []
    for group in groups:
        if sum(spent) + _spent(client) >= args.budget_usd:
            errors.append("budget_exhausted")
            break
        try:
            found = tool_hunter.run_tool_hunter(root, group, client=client, model=args.model, max_steps=tool_hunter.DEFAULT_MAX_STEPS)
            done += 1
        except Exception as error:  # noqa: BLE001 -- recorded per hunt; a pin with no completed hunt is an instrument failure
            errors.append(f"{type(error).__name__}: {str(error)[:200]}")
            continue
        for f in found:
            raw = next((t.split(":", 1)[1] for t in f.tags if t.startswith("family:")), "")
            findings.append(
                {
                    "site": f"{f.path}:{f.line or 0}:{f.function_name or ''}",
                    "family": family_of(raw, f.title),
                    "model_family": raw,
                    "title": f.title,
                    "witness": f.rationale[:400],
                }
            )
    cost = _spent(client)
    spent.append(cost)
    return {
        "root": str(root),
        "families": [family],
        "model": args.model,
        "seconds": round(time.monotonic() - started, 1),
        "questions": len(groups),
        "completed": done,
        "completed_regions": sorted({f"{h.path}:{h.function_name or ''}" for g in groups[:done] for h in g}),
        "hunt_errors": errors,
        "cost_usd": round(cost, 4),
        "findings": sorted(findings, key=lambda f: f["site"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--population", type=Path, default=evaluate.POPULATION)
    parser.add_argument("--only", default="")
    parser.add_argument("--pins", default="")
    parser.add_argument("--pilot-root", type=Path)
    parser.add_argument("--family", default="injection")
    parser.add_argument("--model", default=DEFAULT_DETECTOR_MODEL)
    parser.add_argument("--max-regions", type=int, default=20)
    parser.add_argument("--per-hunt", type=int, default=5)
    parser.add_argument("--budget-usd", type=float, default=10.0)
    parser.add_argument("--score", action="store_true", help="score the hunter's results with the population's protocol")
    args = parser.parse_args()
    from openultrasast.config import load_config

    load_config()  # loads the project's .env: DeepSeek is the chat provider, OpenRouter only embeddings
    spent: list[float] = []
    if args.pilot_root:
        result = hunt(args.pilot_root, args.family, args, spent)
        print(json.dumps({k: v for k, v in result.items() if k != "findings"} | {"findings": result["findings"]}, indent=1))
        return 0
    evaluate.use(args.population)
    evaluate.RESULTS = evaluate.RESULTS.with_name(evaluate.RESULTS.name + "-hunter")
    if args.score:
        return evaluate.score_v2()
    only = {c.strip() for c in args.only.split(",") if c.strip()}
    wanted = {p.strip() for p in args.pins.split(",") if p.strip()}
    for case in evaluate.cases():
        if only and case["id"] not in only:
            continue
        for label, commit in evaluate.pins(case).items():
            if wanted and label not in wanted:
                continue
            out = evaluate.RESULTS / "scans" / f"{case['id']}--{label}.json"
            if out.is_file():
                continue
            if sum(spent) >= args.budget_usd:
                print(json.dumps({"stopped": "budget", "spent_usd": round(sum(spent), 4)}), flush=True)
                return 1
            out.parent.mkdir(parents=True, exist_ok=True)
            checkout = evaluate.export(case, label, commit)
            try:
                result = hunt(checkout, case["family"], args, spent)
            finally:
                shutil.rmtree(checkout, ignore_errors=True)
            if not result["completed"]:
                result["instrument_error"] = "no hunt completed: " + "; ".join(result["hunt_errors"][:3])
            result["root"] = "/case"
            out.write_text(json.dumps(result, indent=2) + "\n")
            print(
                json.dumps({"case": case["id"], "pin": label, "findings": len(result["findings"]), "hunts": f"{result['completed']}/{result['questions']}", "usd": result["cost_usd"], "total_usd": round(sum(spent), 4)}),
                flush=True,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
