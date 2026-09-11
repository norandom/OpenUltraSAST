"""Phase 0 of flow-aware-ranking: where does each pinned CVE sit in the order the scan actually examines?

The ranker's success metric is not "is the CVE in the budget" -- on Paid Memberships Pro it already is, at
position 390 of 4,463 -- but **how small the budget can be while every CVE stays in it**. That number is
`budget_at_recall`, and until it is written down nothing later can claim to have improved it.

This is the baseline. It runs no engine and asks no model: it is the region pipeline exactly as the scan
uses it, sorted exactly as the scan sorts it, with each known vulnerability's position read off. Offline,
against pinned checkouts, so two runs of one repository agree.

    ousast-venv/bin/python benchmarks/ranking/position.py            # every pinned recipe with a checkout
    ousast-venv/bin/python benchmarks/ranking/position.py --json     # the same, as an artifact
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from openultrasast.mapping import analyze_entry_points  # noqa: E402
from openultrasast.model.regions import ScanRegion, regions_for  # noqa: E402
from openultrasast.model.shipped import declared_sources  # noqa: E402
from openultrasast.preprocess import preprocess_repository  # noqa: E402
from openultrasast.repos import checkout_path, load_repo_recipes  # noqa: E402

HEAD = 150  # how much of the evidence order a baseline records, region by region


def ordered_regions(root: Path) -> list[ScanRegion]:
    """The regions in the order `scan_repository` examines them. One definition, imported, never copied."""
    _, targets = preprocess_repository(root)
    regions = regions_for(analyze_entry_points(root, targets), targets, shipped=declared_sources(root))
    # The scan's own total order. If this drifts from scan.py the baseline measures the wrong thing, which
    # is why the sort key is the one thing here worth a test against the driver.
    return sorted(regions, key=lambda r: (not r.shipped, -r.rank, r.path, r.function or ""))


def evidence_ordered_regions(root: Path, regions: list[ScanRegion], language: str) -> tuple[list[ScanRegion], dict[str, object]]:
    """The regions in the order phase 2 spends the budget: by each region's best (tier, score), from a real
    evidence pass over EVERY region. Needs Joern. The ordering function is the scan's own, imported."""
    import time

    from openultrasast.cpg.backend import resolve_cpg_backend
    from openultrasast.model.scan import _collect, _evidence_pass, _hook_callbacks, order_by_evidence

    # A benchmark pass runs over EVERY region, not the scan's 500: pmpro's 22,315 pairs took 255 s without
    # the join facts and past the scan's 300 s default with them, and a pass that times out answers
    # nothing -- which read as "tiers={}" once and cost a run. The scan's per-push ceiling is not this
    # measurement's; an operator who set one keeps it.
    os.environ.setdefault("OPENULTRASAST_CPG_QUERY_TIMEOUT", "1800")
    backend = resolve_cpg_backend()
    started = time.monotonic()
    # The RECIPE's language, never the first region's: WP Statistics's first region is JavaScript, and a
    # build asked for as JavaScript went looking for jssrc2cpg and lost the whole repository's measurement.
    cpg = backend.build(root, language=language)
    build_seconds = round(time.monotonic() - started, 1)
    if cpg is None:
        raise SystemExit(f"no graph for {root}: {getattr(backend, 'last_failure', '')}")
    try:
        started = time.monotonic()
        evidence, failed = _evidence_pass(cpg, _collect(regions), _hook_callbacks(root, regions))
        evidence_seconds = round(time.monotonic() - started, 1)
    finally:
        if callable(getattr(cpg, "cleanup", None)):
            cpg.cleanup()
    tiers = Counter(e.tier for e in evidence.values())
    ordered = order_by_evidence(regions, evidence)
    best: dict[tuple[str, str], tuple[int, float]] = {}
    for (path, function, _family), vector in evidence.items():
        best[(path, function)] = max(best.get((path, function), (-1, 0.0)), vector.order_key)
    facts = {
        # The head of the order, with each region's (tier, score), so a baseline says WHAT sits ahead of a
        # pinned CVE and not only how much of it -- the within-tier ties are the next thing to read.
        "head": [
            {
                "position": i,
                "tier": best.get((r.path, r.function or ""), (-1, 0.0))[0],
                "score": best.get((r.path, r.function or ""), (-1, 0.0))[1],
                "site": f"{r.path}:{r.function or ''}",
                "rank": r.rank,
            }
            for i, r in enumerate(ordered[:HEAD])
        ],
        "build_seconds": build_seconds,
        "evidence_seconds": evidence_seconds,
        "pairs": len(evidence),
        "pairs_unanswered": failed,
        "tier_counts": {str(k): v for k, v in sorted(tiers.items())},
    }
    return ordered, facts


def measure(name: str, root: Path, known: list[dict[str, object]], *, by_evidence: bool = False, language: str = "") -> dict[str, object]:
    regions = ordered_regions(root)
    facts: dict[str, object] = {}
    if by_evidence:
        regions, facts = evidence_ordered_regions(root, regions, language)
    tiers = Counter(r.rank for r in regions)
    largest = max(tiers.values()) if tiers else 0
    rows: list[dict[str, object]] = []
    for item in known:
        # A known vulnerability names a file and a function. Match on both, path by suffix because a recipe
        # writes it relative to the repository and a region may carry it the same way or deeper.
        hit = next(
            (i for i, r in enumerate(regions) if r.path.endswith(str(item["file"])) and r.function == item["function"]),
            None,
        )
        rows.append(
            {
                "id": item["id"],
                "family": item["family"],
                "site": f"{item['file']}:{item['line']}:{item['function']}",
                # Zero-based. None means no region is named after this function: the site is a SINK that an
                # entry-point region elsewhere reaches through `callDepth` -- VAmPI's SQL injection lives in
                # `models/user_model.py:get_user` and is found from the handler that calls it. Its true
                # position is that handler's, which only the flow can say, so it is reported and left out of
                # `budget_at_recall` rather than counted as a miss it is not.
                "position": hit,
                "rank": regions[hit].rank if hit is not None else None,
                "in_scope": item["in_scope"],
                "reached_transitively": hit is None,
            }
        )
    positioned = [r["position"] for r in rows if r["position"] is not None and r["in_scope"]]
    return {
        "repo": name,
        "regions": len(regions),
        "distinct_ranks": len(tiers),
        "largest_tier_share": round(largest / len(regions), 3) if regions else 0.0,
        "largest_tier_rank": max(tiers, key=lambda k: tiers[k]) if tiers else None,
        # The smallest examined-region budget that still holds every in-scope known vulnerability.
        "budget_at_recall": (max(positioned) + 1) if positioned else None,
        "known": rows,
        **facts,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", action="store_true", help="emit one JSON object per repository")
    parser.add_argument("--repo", help="only this recipe")
    parser.add_argument("--evidence", action="store_true", help="phase 2: order by a real evidence pass over every region (needs Joern)")
    args = parser.parse_args()

    results: list[dict[str, object]] = []
    for recipe in load_repo_recipes():
        if args.repo and recipe.name != args.repo:
            continue
        if "detection" not in recipe.measures:
            continue
        root = checkout_path(recipe)
        if not root.is_dir():
            print(f"{recipe.name}: not checked out, skipping", file=sys.stderr)
            continue
        known = [
            {"id": k.id, "family": k.family, "file": k.file, "function": k.function, "line": k.line, "in_scope": k.in_scope}
            for k in recipe.known
        ]
        result = measure(recipe.name, root, known, by_evidence=args.evidence, language=recipe.language)
        results.append(result)
        # One line per repository as it lands, so a failure on the next repository cannot lose this one.
        print(json.dumps(result), file=sys.stderr, flush=True)

    if args.json:
        print(json.dumps(results, indent=2))
        return 0
    for r in results:
        print(
            f"{r['repo']}: {r['regions']} regions, {r['distinct_ranks']} distinct ranks, "
            f"{100 * float(r['largest_tier_share']):.1f}% share rank {r['largest_tier_rank']}"
        )
        for k in r["known"]:
            where = "reached via another region" if k["position"] is None else f"position {k['position']} (rank {k['rank']})"
            scope = "" if k["in_scope"] else "  [out of scope]"
            print(f"   {k['id']:16} {where:28} {k['site']}{scope}")
        print(f"   budget_at_recall = {r['budget_at_recall']}")
        if "tier_counts" in r:
            print(f"   build {r['build_seconds']}s, evidence {r['evidence_seconds']}s over {r['pairs']} pairs, tiers {r['tier_counts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
