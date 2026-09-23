"""Every finding of chosen families on one checkout, whole, for a human to adjudicate.

The family census keeps ten examples per family, which is enough to say a family establishes something and far
too few to say whether what it establishes is TRUE. Precision is the release gate (95%) and had never been
measured on PHP: 224 findings on Paid Memberships Pro, none reviewed. This runs the production discovery and scan
restricted to the families asked for, and writes every finding with its site, rung and witness, sorted by site so
a systematic sample (every n-th) is reproducible.

Usage: python finding_dump.py --root <checkout> --families injection --out findings.json [--deadline 3600]
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import time
from pathlib import Path

from openultrasast.cpg.backend import JoernBackend
from openultrasast.mapping import analyze_entry_points
from openultrasast.model.contracts import ExecutionBudget
from openultrasast.model.regions import regions_for
from openultrasast.model.scan import ScanBudget, scan_repository
from openultrasast.model.shipped import declared_sources
from openultrasast.preprocess import build_file_target, enumerate_source_files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--families", default="injection")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--deadline", type=float, default=3600.0)
    parser.add_argument("--max-regions", type=int, default=5000)
    args = parser.parse_args()
    wanted = tuple(f.strip() for f in args.families.split(",") if f.strip())

    files = enumerate_source_files(args.root)
    opened = sum(p.stat().st_size for p in files if p.is_file())
    if not files or not opened:
        raise SystemExit(f"read nothing under {args.root}")
    targets = [build_file_target(args.root, p) for p in files]
    regions = [
        dataclasses.replace(r, families=tuple(f for f in r.families if f in wanted))
        for r in regions_for(analyze_entry_points(args.root, targets), targets, shipped=declared_sources(args.root))
    ]
    regions = [r for r in regions if r.families]
    print(f"read {len(files)} files, {opened} bytes; {len(regions)} regions offer {wanted}", flush=True)

    started = time.monotonic()
    budget = ExecutionBudget(time.monotonic() + args.deadline, 5.0)
    result = scan_repository(
        args.root,
        regions[: args.max_regions],
        backend=JoernBackend(execution_budget=budget),
        budget=ScanBudget(max_model_calls=0, max_regions=args.max_regions, order_by_evidence=True),
        execution_budget=budget,
        ranking_mode="evidence",
        unit="repository",
        population_complete=True,
    )
    outcomes = result.question_outcomes
    findings = sorted(
        (
            {
                "site": f.site,
                "family": f.family,
                "rung": str(getattr(f.rung, "value", f.rung)),
                "witness": f.witness,
                "reached_from": f.reached_from,
            }
            for f in result.findings
            if f.family in wanted
        ),
        key=lambda f: f["site"],
    )
    record = {
        "root": str(args.root),
        "families": wanted,
        "seconds": round(time.monotonic() - started, 1),
        "questions": len(outcomes),
        "completed": sum(1 for o in outcomes if o.status == "completed"),
        "degradations": sorted({str(d.get("reason")) for d in result.degradations}),
        "findings": findings,
    }
    args.out.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({k: v for k, v in record.items() if k != "findings"} | {"findings": len(findings)}), flush=True)
    if not outcomes:
        raise SystemExit("no question was asked: the dump measured nothing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
