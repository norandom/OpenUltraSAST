"""Which declared vulnerability families actually establish findings on real code?

Seven families are declared. Two are proven end to end: injection on NodeGoat and VAmPI, and access
control on VAmPI once its change context could complete. The other five have never been checked for
whether they produce a witness on anything, and a family that is declared but silent is advertised
coverage the tool does not have.

This runs the production discovery and scan over a whole checkout and reports, per family, how many
regions were asked, how many questions completed, and what was found with the witness and rung that
established it. It makes no novelty or admission claim: there is no comparison here, only detection.

A family reporting nothing is recorded as nothing. That is the point of asking.
"""

from __future__ import annotations

import argparse
import collections
import json
import time
from pathlib import Path
from typing import Any

from openultrasast.cpg.backend import JoernBackend
from openultrasast.mapping import analyze_entry_points, php_hook_callbacks
from openultrasast.model.contracts import ExecutionBudget
from openultrasast.model.regions import regions_for
from openultrasast.model.scan import ScanBudget, scan_repository
from openultrasast.model.shipped import declared_sources
from openultrasast.preprocess import build_file_target, enumerate_source_files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--deadline", type=float, default=1800.0)
    parser.add_argument("--max-regions", type=int, default=500)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    record: dict[str, Any] = {
        "schema_version": 1,
        "experiment": "family-detection-census-v1",
        "subject": args.name,
        "root": str(args.root),
        "claim_scope": "Detection only. No comparison, no novelty, no admission, no capability enabled.",
    }
    target = args.out / f"{args.name}.json"

    def save() -> None:
        target.write_text(json.dumps(record, indent=2, default=str) + "\n")

    files = enumerate_source_files(args.root)
    targets = [build_file_target(args.root, path) for path in files]
    opened = sum(path.stat().st_size for path in files if path.is_file())
    regions = regions_for(analyze_entry_points(args.root, targets), targets, shipped=declared_sources(args.root))
    record["inputs"] = {"files": len(files), "bytes": opened, "regions": len(regions)}
    record["regions_by_family"] = dict(collections.Counter(f for r in regions for f in r.families))
    record["languages"] = dict(collections.Counter(r.language for r in regions))
    save()
    if not files or not opened:
        record["error"] = "no readable source"
        save()
        return 2

    backend = JoernBackend(execution_budget=ExecutionBudget(time.monotonic() + args.deadline, 5.0))
    hooks = php_hook_callbacks(args.root, targets) if any(r.language == "php" for r in regions) else {}
    started = time.monotonic()
    result = scan_repository(
        args.root,
        regions[: args.max_regions],
        backend=backend,
        budget=ScanBudget(max_model_calls=0, max_regions=args.max_regions, order_by_evidence=True),
        execution_budget=ExecutionBudget(time.monotonic() + args.deadline, 5.0),
        ranking_mode="evidence",
        unit="repository",
        population_complete=True,
    )
    record["scan"] = {
        "seconds": round(time.monotonic() - started, 1),
        "build_seconds": result.build_seconds,
        "query_seconds": result.query_seconds,
        "hook_table_hooks": len(hooks),
        "degradations": [str(d.get("reason")) for d in result.degradations],
        # The reason alone cannot be acted on. A partition census that reports files missing carries WHICH
        # files, and without them the gap is a label rather than a lead.
        "degradation_detail": [
            {k: (v[:20] if isinstance(v, list) else v) for k, v in d.items() if k != "stage"} for d in result.degradations
        ],
        "questions_total": len(result.question_outcomes),
        "questions_completed": sum(1 for q in result.question_outcomes if q.status == "completed"),
        "findings_total": len(result.findings),
        # Why the outcomes say what they say, counted rather than inferred: a family can find something while
        # every one of its questions is recorded unresolved, and the two numbers then disagree in public.
        "outcome_status": dict(collections.Counter(q.status for q in result.question_outcomes)),
        # WHY an outcome is not completed. Counting only the statuses left three separate causes looking
        # identical, and each one had to be found by reading code rather than by reading the record.
        "outcome_reason": dict(collections.Counter(f"{q.status}:{q.reason}" for q in result.question_outcomes)),
    }

    asked = collections.Counter(q.identity.family for q in result.question_outcomes)
    completed = collections.Counter(q.identity.family for q in result.question_outcomes if q.status == "completed")
    found: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for finding in result.findings:
        found[finding.family].append(
            {
                "site": finding.site,
                "rung": finding.rung.value,
                "witness": (finding.witness or "")[:200],
                "reached_from": finding.reached_from,
            }
        )
    # Families with regions but no question must appear, or the census hides its own biggest finding: on
    # VAmPI four declared families were offered 25 regions each and asked nothing, and building this list
    # from the questions alone made them invisible rather than negative.
    offered = record["regions_by_family"]
    families = sorted(set(offered) | set(asked) | set(found))
    record["families"] = {
        family: {
            "regions_offering": offered.get(family, 0),
            "questions_asked": asked.get(family, 0),
            "questions_completed": completed.get(family, 0),
            "findings": len(found.get(family, [])),
            "rungs": dict(collections.Counter(item["rung"] for item in found.get(family, []))),
            "examples": found.get(family, [])[:10],
            # The distinction that matters: a family that answered and found nothing is a different
            # statement from one that could not answer, and neither is "clean".
            #
            # Findings are checked FIRST, and that order is the whole point. It used to ask about completion
            # before findings, so a family that established 18 findings on a PHP plugin while no question
            # outcome was marked completed reported "asked but no question completed" -- and a census whose
            # job is to say what each family finds reported nothing for a repository that had found a real
            # SQL injection. A question-outcome count is a statement about bookkeeping; a finding is the
            # thing being censused, and it cannot be hidden behind the other.
            "verdict": (
                "establishes findings"
                if found.get(family)
                else "region offered, no question asked"
                if not asked.get(family)
                else "asked but no question completed"
                if not completed.get(family)
                else "answered, nothing found"
            ),
        }
        for family in families
    }
    record["summary"] = dict(collections.Counter(entry["verdict"] for entry in record["families"].values()))
    save()
    cleanup = getattr(result, "cleanup", None)
    if callable(cleanup):
        cleanup()
    print(json.dumps({"subject": args.name, "summary": record["summary"]}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
