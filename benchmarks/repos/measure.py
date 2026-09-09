"""contributor-scan 2.2: measure one pinned checkout end to end.

    python benchmarks/repos/measure.py vampi --out benchmarks/measurements/<date>-repo-vampi.json

This is the go/no-go instrument for the repository shape, so it records the things that decide it rather
than a single verdict:

* **Where the wall-clock went** -- CPG build, Joern queries, and arbitration as three numbers. A total cannot
  say whether a warm Joern server (task 2.3) would buy anything, or whether the ceiling is the engine or the
  budget.
* **What went unjudged.** A scan that ran out of budget and a scan that examined everything both report
  findings; only the unjudged count separates them.
* **Whether each KNOWN vulnerability was found, and at which rung** -- but only for the ones the recipe marks
  in scope. An out-of-family CVE is reported as `out_of_scope`, never as a miss.

The scan runs against a copy: the pinned checkout stays pristine, and a scan's own artifacts never
accumulate inside the thing being measured.
"""

from __future__ import annotations

import argparse
import json
import resource
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from openultrasast.repos import (  # noqa: E402
    DEFAULT_REPO_DIR,
    KnownVulnerability,
    load_repo_recipes,
    recipe_payload,
    resolve,
    verify,
)

# How far from the declared line a finding may land and still be the same defect. A taint finding lands on
# the sink, an obligation finding on the handler, and the two can be tens of lines apart in one function.
LINE_TOLERANCE = 40
RUNG_ORDER = ("execution_confirmed", "model_entailed", "model_corroborated", "suspicion")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="measure a scan of one pinned known-vulnerable checkout")
    parser.add_argument("name")
    parser.add_argument("--dir", type=Path, default=DEFAULT_REPO_DIR)
    parser.add_argument("--fetch", action="store_true", help="allow network to materialise the checkout")
    parser.add_argument("--mode", default="standard", choices=("quick", "standard", "deep"))
    parser.add_argument("--work", type=Path, default=None, help="where the scanned copy goes (default: a temp dir)")
    parser.add_argument("--config", type=Path, default=None, help="scan config; without one the shipped defaults apply")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    recipes = [item for item in load_repo_recipes(args.dir) if item.name == args.name]
    if not recipes:
        raise SystemExit(f"no recipe named {args.name!r} in {args.dir}")
    recipe = recipes[0]

    root = resolve(recipe, fetch=True if args.fetch else None)
    problems = verify(recipe, root)
    if problems:
        raise SystemExit(f"{recipe.name}: the checkout contradicts the recipe: {problems}")

    work = args.work or Path(f"/tmp/ousast-measure-{recipe.name}")  # noqa: S108 - operator-visible, overridable
    _copy(root, work)

    outcome = _scan(work, args.mode, args.config)
    payload = {
        "generated": datetime.now(UTC).strftime("%Y-%m-%d"),
        "spec": "contributor-scan 2.2 (Req 4.1-4.5)",
        "repo": recipe_payload(recipe),
        "mode": args.mode,
        "config": str(args.config) if args.config else "shipped defaults",
        **outcome,
        "known_outcomes": [_outcome(item, outcome["findings"]) for item in recipe.known],
    }
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(text)
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


def _copy(root: Path, work: Path) -> None:
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(root, work, ignore=shutil.ignore_patterns(".git"))


def _scan(work: Path, mode: str, config: Path | None = None) -> dict[str, object]:
    """Run the scan as a child process, so its peak RSS is measurable and a crash is a recorded stage."""
    before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    started = time.monotonic()
    proc = subprocess.run(
        [sys.executable, "-m", "openultrasast.cli", "scan", str(work), "--mode", mode] + (["--config", str(config)] if config else []),
        capture_output=True,
        text=True,
    )
    wall = round(time.monotonic() - started, 2)
    peak_kb = max(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss, before)

    runs = sorted((work / ".openultrasast" / "runs").glob("*/"))
    manifest = runs[-1] / "manifest.json" if runs else None
    if proc.returncode not in (0, 1) or manifest is None or not manifest.is_file():
        # Req 4.3: a repository that cannot be processed records the stage it failed at, not an opaque error.
        return {
            "completed": False,
            "failed_at": "scan" if manifest is None else "manifest",
            "exit_code": proc.returncode,
            "stderr_tail": proc.stderr[-2000:],
            "scan_seconds": wall,
            "peak_rss_mb": round(peak_kb / 1024, 1),
            "findings": [],
        }

    data = json.loads(manifest.read_text())
    model = dict(data.get("model", {}))
    findings = _findings(runs[-1])
    return {
        "completed": True,
        "exit_code": proc.returncode,
        "scan_seconds": wall,
        "peak_rss_mb": round(peak_kb / 1024, 1),
        "model": model,
        "stages": data.get("stages", {}),
        "degradations": data.get("degradations", []),
        "findings_total": len(findings),
        "findings_by_rung": _tally(findings),
        "findings": findings,
    }


def _findings(run_dir: Path) -> list[dict[str, object]]:
    path = run_dir / "findings.json"
    if not path.is_file():
        return []
    data = json.loads(path.read_text())
    rows = data if isinstance(data, list) else data.get("findings", [])
    return [dict(row) for row in rows]


def _tally(findings: list[dict[str, object]]) -> dict[str, int]:
    counts = {rung: 0 for rung in RUNG_ORDER}
    for row in findings:
        rung = str(row.get("rung", "suspicion"))
        counts[rung] = counts.get(rung, 0) + 1
    return counts


def _outcome(known: KnownVulnerability, findings: list[dict[str, object]]) -> dict[str, object]:
    """Whether this vulnerability was found -- and, when it was never in scope, that it was not asked."""
    if not known.in_scope:
        return {
            "id": known.id,
            "location": known.location,
            "family": known.family,
            "result": "out_of_scope",
            "note": "this engine arbitrates no family that decides this weakness; 'not found' would be a category error, not a miss",
        }
    matches = [row for row in findings if _matches(known, row)]
    if not matches:
        return {"id": known.id, "location": known.location, "family": known.family, "result": "missed"}
    best = min(matches, key=lambda row: _rank(str(row.get("rung", "suspicion"))))
    return {
        "id": known.id,
        "location": known.location,
        "family": known.family,
        "result": "found",
        "rung": best.get("rung"),
        "finding_id": best.get("finding_id"),
        "line": best.get("line"),
        "matches": len(matches),
    }


def _matches(known: KnownVulnerability, row: dict[str, object]) -> bool:
    if str(row.get("path", "")) != known.file:
        return False
    if str(row.get("function_name") or "") == known.function:
        return True
    line = row.get("line")
    return isinstance(line, int) and abs(line - known.line) <= LINE_TOLERANCE


def _rank(rung: str) -> int:
    return RUNG_ORDER.index(rung) if rung in RUNG_ORDER else len(RUNG_ORDER)


if __name__ == "__main__":
    raise SystemExit(main())
