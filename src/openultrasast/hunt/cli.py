"""Command line for the hunt program: run a program over a frozen manifest and write scorable records.

    python -m openultrasast.hunt.cli run MANIFEST --repos REPOS.json --out DIR [--mask producer,...]
        [--only vulnerability|ordinary|all] [--slice 1] [--budget-usd 2.0] [--budget-calls 200]
        [--no-tools] [--max-iters 8] [--pilot-report]

The model key comes from the environment only. Records and the DSPy cache go under DIR; the pilot manifest is
refused unless --pilot-report is given (the held-out set is a report surface, not a tuning surface).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import dspy

from benchmarks.unseen.replay import load_slice

from . import program as hp
from . import runner


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("manifest", type=Path)
    run.add_argument("--repos", type=Path, required=True, help="JSON map repo -> local clone with history")
    run.add_argument("--out", type=Path, required=True)
    run.add_argument("--mask", default="", help="comma-separated producers or inputs to drop (an ablation arm)")
    run.add_argument("--only", choices=("vulnerability", "ordinary", "all"), default="all")
    run.add_argument("--slice", default="1")
    run.add_argument("--budget-usd", type=float, default=None)
    run.add_argument("--budget-calls", type=float, default=None)
    run.add_argument("--no-tools", action="store_true", help="one prediction per change instead of the tool loop")
    run.add_argument("--max-iters", type=int, default=8)
    run.add_argument("--pilot-report", action="store_true")
    args = parser.parse_args(argv)

    mask = tuple(part.strip() for part in args.mask.split(",") if part.strip())
    args.out.mkdir(parents=True, exist_ok=True)
    lm = hp.build_lm(cache_dir=args.out / "dspy-cache")
    dspy.configure(lm=lm, adapter=dspy.ChatAdapter())
    tools_for = None if args.no_tools else hp.repository_tools
    # The program is built with the tools of a placeholder root; the runner rebinds them per checkout.
    program = hp.HuntProgram(mask=mask, tools=() if args.no_tools else hp.repository_tools(Path(".")), max_iters=args.max_iters)
    pid = hp.program_id(program, mask=mask)
    budget = {key: value for key, value in (("usd", args.budget_usd), ("calls", args.budget_calls)) if value is not None}
    repos = json.loads(args.repos.read_text())
    versions = {"dspy": dspy.__version__, "python": sys.version.split()[0]}
    with dspy.track_usage() as usage:
        artifact = runner.run(
            args.manifest,
            repos,
            args.out,
            program=program,
            program_id=pid,
            mask=mask,
            only=args.only,
            slice_id=args.slice,
            budget=budget or None,
            pilot_report=args.pilot_report,
            tools_for=tools_for,
            load_changes=load_slice,
            versions=versions,
        )
    totals = usage.get_total_tokens() if hasattr(usage, "get_total_tokens") else {}
    print(
        json.dumps(
            {"program_id": pid, "mask": list(mask), "artifact": artifact.artifact_id if artifact else None, "tokens": totals}, default=str
        )
    )
    return 0 if artifact is not None else 3


if __name__ == "__main__":
    sys.exit(main())
