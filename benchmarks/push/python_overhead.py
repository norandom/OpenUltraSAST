"""The push path at full repository scale with an engine that answers instantly: what does the PYTHON cost?

Named by the 2026-09-23 PHP transfer replay, which met four scale defects one two-hour run at a time -- a cache
that rescanned itself on every write, a relationship list searched linearly, a fsync per cache entry, and the
ruleset re-parsed per region (89,127 TOML parses in one discovery). Every one was Python bookkeeping around the
engine, every one grew with the repository, and none could show in a unit test or on a small subject.

This runs the real `replay()` -- snapshots, discovery, partitions, evidence, change context, arbitration,
comparison, reporting, the reuse cache -- on a real checkout, with a `JoernBackend` whose graphs are stubs and
whose queries answer at once with rows recorded from the real engine on the same repository. Engine time is
zero by construction, so everything left is ours. It runs in minutes, with the sampling profiler on, and it
fails loudly if the instrument did not actually exercise the path (no questions, no rows, no stages).

Usage:
    python benchmarks/push/python_overhead.py --repository <objects.git> --base <oid> --head <oid> \\
        --rows <recorded rows json> [--rows ...] --out <dir> [--deadline 3600]
"""

from __future__ import annotations

import argparse
import json
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from openultrasast import profiling
from openultrasast.config import PushConfig
from openultrasast.cpg.backend import TIMING, CpgResult, JoernBackend
from openultrasast.push.runner import replay

# What each partition's graph holds, so the stub census names exactly the files a real frontend would read.
EXTENSIONS = {"php": (".php",), "javascript": (".js", ".jsx", ".mjs", ".cjs"), "typescript": (".ts", ".tsx"), "python": (".py",)}


class StubEngine(JoernBackend):
    """A backend whose engine is a table lookup: real row shapes, zero engine time."""

    def __init__(self, templates: list[list[object]], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.templates = templates
        self.asked = 0
        self.graphs = 0

    def build(self, root: Path, *, language: str = "", exclude: Any = (), execution_budget: Any = None) -> CpgResult | None:
        extensions = EXTENSIONS.get(language.lower(), ())
        files = sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() and p.suffix.lower() in extensions)
        graph = Path(__import__("tempfile").mkdtemp(prefix="ousast-stub-")) / "cpg.bin"
        graph.write_bytes(("stub graph " + language + " " + str(len(files))).encode())
        self.graphs += 1
        census = {
            "files": str(len(files)),
            "methods": str(max(1, 10 * len(files))),
            "calls": "1",
            "file_names": files,
            "overlays": "dataflowOss",
        }

        def run(kind: str, params: Mapping[str, object]) -> object:
            if kind == "census":
                return dict(census)
            answer = batch(kind, {"one": params})
            return answer.get("one") if answer else None

        def batch(kind: str, requests: Mapping[str, Mapping[str, object]]) -> dict[str, list[object]]:
            answers: dict[str, list[object]] = {"__census__": [dict(census)]}
            timing = []
            for rid in requests:
                self.asked += 1
                rows = self.templates[self.asked % len(self.templates)] if kind == "taint" else [{"kind": "context_summary"}]
                answers[rid] = list(rows)
                timing.append({"id": rid, "ms": 1.0})
            answers[TIMING] = timing  # type: ignore[assignment]
            return answers

        return CpgResult(cpg_path=graph, run=run, run_batch=batch, run_batch_once=batch, execution_diagnostics=lambda: ())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--rows", type=Path, action="append", required=True, help="recorded engine rows, {id: rows}")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--deadline", type=float, default=3600.0)
    parser.add_argument("--max-regions", type=int, default=500)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    templates = [rows for path in args.rows for rows in json.loads(path.read_text()).values() if isinstance(rows, list)]
    if not templates:
        raise SystemExit("no recorded rows: the stub would answer nothing and measure nothing")
    print(f"{len(templates)} recorded answers from {len(args.rows)} file(s)", flush=True)
    profiling.start(str(args.out / "profile.txt"), flush=10.0)
    engine = StubEngine(templates)
    started = time.monotonic()
    delivery = replay(
        args.repository,
        base=args.base,
        head=args.head,
        artifact=args.out / "artifact.json",
        config=PushConfig(deadline_seconds=args.deadline, cancellation_allowance_seconds=2.0),
        backend=engine,
        max_regions=args.max_regions,
        cache_dir=args.out / "cache",
    )
    elapsed = time.monotonic() - started
    artifact = json.loads((args.out / "artifact.json").read_text()) if (args.out / "artifact.json").is_file() else {}
    timings = {k: round(v, 1) for k, v in artifact.get("timings", {}).items() if k.endswith("_seconds")}
    questions = sum(len(s["scan"]["question_outcomes"]) for s in artifact.get("scans", []))
    summary = {
        "elapsed": round(elapsed, 1),
        "graphs": engine.graphs,
        "requests_answered": engine.asked,
        "questions": questions,
        "timings": timings,
    }
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary), flush=True)
    print(delivery.terminal if hasattr(delivery, "terminal") else "", flush=True)
    if not engine.asked or not questions:
        raise SystemExit("the instrument did not exercise the push path: nothing was asked or no question was recorded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
