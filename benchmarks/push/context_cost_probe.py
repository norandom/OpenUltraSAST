"""Time the evidence pass with and without change context, on one graph, from the production request builder.

Named by the 2026-09-23 PHP transfer replay. The push path asks every evidence request for change context
(`contextEvidence`), and on Paid Memberships Pro that pass ran four portions in 13, 31 and 51 minutes each and
exhausted a 7,200 s case, where the census -- the same requests without context -- answers 3,935 in 45 s.

This builds the PHP graph ONCE, takes the first ``--requests`` taint requests exactly as the scan builds them,
and asks them in one invocation per mode. It proves it read its input (files, bytes, graph size, rows) before
reporting a time, and it saves every mode's rows so a change to the query can be checked for IDENTICAL output,
not merely for speed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

from openultrasast.cpg.backend import TIMING, JoernBackend
from openultrasast.mapping import analyze_entry_points
from openultrasast.model.contracts import ChangeContext, ChangedSpan, ExecutionBudget, QuestionIdentity
from openultrasast.model.regions import affected_context, regions_for
from openultrasast.model.scan import _collect, _grouped, _hook_callbacks
from openultrasast.model.shipped import declared_sources
from openultrasast.preprocess import build_file_target, enumerate_source_files


def digest(rows: object) -> str:
    return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()[:16]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--requests", type=int, default=400)
    parser.add_argument("--offsets", default="0", help="comma-separated start positions in the scan's request order")
    parser.add_argument("--modes", default="plain,context")
    parser.add_argument("--changed", default="", help="a changed file, for the `filtered` mode and the equivalence check")
    args = parser.parse_args()

    files = enumerate_source_files(args.root)
    opened = sum(path.stat().st_size for path in files if path.is_file())
    if not files or not opened:
        raise SystemExit(f"probe read nothing under {args.root}: {len(files)} files, {opened} bytes")
    targets = [build_file_target(args.root, path) for path in files]
    found = regions_for(analyze_entry_points(args.root, targets), targets, shipped=declared_sources(args.root))
    regions = [r for r in found if r.language == "php"]
    hooks = _hook_callbacks(args.root, regions)
    taint = _grouped(_collect(regions), hook_callbacks=hooks).get("taint", {})
    ordered = list(taint.items())
    print(f"read {len(files)} files, {opened} bytes; {len(regions)} php regions; {len(taint)} taint requests", flush=True)

    backend = JoernBackend(query_timeout=6 * 3600, execution_budget=ExecutionBudget(time.monotonic() + 8 * 3600, 5.0))
    started = time.monotonic()
    graph = backend.build(args.root, language="php")
    if graph is None:
        raise SystemExit(f"graph build failed: {backend.last_failure}")
    size = graph.cpg_path.stat().st_size
    print(f"graph {size} bytes in {time.monotonic() - started:.1f}s", flush=True)
    if size < 100_000:
        raise SystemExit("graph is implausibly small; not measuring an empty graph")

    record: dict[str, object] = {"files": len(files), "bytes": opened, "graph_bytes": size, "requests": args.requests, "modes": {}}
    answers: dict[str, dict[str, object]] = {}
    slices = [(int(o), dict(ordered[int(o) : int(o) + args.requests])) for o in args.offsets.split(",")]
    for (offset, chosen), mode in [(s, m) for s in slices for m in args.modes.split(",")]:
        mode = f"{mode}@{offset}"
        files_in = sorted({str(p.get("file", "")) for p in chosen.values()})
        print(f"{mode}: {len(chosen)} requests over {len(files_in)} files, first {files_in[:3]}", flush=True)
        extra = {"evidenceOnly": "true", **({"contextEvidence": "true"} if mode.startswith(("context", "filtered")) else {})}
        if mode.startswith("filtered"):
            extra.update({"contextFilter": "true", "contextPaths": args.changed})
        requests = {rid: {**dict(params), **extra} for rid, params in chosen.items()}
        started = time.monotonic()
        answer = backend._batch_once(graph.cpg_path, "taint", requests)
        seconds = time.monotonic() - started
        if answer is None:
            raise SystemExit(f"mode {mode}: engine returned nothing after {seconds:.1f}s ({backend.last_failure})")
        rows = {rid: answer[rid] for rid in requests if rid in answer}
        costs = sorted((entry["ms"] for entry in answer.get(TIMING, []) if isinstance(entry, dict)), reverse=True)
        summary = {
            "seconds": round(seconds, 1),
            "answered": len(rows),
            "rows": sum(len(r) for r in rows.values()),
            "digest": digest(rows),
            "engine_ms_total": round(sum(costs)),
            "engine_ms_top5": costs[:5],
        }
        record["modes"][mode] = summary  # type: ignore[index]
        (args.out.parent / f"{args.out.stem}-{mode}-rows.json").write_text(json.dumps(rows, sort_keys=True))
        print(f"{mode}: {json.dumps(summary)}", flush=True)
        args.out.write_text(json.dumps(record, indent=2) + "\n")
        answers[mode] = rows
    # The equivalence that matters: what `affected_context` decides from each form, for a change to `--changed`.
    for offset, chosen in slices:
        full, filtered = answers.get(f"context@{offset}"), answers.get(f"filtered@{offset}")
        if full is None or filtered is None:
            continue
        lines = sum(1 for _ in (args.root / args.changed).open(errors="replace"))
        change = ChangeContext(
            "base",
            "head",
            (args.changed.encode().hex(),),
            (),
            (ChangedSpan(args.changed.encode().hex(), 1, lines, "head"),),
            (),
            (),
            (),
            (),
            "filesystem-bytes-hex",
            (),
        )
        identities = {rid: QuestionIdentity("unit", "php", str(chosen[rid].get("file", "")), rid, "injection") for rid in chosen}
        decided = [
            affected_context(change, list(identities.values()), {identities[rid]: rows[rid] for rid in rows}, args.root)
            for rows in (full, filtered)
        ]
        same = decided[0] == decided[1]
        record[f"equivalent@{offset}"] = {"identical": same, "relationships": len(decided[0][0].relationships), "gaps": len(decided[0][1])}
        print(f"equivalence@{offset}: {json.dumps(record[f'equivalent@{offset}'])}", flush=True)
        args.out.write_text(json.dumps(record, indent=2) + "\n")
        if not same:
            raise SystemExit("filtered context changed what affected_context decides")
    if graph.cleanup:
        graph.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
