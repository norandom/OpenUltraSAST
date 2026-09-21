"""What a repository calls that the ontology does not model (contributor-scan 7.1).

Five of seven families established nothing in the 2026-09 family census, and every one of them failed for an
ontology reason rather than an analysis one: the flow engine was ready and had nothing to aim at. Each gap
was found by investigating one family at a time, over days. This asks the question once.

What it produces is a CANDIDATE LIST. A name here becomes a fact only when someone resolves it to a library
API, states the weakness class and records provenance -- the ontology describes libraries, frameworks and
language constructs, never repositories, and adding a name because a subject called it is how a
general-purpose tool becomes a fixture of its own benchmark.
"""

from __future__ import annotations

import argparse
import collections
import json
import time
from pathlib import Path
from typing import Any

from openultrasast.cpg.backend import JoernBackend
from openultrasast.model.contracts import ExecutionBudget
from openultrasast.model.specs import config_specs, dominance_specs, taint_specs
from openultrasast.preprocess import enumerate_source_files


def modelled_tokens(language: str) -> dict[str, tuple[str, ...]]:
    """Every token any fact table names for this language, by the role it plays.

    Read from the specs rather than from the TOML, so the instrument measures what the analyser actually
    consults: a fact the loader drops is not part of the ontology however neatly it is written.
    """
    roles: dict[str, set[str]] = collections.defaultdict(set)
    for family, spec in taint_specs(language=language).items():
        roles[f"sink:{family}"].update(spec.sinks)
        roles["source"].update(spec.sources)
        roles["sanitizer"].update(spec.sanitizers)
        roles["sanitizer"].update(spec.safe_shape_sinks)
    for spec in dominance_specs(language=language).values():
        roles["operation"].update(spec.operations)
        roles["discharger"].update(spec.dischargers)
    for spec in config_specs(language=language).values():
        roles["setting"].update(spec.settings)
    return {role: tuple(sorted(tokens)) for role, tokens in roles.items()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--language", required=True)
    parser.add_argument("--deadline", type=float, default=1800.0)
    parser.add_argument("--top", type=int, default=60, help="how many unmodelled candidates to record")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    roles = modelled_tokens(args.language)
    every = sorted({token for tokens in roles.values() for token in tokens})
    record: dict[str, Any] = {
        "schema_version": 1,
        "experiment": "ontology-coverage-v1",
        "subject": args.name,
        "language": args.language,
        "root": str(args.root),
        "claim_scope": (
            "A candidate list, not an ontology. A name here is a lead to a library API; it becomes a fact "
            "only with a weakness class and provenance."
        ),
        "ontology_size": {role: len(tokens) for role, tokens in sorted(roles.items())},
    }
    target = args.out / f"{args.name}-{args.language}.json"

    def save() -> None:
        target.write_text(json.dumps(record, indent=2, default=str) + "\n")

    files = enumerate_source_files(args.root)
    record["inputs"] = {"files": len(files), "bytes": sum(p.stat().st_size for p in files if p.is_file())}
    save()
    if not files:
        record["error"] = "no readable source"
        save()
        return 2

    started = time.monotonic()
    budget = ExecutionBudget(started + args.deadline, 5.0)
    backend = JoernBackend(execution_budget=budget)
    graph = backend.build(args.root, language=args.language, execution_budget=budget)
    if graph is None:
        record["error"] = f"graph build failed: {backend.last_failure}"
        save()
        return 3

    rows = backend.query(
        graph.cpg_path,
        "vocabulary",
        {"modelled": ",".join(every), "sources": ",".join(roles.get("source", ()))},
    )
    record["seconds"] = round(time.monotonic() - started, 1)
    if not isinstance(rows, list):
        record["error"] = "the vocabulary query did not answer"
        save()
        return 4

    known = [r for r in rows if isinstance(r, dict) and r.get("modelled")]
    unknown = [r for r in rows if isinstance(r, dict) and not r.get("modelled")]
    calls_total = sum(int(r.get("count", 0)) for r in rows if isinstance(r, dict))
    record["coverage"] = {
        "distinct_call_names": len(rows),
        "calls_total": calls_total,
        "modelled_names": len(known),
        "modelled_calls": sum(int(r.get("count", 0)) for r in known),
        # The share of CALLS, not of names: one name called four hundred times matters more than four
        # hundred called once, and a name count would flatter the ontology.
        "modelled_call_share": round(sum(int(r.get("count", 0)) for r in known) / calls_total, 3) if calls_total else 0.0,
    }
    record["modelled_seen"] = [{k: r[k] for k in ("name", "count") if k in r} for r in known[: args.top]]
    wanted = ("name", "spelling", "count", "nearSource", "file", "line")
    record["candidates"] = [{k: r[k] for k in wanted if k in r} for r in unknown[: args.top]]
    record["candidates_near_a_source"] = [r for r in record["candidates"] if int(r.get("nearSource", 0)) > 0][:20]
    save()
    cleanup = getattr(graph, "cleanup", None)
    if callable(cleanup):
        cleanup()
    backend.close_session()
    print(json.dumps({"subject": args.name, "language": args.language, "coverage": record["coverage"]}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
