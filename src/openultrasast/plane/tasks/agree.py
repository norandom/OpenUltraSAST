"""`agree` task (ai-service-plane task 6): agreement across two `verify` passes, no model calls.

The rule is `verify_batched.agreement`: a candidate is reported when every pass flagged it; a candidate flagged
by one pass is `disputed`. Beside the verdicts go the measurement's numbers: per-candidate cost (a hunt's usd
split evenly over the candidates it asked about, summed over the passes), tool turns per hunt, and -- when the
case's declared sites are given -- the site match by `benchmarks/independent/evaluate.matches_v2`, the rule
protocol v2 scores by, imported from the benchmark tree rather than copied.

Env contract: `OUSAST_INPUT_PASS_A`, `OUSAST_INPUT_PASS_B` (a verify output directory or its `units.jsonl`),
`OUSAST_INPUT_CANDIDATES`, `OUSAST_OUTPUT_DIR`, optional `OUSAST_INPUT_SITES` (a JSON case record with `family`
and `sites` in the `population-v2.toml` shape, or that TOML itself with `OUSAST_CASE_ID` naming the case) and
`OUSAST_BENCHMARKS_DIR` (where `independent/evaluate.py` lives when the package is not run from the repository).
Writes `agreed.json`, `disputed.json`, `summary.json`. Exit 0 done, 2 failed, 3 unfinished.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tomllib
import traceback
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from .verify import EXIT_CODES, USAGE_FIELDS, load_candidates, read_units

Matcher = Callable[[dict[str, Any], dict[str, Any], dict[str, list[tuple[int, int]]]], bool]


def agreement(passes: Sequence[Sequence[Mapping[str, Any]]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(agreed, disputed): flagged in every pass vs in some; the rule of `verify_batched.agreement`."""
    if not passes:
        return [], []
    by_pass = [{str(r["candidate"]): dict(r) for r in flagged} for flagged in passes]
    every = set.intersection(*(set(b) for b in by_pass))
    some = set.union(*(set(b) for b in by_pass))
    first = by_pass[0]
    pick = lambda c: next(b[c] for b in by_pass if c in b)  # noqa: E731
    return [dict(first[c], passes=len(by_pass)) for c in sorted(every)], [
        dict(pick(c), passes=sum(c in b for b in by_pass)) for c in sorted(some - every)
    ]


def load_pass(source: Path) -> list[dict[str, Any]]:
    """The finished unit rows of one verify pass (a directory holding `units.jsonl`, or the file itself)."""
    log = source / "units.jsonl" if source.is_dir() else source
    return [r for r in read_units(log) if "error" not in r and "flagged" in r]


def load_sites(path: Path | None, case_id: str | None) -> dict[str, Any] | None:
    """A case record with `family`, `sites` and optional `ranges` (`{path: [[first, last], ...]}`)."""
    if path is None:
        return None
    if path.suffix == ".toml":
        cases = tomllib.loads(path.read_text()).get("case", [])
        found = [c for c in cases if not case_id or c.get("id") == case_id]
        if len(found) != 1:
            raise ValueError(f"{path}: {len(found)} cases match id {case_id!r}; set OUSAST_CASE_ID")
        return dict(found[0])
    record = json.loads(path.read_text())
    if not isinstance(record, dict):
        raise ValueError(f"{path}: a case record (object with family and sites) was expected")
    return record


def load_matcher(benchmarks_dir: Path | None = None) -> Matcher | None:
    """`evaluate.matches_v2` from the benchmark tree, loaded by file so the package never imports it by name;
    None when the tree is not present (site matching is then reported as not assessed, never as a miss)."""
    roots = [benchmarks_dir] if benchmarks_dir is not None else []
    roots += [p / "benchmarks" for p in (Path.cwd(), *Path(__file__).resolve().parents)]
    for root in roots:
        script = root / "independent" / "evaluate.py"
        if script.is_file():
            spec = importlib.util.spec_from_file_location("ousast_benchmark_evaluate", script)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            matcher: Matcher = module.matches_v2
            return matcher
    return None


def _per_candidate_cost(rows: Sequence[Mapping[str, Any]]) -> tuple[dict[str, float | None], dict[str, int]]:
    """A hunt's usd split evenly over its candidates; its turns and calls counted once per candidate."""
    usd: dict[str, float | None] = {}
    turns: dict[str, int] = {}
    for row in rows:
        names = [f"{row['path']}::{c[1]}" for c in row.get("candidates", [])]
        share = None if row.get("usd") is None or not names else float(row["usd"]) / len(names)
        for name in names:
            usd[name] = None if share is None or usd.get(name, 0.0) is None else (usd.get(name) or 0.0) + share
            turns[name] = turns.get(name, 0) + int(row.get("turns") or 0)
    return usd, turns


def _mean(values: Sequence[float]) -> float | None:
    return round(sum(values) / len(values), 3) if values else None


def run(
    output_dir: Path,
    candidates: object,
    pass_a: Sequence[Mapping[str, Any]],
    pass_b: Sequence[Mapping[str, Any]],
    *,
    sites: Mapping[str, Any] | None = None,
    matcher: Matcher | None = None,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    family, unique = load_candidates(candidates)
    names = [f"{p}::{fn}" for p, fn, _ in unique]
    lines = {f"{p}::{fn}": ln for p, fn, ln in unique}
    asked = [{f"{r['path']}::{c[1]}" for r in rows for c in r.get("candidates", [])} for rows in (pass_a, pass_b)]
    flagged = [{str(f["candidate"]): dict(f) for r in rows for f in r.get("flagged", [])} for rows in (pass_a, pass_b)]
    agreed, disputed = agreement([list(flagged[0].values()), list(flagged[1].values())])
    usd_by, turns_by = _per_candidate_cost([*pass_a, *pass_b])
    case = dict(sites) if sites else None
    if case is not None and "family" not in case and family:
        case["family"] = family
    ranges = {p: [(int(a), int(b)) for a, b in spans] for p, spans in (case or {}).get("ranges", {}).items()}
    match_state = (
        "not assessed: no sites given" if case is None else ("not assessed: evaluate.py not found" if matcher is None else "assessed")
    )
    rows: list[dict[str, Any]] = []
    for name in names:
        in_a, in_b = (name in flagged[0] if name in asked[0] else None), (name in flagged[1] if name in asked[1] else None)
        finding = flagged[0].get(name) or flagged[1].get(name)
        site = finding["site"] if finding else f"{name.partition('::')[0]}:{lines[name]}:{name.partition('::')[2]}"
        site_match = None
        if case is not None and matcher is not None:
            site_match = matcher({"site": site, "family": (finding or {}).get("family", family)}, case, ranges)
        cost = usd_by.get(name)
        rows.append({
            "candidate": name, "site": site, "a": in_a, "b": in_b, "agreed": bool(in_a and in_b), "disputed": bool(in_a) != bool(in_b),
            "site_match": site_match, "usd": (None if cost is None else round(cost, 6)), "turns": turns_by.get(name, 0), "finding": finding,
        })  # fmt: skip
    unasked = [r["candidate"] for r in rows if r["a"] is None or r["b"] is None]
    declared = [r for r in rows if r["site_match"]]
    hunts = [*pass_a, *pass_b]
    usd_total = None if any(r.get("usd") is None for r in hunts) else round(sum(float(r["usd"]) for r in hunts), 6)
    metrics = {
        "candidates": len(names), "asked_in_both": len(names) - len(unasked), "flagged_a": len(flagged[0]), "flagged_b": len(flagged[1]),
        "agreed": len(agreed), "disputed": len(disputed), "hunts": len(hunts),
        "declared_sites": len(set((case or {}).get("sites", []))), "declared_sites_matched": len(declared),
        "declared_sites_matched_agreed": sum(1 for r in declared if r["agreed"]), "site_matching": match_state,
        "usd_total": usd_total, "cost_per_candidate": (None if usd_total is None or not names else round(usd_total / len(names), 6)),
        "turns_per_hunt": _mean([float(r.get("turns") or 0) for r in hunts]),
        "calls_per_hunt": _mean([float((r.get("usage") or {}).get("calls") or 0) for r in hunts]),
    }  # fmt: skip
    (output_dir / "agreed.json").write_text(
        json.dumps({"family": family, "candidates": rows, "agreed": agreed, "disputed": disputed, "metrics": metrics}, indent=1) + "\n"
    )
    (output_dir / "disputed.json").write_text(json.dumps(disputed, indent=1) + "\n")
    summary: dict[str, Any] = {
        "status": "done" if not unasked else "unfinished", "units_done": len(names) - len(unasked), "units_total": len(names),
        "usd": 0, "calls": 0, "usage": dict.fromkeys(USAGE_FIELDS, 0), "priced": True, "model": None, "pass": None, "metrics": metrics,
    }  # fmt: skip
    if unasked:
        summary["reason"] = f"{len(unasked)} candidates not answered by both passes: {unasked[:5]}"
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    return summary


def main() -> int:
    output_dir = Path(os.environ["OUSAST_OUTPUT_DIR"]) if os.environ.get("OUSAST_OUTPUT_DIR") else None
    try:
        if output_dir is None:
            raise ValueError("OUSAST_OUTPUT_DIR is not set")
        pass_a, pass_b = (load_pass(Path(os.environ[name])) for name in ("OUSAST_INPUT_PASS_A", "OUSAST_INPUT_PASS_B"))
        candidates = json.loads(Path(os.environ["OUSAST_INPUT_CANDIDATES"]).read_text())
        sites_path = Path(os.environ["OUSAST_INPUT_SITES"]) if os.environ.get("OUSAST_INPUT_SITES") else None
        sites = load_sites(sites_path, os.environ.get("OUSAST_CASE_ID"))
        benchmarks = Path(os.environ["OUSAST_BENCHMARKS_DIR"]) if os.environ.get("OUSAST_BENCHMARKS_DIR") else None
        summary = run(output_dir, candidates, pass_a, pass_b, sites=sites, matcher=load_matcher(benchmarks) if sites else None)
    except Exception:  # noqa: BLE001 -- a crash is `failed` with its traceback
        summary = {
            "status": "failed", "units_done": 0, "units_total": 0, "usd": 0, "calls": 0, "usage": dict.fromkeys(USAGE_FIELDS, 0),
            "priced": True, "model": None, "pass": None, "reason": traceback.format_exc()[-2000:],
        }  # fmt: skip
        if output_dir is not None:
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps({k: summary.get(k) for k in ("status", "units_done", "units_total", "metrics")}), file=sys.stderr)
    return EXIT_CODES.get(str(summary["status"]), 2)


__all__ = ["agreement", "load_matcher", "load_pass", "load_sites", "main", "run"]


if __name__ == "__main__":
    raise SystemExit(main())
