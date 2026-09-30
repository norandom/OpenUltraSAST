"""`agree` task (ai-service-plane task 6): agreement across two `verify` passes, no model calls.

The rule is `verify_batched.agreement`: a candidate is reported when every pass flagged it; a candidate flagged
by one pass is `disputed`. Beside the verdicts go the measurement's numbers: per-candidate cost (a hunt's usd
split evenly over the candidates it asked about, summed over the passes), tool turns per hunt, and -- when the
case's declared sites and fix ranges are given -- the site match by :func:`matches_declared`, which is
`benchmarks/independent/evaluate.matches_v2` (the rule protocol v2 and `score_batched.py` score by) reproduced
here so the runner image needs no benchmark tree; `tests/test_plane_scoring_parity.py` proves identical verdicts
on the recorded reference outputs. The ranges are the reference's own (`evaluate.hunks(case, "old")`), resolved
by the generator into `case.json`, and sites are anchored to the candidate as `score_batched.anchored` does.

Cost is reported twice: `cost_per_candidate` is the plane's spend alone; `cost_per_candidate_with_recorded_triage`
adds the recorded triage cost of the case (`case.json` `cost.recorded_triage_usd`), because the reference's
$0.022 per candidate for two passes paid for triage and the plane applies the recorded triage instead. Both
divide by the candidates before triage when `case.json` gives that count, as the reference did.

Env contract: `OUSAST_INPUT_PASS_A`, `OUSAST_INPUT_PASS_B` (a verify output directory or its `units.jsonl`),
`OUSAST_INPUT_CANDIDATES`, `OUSAST_OUTPUT_DIR`, optional `OUSAST_INPUT_SITES` (the generator's `case.json`:
`family`, `sites`, `ranges`, `sites_in_set`, `cost`; or a `population-v2.toml`-shaped TOML with `OUSAST_CASE_ID`
naming the case), optional `OUSAST_INPUT_PASS_C` (the tie-break pass: `verify` restricted to the candidates a and
b disputed). Writes `agreed.json`, `disputed.json`, `summary.json`. Exit 0 done, 2 failed, 3 unfinished.

With pass c the decision is 2 of 3 for every candidate pass c asked about and the a/b rule for the rest, so pass c
alone never decides; `metrics.tiebreak` counts the candidates asked and the decisions that flipped against a/b,
and names the rule. The declared-site metrics and `agreed`/`disputed` are on the final decision; `usd_total`,
`hunts` and the per-hunt means include pass c. Without pass c every number is the two-pass one.
"""

from __future__ import annotations

import json
import os
import sys
import tomllib
import traceback
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .verify import EXIT_CODES, USAGE_FIELDS, load_candidates, read_units

LINE_WINDOW = 10  # evaluate.LINE_WINDOW: a finding within 10 lines of a changed range matches


def matches_declared(finding: Mapping[str, Any], case: Mapping[str, Any], ranges: Mapping[str, Sequence[Sequence[int]]]) -> bool:
    """`evaluate.matches_v2`: the finding's family is the case's, and its `path:line:function` site is a declared
    `path::function`, or lies in a file the fix changed and names a declared site's function or is within
    `LINE_WINDOW` lines of a changed range (`ranges`: the old side of the fix diff, per file)."""
    path, _, rest = str(finding["site"]).partition(":")
    line_text, _, function = rest.partition(":")
    if finding.get("family") != case["family"]:
        return False
    sites = {str(s) for s in case.get("sites", [])}
    if f"{path}::{function}" in sites:
        return True
    if path not in ranges:
        return False
    if function in {site.partition("::")[2] for site in sites}:
        return True
    line = int(line_text) if line_text.isdigit() else -1
    return any(int(first) - LINE_WINDOW <= line <= int(last) + LINE_WINDOW for first, last in ranges[path])


def anchor_site(candidate: str, site: str) -> str:
    """`score_batched.anchored`: the site is the candidate's file and function; the reported line is kept only
    when the site is in the candidate's file (otherwise 0)."""
    path, _, function = candidate.partition("::")
    site_path, _, rest = site.partition(":")
    line = rest.split(":")[0] if site_path == path else "0"
    return f"{path}:{line}:{function}"


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
    """A case record with `family`, `sites` and `ranges` (`{path: [[first, last], ...]}`); without `ranges`
    site matching is reported as not assessed."""
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


def _per_candidate(total: float | None, count: int) -> float | None:
    return None if total is None or not count else round(total / count, 6)


RULE_A_B = "agreed when passes a and b both flagged the candidate (no pass c given)"
RULE_2_OF_3 = (
    "a candidate asked in pass c is agreed when at least 2 of passes a, b, c flagged it; a candidate not asked in "
    "pass c is agreed when passes a and b both flagged it (pass c alone never decides)"
)


def _votes(candidate: str, flagged: Sequence[Mapping[str, Any]]) -> int:
    return sum(candidate in f for f in flagged)


def _pick(candidate: str, flagged: Sequence[Mapping[str, Mapping[str, Any]]]) -> dict[str, Any]:
    return dict(next(f[candidate] for f in flagged if candidate in f))


def _decided(candidate: str, asked_c: set[str], flagged: Sequence[Mapping[str, Any]]) -> bool:
    """The final decision: 2 of 3 when pass c asked the candidate, else both of a and b."""
    if candidate in asked_c:
        return _votes(candidate, flagged) >= 2
    return candidate in flagged[0] and candidate in flagged[1]


def run(
    output_dir: Path,
    candidates: object,
    pass_a: Sequence[Mapping[str, Any]],
    pass_b: Sequence[Mapping[str, Any]],
    *,
    sites: Mapping[str, Any] | None = None,
    pass_c: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    family, unique = load_candidates(candidates)
    names = [f"{p}::{fn}" for p, fn, _ in unique]
    lines = {f"{p}::{fn}": ln for p, fn, ln in unique}
    passes = (pass_a, pass_b, pass_c or [])
    asked = [{f"{r['path']}::{c[1]}" for r in rows for c in r.get("candidates", [])} for rows in passes]
    flagged = [{str(f["candidate"]): dict(f) for r in rows for f in r.get("flagged", [])} for rows in passes]
    ab_agreed, _ = agreement([list(flagged[0].values()), list(flagged[1].values())])
    ab = {str(f["candidate"]) for f in ab_agreed}
    final = {c for c in set(flagged[0]) | set(flagged[1]) | set(flagged[2]) if _decided(c, asked[2], flagged)}
    agreed = [dict(f, passes=_votes(f["candidate"], flagged)) for f in ab_agreed if f["candidate"] in final]
    agreed += [dict(_pick(c, flagged), passes=_votes(c, flagged)) for c in sorted(final - ab)]
    agreed.sort(key=lambda f: str(f["candidate"]))
    some = (set(flagged[0]) | set(flagged[1]) | set(flagged[2])) - final
    disputed = [dict(_pick(c, flagged), passes=_votes(c, flagged)) for c in sorted(some)]
    tiebreak = {
        "asked": len(asked[2]), "flipped_to_agreed": len(final - ab), "flipped_to_rejected": len(ab - final),
        "rule": RULE_2_OF_3 if pass_c is not None else RULE_A_B,
    }  # fmt: skip
    usd_by, turns_by = _per_candidate_cost([*pass_a, *pass_b, *(pass_c or [])])
    case = dict(sites) if sites else None
    if case is not None and "family" not in case and family:
        case["family"] = family
    ranges = (case or {}).get("ranges")
    assessed = case is not None and isinstance(ranges, Mapping)
    match_state = "assessed" if assessed else ("not assessed: no sites given" if case is None else "not assessed: no fix ranges given")
    rows: list[dict[str, Any]] = []
    for name in names:
        in_a, in_b = (name in flagged[0] if name in asked[0] else None), (name in flagged[1] if name in asked[1] else None)
        in_c = name in flagged[2] if name in asked[2] else None
        finding = flagged[0].get(name) or flagged[1].get(name) or flagged[2].get(name)
        site = anchor_site(name, finding["site"]) if finding else f"{name.partition('::')[0]}:{lines[name]}:{name.partition('::')[2]}"
        site_match = None
        if assessed and case is not None and isinstance(ranges, Mapping):
            site_match = matches_declared({"site": site, "family": (finding or {}).get("family", family)}, case, ranges)
        cost = usd_by.get(name)
        rows.append({
            "candidate": name, "site": site, "a": in_a, "b": in_b, "c": in_c, "agreed": name in final, "disputed": bool(in_a) != bool(in_b),
            "site_match": site_match, "usd": (None if cost is None else round(cost, 6)), "turns": turns_by.get(name, 0), "finding": finding,
        })  # fmt: skip
    unasked = [r["candidate"] for r in rows if r["a"] is None or r["b"] is None]
    declared = [r for r in rows if r["site_match"]]
    hunts = [*pass_a, *pass_b, *(pass_c or [])]
    usd_total = None if any(r.get("usd") is None for r in hunts) else round(sum(float(r["usd"]) for r in hunts), 6)
    reference: Mapping[str, Any] = (case or {}).get("cost") or {}
    before = int(reference.get("candidates_before_triage") or len(names))
    triage_usd = float(reference["recorded_triage_usd"]) if reference.get("recorded_triage_usd") is not None else None
    with_triage = None if usd_total is None or triage_usd is None else round(usd_total + triage_usd, 6)
    metrics = {
        "candidates": len(names), "candidates_before_triage": before, "asked_in_both": len(names) - len(unasked),
        "flagged_a": len(flagged[0]), "flagged_b": len(flagged[1]), "agreed": len(agreed), "disputed": len(disputed), "hunts": len(hunts),
        "declared_sites": len(set((case or {}).get("sites", []))),
        "declared_sites_in_set": (len(case["sites_in_set"]) if case and "sites_in_set" in case else None),
        "declared_sites_matched": len(declared), "declared_sites_matched_agreed": sum(1 for r in declared if r["agreed"]),
        "site_matching": match_state,
        "usd_total": usd_total, "cost_per_candidate": _per_candidate(usd_total, before),
        "recorded_triage_usd": triage_usd, "recorded_triage_basis": reference.get("recorded_triage_basis"),
        "usd_total_with_recorded_triage": with_triage, "cost_per_candidate_with_recorded_triage": _per_candidate(with_triage, before),
        "turns_per_hunt": _mean([float(r.get("turns") or 0) for r in hunts]),
        "calls_per_hunt": _mean([float((r.get("usage") or {}).get("calls") or 0) for r in hunts]),
        "tiebreak": tiebreak,
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
        pass_c = load_pass(Path(os.environ["OUSAST_INPUT_PASS_C"])) if os.environ.get("OUSAST_INPUT_PASS_C") else None
        summary = run(output_dir, candidates, pass_a, pass_b, sites=sites, pass_c=pass_c)
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


__all__ = [
    "LINE_WINDOW",
    "RULE_2_OF_3",
    "RULE_A_B",
    "agreement",
    "anchor_site",
    "load_pass",
    "load_sites",
    "main",
    "matches_declared",
    "run",
]


if __name__ == "__main__":
    raise SystemExit(main())
