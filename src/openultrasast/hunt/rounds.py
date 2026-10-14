"""Measure proposals through the checkout runner before applying the acceptance rule."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .. import stats
from . import accept, runner
from .ablation import _findings, _write
from .metric import search_outcome
from .propose import Candidate
from .table import FeatureTable


def _fold_changes(pool_manifest: Path, table: FeatureTable, load_changes: Any) -> list[dict]:
    """Resolve folds from table rows, rejecting conflicting change or repository identities."""
    from benchmarks.unseen.replay import load_slice

    runner.refuse_pilot(pool_manifest, pilot_report=False)
    folds: dict[str, tuple[str, int]] = {}
    repo_folds: dict[str, int] = {}
    for row in table.rows:
        key, repo, fold = row["change_id"], row["repo"], row.get("fold")
        if type(fold) is not int or fold < 0:
            raise ValueError("each table row needs a non-negative fold")
        if key in folds and folds[key] != (repo, fold):
            raise ValueError("rows of a change must share repository and fold")
        if repo in repo_folds and repo_folds[repo] != fold:
            raise ValueError("a repository cannot cross folds")
        folds[key], repo_folds[repo] = (repo, fold), fold
    loaded = (load_changes or load_slice)(pool_manifest, "1")
    if len({c["id"] for c in loaded}) != len(loaded):
        raise ValueError("change IDs must be unique")
    selected = []
    for change in loaded:
        if change["id"] not in folds:
            raise ValueError("pool changes must exist in the feature table")
        repo, fold = folds[change["id"]]
        if change["repo"] != repo:
            raise ValueError("pool and table disagree on repository")
        selected.append({**change, "fold": fold})
    return selected


def score_folds(
    program: Any,
    *,
    program_id: str,
    mask: Sequence[str],
    pool_manifest: Path,
    repos: Mapping[str, str],
    table: FeatureTable,
    folds: Sequence[int],
    out_dir: Path,
    lm: Any,
    budget: Mapping[str, float],
    repeats: int = 1,
    load_changes: Any = None,
    tools_for: Any = None,
) -> Path:
    """Run selected folds in repeat directories numbered from zero, with runner resumability.

    The table supplies fold membership; the runner computes inputs at each change's head and
    binds repository tools there. The saved study fixes the sample before any records are written.
    Budget applies to each runner pass, as it does for ablations.
    """
    import dspy

    from .program import repository_tools

    if type(repeats) is not int or repeats < 1:
        raise ValueError("repeats must be a positive integer")
    if not folds or any(type(f) is not int or f < 0 for f in folds) or len(set(folds)) != len(folds):
        raise ValueError("folds must be distinct non-negative integers")
    pool_manifest, out = Path(pool_manifest), Path(out_dir)
    changes = [c for c in _fold_changes(pool_manifest, table, load_changes) if c["fold"] in folds]
    if not changes:
        raise ValueError("selected folds contain no changes")
    study = dict(
        changes=changes,
        repeats=repeats,
        program_id=program_id,
        mask=sorted(set(mask)),
        folds=sorted(folds),
        table_digest=table.digest(),
        pool_digest=hashlib.sha256(pool_manifest.read_bytes()).hexdigest(),
    )
    path = out / "study.json"
    if path.exists() and json.loads(path.read_text()) != study:
        raise ValueError("study differs from the saved fold run")
    if not path.exists() and out.exists() and any(out.iterdir()):
        raise ValueError("cannot adopt records without a saved fold study")
    _write(path, study)
    for repeat in range(repeats):
        with dspy.context(lm=lm, adapter=dspy.ChatAdapter()):
            runner.run(
                pool_manifest,
                repos,
                out / str(repeat),
                program=program,
                program_id=program_id,
                mask=mask,
                only="all",
                pilot_report=False,
                budget=budget,
                load_changes=lambda _path, _slice: changes,
                tools_for=tools_for or repository_tools,
                versions={"dspy": dspy.__version__},
            )
    return out


def _outcome(record: Mapping, change: Mapping, tolerance: int) -> dict:
    """Keep failed, unparsed and absent records as misses, exactly as ablation analysis does."""
    failed = record.get("status") == "instrument_failure"
    parsed = bool(record.get("parse_failed"))
    defects = record.get("push", {}).get("admission", {}).get("defects", [])
    if not record.get("done") or failed or parsed:
        defects = []
    return dict(
        defects=defects,
        hit=search_outcome(change, _findings(defects), tolerance=tolerance).hit,
        instrument_failures=int(failed),
        parse_failures=int(parsed),
        missing_records=int(not record),
    )


def _estimate(rows: list[dict], *, seed: int, resamples: int, stat: Any = None) -> stats.Estimate:
    """Compare candidate minus current while resampling whole repositories."""
    import pandas as pd

    return stats.paired_bootstrap(
        pd.DataFrame(rows, columns=["repo", "a", "b"]), "repo", "a", "b", seed=seed, resamples=resamples, stat=stat
    )


def _families(units: list[dict], arms: Sequence[str]) -> list[str]:
    """Include labelled families and families reported only on ordinary pushes."""
    return sorted(
        {u["change"]["family"] for u in units if u["change"].get("family")}
        | {d["family"] for u in units for arm in arms for d in u[arm]["defects"] if d.get("family")}
    )


def _paired(units: list[dict], family: str | None, *, seed: int, resamples: int) -> tuple[stats.Estimate, stats.Estimate]:
    """Compare hits on labelled positives and family suspicions over every ordinary push."""
    positives = [u for u in units if u["change"]["kind"] == "vulnerability" and (family is None or u["change"].get("family") == family)]
    ordinary = [u for u in units if u["change"]["kind"] == "ordinary"]
    recall = _estimate(
        [dict(repo=u["change"]["repo"], a=int(u["a"]["hit"]), b=int(u["b"]["hit"])) for u in positives], seed=seed, resamples=resamples
    )
    suspicions = _estimate(
        [
            {
                "repo": u["change"]["repo"],
                **{arm: sum(family is None or d.get("family") == family for d in u[arm]["defects"]) for arm in ("a", "b")},
            }
            for u in ordinary
        ],
        seed=seed,
        resamples=resamples,
    )
    return recall, suspicions


def fold_results(
    current_dir: Path, candidate_dir: Path, changes: Sequence[Mapping], *, scope: str, tolerance: int, seed: int, resamples: int = 2000
) -> dict[str, accept.FoldResult]:
    """Return acceptance inputs on (change, repeat) pairs, including missing records as misses.

    Pass the changes for this scope. Saved studies fix the expected repeats; for standalone record
    fixtures, numeric child directories supply repeats. The union keeps an entirely missing arm.
    """
    if scope not in ("compile", "holdout"):
        raise ValueError("scope must be compile or holdout")
    if tolerance < 0 or resamples < 2:
        raise ValueError("tolerance must be non-negative and resamples at least two")
    changes = list(changes)
    if len({c["id"] for c in changes}) != len(changes):
        raise ValueError("change IDs must be unique")
    directories = {"a": Path(current_dir), "b": Path(candidate_dir)}
    studies: dict[str, Any] = {}
    repeats: set[int] = set()
    for arm, directory in directories.items():
        path = directory / "study.json"
        if path.exists():
            study = studies[arm] = json.loads(path.read_text())
            saved = {c["id"]: c for c in study["changes"]}
            if any(c["id"] not in saved or {"fold": saved[c["id"]]["fold"], **c} != saved[c["id"]] for c in changes):
                raise ValueError("analysis changes differ from the saved study")
            repeats.update(range(study["repeats"]))
        elif directory.exists():
            repeats.update(int(p.name) for p in directory.iterdir() if p.is_dir() and p.name.isdecimal())
    if len(studies) == 2 and studies["a"]["repeats"] != studies["b"]["repeats"]:
        raise ValueError("paired studies must have the same repeats")
    units = []
    for change in changes:
        for repeat in sorted(repeats or {0}):
            unit = dict(change=change, repeat=repeat)
            for arm, directory in directories.items():
                path = runner.record_path(directory / str(repeat), change["id"])
                record = json.loads(path.read_text()) if path.exists() else {}
                if record and arm in studies:
                    study = studies[arm]
                    saved_change = next(c for c in study["changes"] if c["id"] == change["id"])
                    if (
                        record.get("id") != change["id"]
                        or record.get("program_id") != study["program_id"]
                        or set(record.get("mask", [])) != set(study["mask"])
                        or record.get("input_digest") != runner.input_digest(saved_change, study["program_id"], study["mask"])
                    ):
                        raise ValueError("record does not match the saved change, program or mask")
                unit[arm] = _outcome(record, change, tolerance)
            units.append(unit)
    return {
        family: accept.FoldResult(scope, family, *_paired(units, None if family == "pooled" else family, seed=seed, resamples=resamples))
        for family in ["pooled", *_families(units, ("a", "b"))]
    }


def _candidate_program(candidate: Candidate, tools_for: Any = None) -> Any:
    """Restore either a one-call program or its tool loop without losing the proposed state."""
    from .program import HuntProgram, program_id, repository_tools

    uses_tools = "hunt.react" in candidate.state
    tools = (tools_for or repository_tools)(Path.cwd()) if uses_tools else ()
    program = HuntProgram(mask=candidate.mask, tools=tools)
    if set(program.dump_state()) != set(candidate.state):
        raise ValueError("unsupported candidate program structure")
    program.load_state(candidate.state)
    if program_id(program, mask=candidate.mask) != candidate.program_id:
        raise ValueError("candidate program ID does not match its saved state")
    return program


def round_trip(
    current: Any,
    candidate: Candidate,
    *,
    current_id: str,
    pool_manifest: Path,
    repos: Mapping[str, str],
    table: FeatureTable,
    compile_folds: Sequence[int],
    holdout_folds: Sequence[int],
    out_dir: Path,
    lm: Any,
    budget: Mapping[str, float],
    rule: accept.Rule,
    repeats: int = 1,
    tolerance: int = 10,
    seed: int = 0,
    resamples: int = 2000,
    load_changes: Any = None,
    tools_for: Any = None,
) -> accept.Decision:
    """Score both programs on both scopes, decide, and retain compile-only rejection history."""
    from .program import program_id

    if not compile_folds or not holdout_folds or set(compile_folds) & set(holdout_folds):
        raise ValueError("compile and holdout folds must be nonempty and disjoint")
    if current_id != program_id(current, mask=candidate.base_mask) or tuple(current.mask) != candidate.base_mask:
        raise ValueError("current program does not match its ID and base mask")
    candidate_program = _candidate_program(candidate, tools_for)
    changes = _fold_changes(Path(pool_manifest), table, load_changes)
    results = {}
    for scope, folds in (("compile", compile_folds), ("holdout", holdout_folds)):
        paths = []
        for arm, program, pid, mask in (
            ("current", current, current_id, candidate.base_mask),
            ("candidate", candidate_program, candidate.program_id, candidate.mask),
        ):
            paths.append(
                score_folds(
                    program,
                    program_id=pid,
                    mask=mask,
                    pool_manifest=pool_manifest,
                    repos=repos,
                    table=table,
                    folds=folds,
                    out_dir=Path(out_dir) / scope / arm,
                    lm=lm,
                    budget=budget,
                    repeats=repeats,
                    load_changes=load_changes,
                    tools_for=tools_for,
                )
            )
        results[scope] = fold_results(
            paths[0], paths[1], [c for c in changes if c["fold"] in folds], scope=scope, tolerance=tolerance, seed=seed, resamples=resamples
        )
    decision = accept.decide(current_id, candidate, results["compile"], results["holdout"], rule)
    if not decision.accepted:
        accept.record_rejection(candidate.out_dir, candidate, decision)
    return decision
