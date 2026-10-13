"""Register paired annotation experiments and report effects without choosing a confidence cut.

Each unit is one change in one repeat. Intervals resample whole repositories. Failed and missing
records remain in the population. Only held-out effects feed the annotation keep/drop rule.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .. import stats
from . import runner
from .features import ENGINEERED, annotations_of, feature_frame
from .metric import search_outcome
from .table import FEATURE_NAMES, FeatureTable, canonical_json


@dataclass(frozen=True)
class Manifest:
    """The choices fixed before a round runs.

    Arms map names to masked input or producer names; full must have an empty mask. Sample holds
    the ordered change IDs and the repeat count. Metric is 'hunt.metric.search_outcome(tolerance=N)'.
    Rule holds version 'keep-drop-v1', optional bootstrap resamples (default 2000), and annotation
    dependencies under needs. Budget (usd, calls) is passed unchanged to each runner invocation.
    Compile and holdout folds must be disjoint. Program ID names the common program before masking.
    """

    table_digest: str
    arms: Mapping[str, list[str]]
    compile_folds: list[int]
    holdout_folds: list[int]
    metric: str
    sample: Mapping[str, Any]
    budget: Mapping[str, float]
    rule: Mapping[str, Any]
    seed: int
    program_id: str


def assign_folds(table: FeatureTable, *, k: int, seed: int) -> FeatureTable:
    """Return a copy with repository-grouped folds; every row of a change stays together."""
    frame = table.to_pandas()
    if frame.empty or frame["repo"].isna().any() or frame["change_id"].isna().any():
        raise ValueError("folds require rows with repository and change IDs")
    if frame.groupby("change_id")["repo"].nunique().gt(1).any():
        raise ValueError("a change cannot belong to multiple repositories")
    result = FeatureTable(table.rows, masked=table.masked)
    for fold, (_, indices) in enumerate(stats.group_folds(frame, "repo", k=k, seed=seed)):
        for index in indices:
            result.rows[index]["fold"] = fold
    return result


def leak_audit(table: FeatureTable) -> Any:
    """Report every engineered column's label separation, scored row count, annotation and note.

    Unscorable columns remain in the report with a null AUC and the reason. This audit drops nothing
    and does not decide whether separation is useful evidence or a leak.
    """
    frame = feature_frame(table)
    if "label" not in frame:
        frame["label"] = None
    report = stats.separation(frame, "label", ENGINEERED)
    report["annotation"] = [ENGINEERED[column][1] for column in report["column"]]
    return report


def manifest_id(manifest: Manifest) -> str:
    """Hash the manifest's canonical JSON, including every registered choice."""
    return hashlib.sha256(canonical_json(asdict(manifest)).encode("utf-8")).hexdigest()


def _validate(manifest: Manifest) -> int:
    from .program import INPUTS

    match = re.fullmatch(r"hunt\.metric\.search_outcome\(tolerance=(\d+)\)", manifest.metric)
    if match is None:
        raise ValueError("metric must name hunt.metric.search_outcome and its non-negative tolerance")
    if "full" not in manifest.arms or manifest.arms["full"]:
        raise ValueError("the full arm must have an empty mask")
    allowed = set(FEATURE_NAMES) | {name for name, _, _ in INPUTS}
    for arm, mask in manifest.arms.items():
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", arm):
            raise ValueError("arm names must be safe directory names")
        if not isinstance(mask, list) or any(name not in allowed for name in mask):
            raise ValueError("mask must contain only annotation inputs or producers")
    folds = manifest.compile_folds + manifest.holdout_folds
    if not manifest.holdout_folds or any(type(fold) is not int or fold < 0 for fold in folds) or len(set(folds)) != len(folds):
        raise ValueError("compile and holdout folds must be disjoint, with a nonempty holdout")
    ids = manifest.sample.get("changes")
    if not isinstance(ids, list) or not ids or any(not isinstance(item, str) or not item for item in ids) or len(set(ids)) != len(ids):
        raise ValueError("sample changes must be an ordered list of unique change IDs")
    if type(manifest.sample.get("repeats")) is not int or manifest.sample["repeats"] < 1:
        raise ValueError("sample repeats must be a positive integer")
    if set(manifest.budget) != {"usd", "calls"} or any(not math.isfinite(v) or v < 0 for v in manifest.budget.values()):
        raise ValueError("budget must have finite non-negative usd and calls bounds")
    if manifest.rule.get("version") != "keep-drop-v1":
        raise ValueError("unsupported decision rule version")
    resamples = manifest.rule.get("resamples", stats.RESAMPLES)
    if type(resamples) is not int or resamples < 2:
        raise ValueError("bootstrap resamples must be an integer of at least two")
    return int(match[1])


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".partial")
    temporary.write_text(canonical_json(value) + "\n", encoding="utf-8")
    temporary.replace(path)


def _registration(manifest: Manifest, out: Path) -> None:
    path = out / "ablation.json"
    if not path.is_file():
        raise ValueError("ablation registration is missing")
    saved = json.loads(path.read_text(encoding="utf-8"))
    if saved != {"manifest": asdict(manifest), "manifest_id": manifest_id(manifest)}:
        raise ValueError("ablation registration does not match the manifest")


def register(manifest: Manifest, out_dir: Path | str) -> Path:
    """Write ablation.json before any run; refuse to replace a different registration or adopt old runs."""
    _validate(manifest)
    out = Path(out_dir)
    path = out / "ablation.json"
    if path.exists():
        _registration(manifest, out)
    else:
        if out.exists() and any(out.iterdir()):
            raise ValueError("registration requires an empty output directory")
        _write(path, {"manifest": asdict(manifest), "manifest_id": manifest_id(manifest)})
    return path


def _population(manifest: Manifest, changes: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    indexed = {change["id"]: dict(change) for change in changes}
    if len(indexed) != len(changes) or set(indexed) != set(manifest.sample["changes"]):
        raise ValueError("changes must match the registered sample exactly")
    selected = [indexed[item] for item in manifest.sample["changes"]]
    repo_folds: dict[str, int] = {}
    for change in selected:
        fold = change.get("fold")
        if type(fold) is not int or fold not in manifest.compile_folds + manifest.holdout_folds:
            raise ValueError("each change needs a registered fold")
        if change["repo"] in repo_folds and repo_folds[change["repo"]] != fold:
            raise ValueError("a repository cannot cross folds")
        repo_folds[change["repo"]] = fold
    return selected


def run(
    manifest: Manifest,
    pool_manifest_path: Path | str,
    repos: Mapping[str, str],
    out_dir: Path | str,
    *,
    program_factory: Any,
    lm: Any,
    repeats: int,
    table: FeatureTable,
    load_changes: Any = None,
    slice_id: str = "1",
    tools_for: Any = None,
) -> dict[str, Any]:
    """Run each arm and repeat on the same registered changes using the existing runner.

    The factory is called with mask= for each arm and repeat. LM is the common DSPy model, or a
    mapping of arm names to identically configured scripted models for deterministic experiments.
    Repeats are numbered from zero. Table supplies the registered digest and change folds; labels
    and verification stay with the runner's scoring data and never become mask names or model inputs.
    The runner owns budget accounting and resumability; its budget applies per arm and repeat.
    """
    import dspy

    from benchmarks.unseen.replay import load_slice

    out = Path(out_dir)
    _registration(manifest, out)
    _validate(manifest)
    if repeats != manifest.sample["repeats"]:
        raise ValueError("repeats do not match registration")
    if table.digest() != manifest.table_digest:
        raise ValueError("table digest does not match registration")
    runner.refuse_pilot(Path(pool_manifest_path), pilot_report=False)
    folds: dict[str, tuple[str, int]] = {}
    for row in table.rows:
        key, value = row["change_id"], (row["repo"], row.get("fold"))
        if key in folds and folds[key] != value:
            raise ValueError("rows of a change must share repository and fold")
        folds[key] = value
    loaded = (load_changes or load_slice)(Path(pool_manifest_path), slice_id)
    indexed = {change["id"]: change for change in loaded}
    selected = []
    for item in manifest.sample["changes"]:
        if item not in indexed or item not in folds or indexed[item]["repo"] != folds[item][0]:
            raise ValueError("registered changes must exist in the pool and feature table")
        selected.append({**indexed[item], "fold": folds[item][1]})
    selected = _population(manifest, selected)
    # Freeze revisions and folds too: resuming a changed pool must not silently replace paired records.
    study = {
        "manifest_id": manifest_id(manifest),
        "pool_digest": hashlib.sha256(Path(pool_manifest_path).read_bytes()).hexdigest(),
        "changes": selected,
    }
    study_path = out / "study.json"
    if study_path.exists() and json.loads(study_path.read_text()) != study:
        raise ValueError("pool or changes differ from the registered run")
    _write(study_path, study)
    _write(out / "leak-audit.json", json.loads(leak_audit(table).to_json(orient="records")))
    if isinstance(lm, Mapping) and set(lm) != set(manifest.arms):
        raise ValueError("scripted models must cover exactly the registered arms")
    for arm, mask in manifest.arms.items():
        for repeat in range(repeats):
            program = program_factory(mask=mask)
            with dspy.context(lm=lm[arm] if isinstance(lm, Mapping) else lm, adapter=dspy.ChatAdapter()):
                runner.run(
                    Path(pool_manifest_path),
                    repos,
                    out / f"{arm}-{repeat}",
                    program=program,
                    program_id=manifest.program_id,
                    mask=mask,
                    budget=manifest.budget,
                    slice_id=slice_id,
                    tools_for=tools_for,
                    load_changes=lambda _path, _slice: selected,
                    versions={"dspy": dspy.__version__},
                )
    return analyse(out, manifest, selected)


def _findings(defects: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [{**defect, "path": path, "line": line} for defect in defects for path, line in defect.get("locations", [])]


def _paired(units: list[dict[str, Any]], a: str, b: str, manifest: Manifest, family: str | None) -> dict[str, Any]:
    import pandas as pd

    positives = [u for u in units if u["change"]["kind"] == "vulnerability" and (family is None or u["change"].get("family") == family)]
    ordinary = [u for u in units if u["change"]["kind"] == "ordinary"]

    def estimate(part: list[dict[str, Any]], metric: str) -> dict[str, Any]:
        def value(unit: dict[str, Any], arm: str) -> int:
            if metric == "hit":
                return int(unit[arm]["hit"])
            return sum(family is None or d.get("family") == family for d in unit[arm]["defects"])

        frame = pd.DataFrame([{"repo": u["change"]["repo"], "a": value(u, a), "b": value(u, b)} for u in part], columns=["repo", "a", "b"])
        return asdict(
            stats.paired_bootstrap(
                frame, "repo", "a", "b", seed=manifest.seed, resamples=manifest.rule.get("resamples", stats.RESAMPLES), alpha=0.05
            )
        )

    return {
        "recall": estimate(positives, "hit"),
        "suspicions_per_push": estimate(ordinary, "suspicions"),
        "mcnemar": asdict(stats.mcnemar_exact([u[a]["hit"] for u in positives], [u[b]["hit"] for u in positives])),
    }


def _arm_summary(units: list[dict[str, Any]], arm: str, tolerance: int) -> dict[str, Any]:
    positives = [u for u in units if u["change"]["kind"] == "vulnerability"]
    ordinary = [u for u in units if u["change"]["kind"] == "ordinary"]
    cuts = sorted(
        {
            d["confidence"]
            for u in units
            for d in u[arm]["defects"]
            if isinstance(d.get("confidence"), int | float) and math.isfinite(d["confidence"])
        },
        reverse=True,
    )
    curve = []
    for cut in cuts:

        def above(unit: dict[str, Any], cut: float = cut) -> list[dict[str, Any]]:
            return [
                d
                for d in unit[arm]["defects"]
                if isinstance(d.get("confidence"), int | float) and math.isfinite(d["confidence"]) and d["confidence"] >= cut
            ]

        hits = sum(search_outcome(u["change"], _findings(above(u)), tolerance=tolerance).hit for u in positives)
        curve.append(
            {
                "confidence": cut,
                "recall": hits / len(positives) if positives else None,
                "suspicions_per_push": sum(len(above(u)) for u in ordinary) / len(ordinary) if ordinary else None,
                "positive_units": len(positives),
                "ordinary_units": len(ordinary),
            }
        )
    return {
        "positive_units": len(positives),
        "ordinary_units": len(ordinary),
        "recall": sum(u[arm]["hit"] for u in positives) / len(positives) if positives else None,
        "suspicions_per_push": sum(len(u[arm]["defects"]) for u in ordinary) / len(ordinary) if ordinary else None,
        **{key: sum(u[arm][key] for u in units) for key in ("instrument_failures", "parse_failures", "missing_records")},
        "unranked_findings": sum(
            not isinstance(d.get("confidence"), int | float) or not math.isfinite(d["confidence"]) for u in units for d in u[arm]["defects"]
        ),
        "curve": curve,
    }


def analyse(out_dir: Path | str, manifest: Manifest, changes: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Report arm-minus-full effects, additions versus baseline, and every reported confidence cut.

    Results contain all, compile and heldout sections, each with pooled and per-family comparisons.
    Ordinary denominators include all ordinary pushes; family reports count only that family's findings.
    Missing, instrument-failed and answer-parse-failed records are misses. An incomplete tool step with
    a valid final answer is still scored. Changes must carry folds, or obtain them from the saved study.
    Analysis, importance and decisions are written beside the registration for the next round.
    """
    out = Path(out_dir)
    _registration(manifest, out)
    tolerance = _validate(manifest)
    study_path = out / "study.json"
    if study_path.exists():
        study = json.loads(study_path.read_text())
        saved = {c["id"]: c for c in study["changes"]}
        changes = [{**c, "fold": c.get("fold", saved.get(c["id"], {}).get("fold"))} for c in changes]
        if study["manifest_id"] != manifest_id(manifest) or {c["id"]: c for c in changes} != saved:
            raise ValueError("analysis changes do not match the saved study")
    changes = _population(manifest, changes)
    units = []
    for change in changes:
        for repeat in range(manifest.sample["repeats"]):
            unit: dict[str, Any] = {"change": change, "repeat": repeat}
            for arm, mask in manifest.arms.items():
                path = runner.record_path(out / f"{arm}-{repeat}", change["id"])
                record = json.loads(path.read_text()) if path.exists() else {}
                if record and (
                    record.get("id") != change["id"]
                    or record.get("program_id") != manifest.program_id
                    or set(record.get("mask", [])) != set(mask)
                    or record.get("input_digest") != runner.input_digest(change, manifest.program_id, mask)
                ):
                    raise ValueError("record does not match the registered change, program or mask")
                failed = record.get("status") == "instrument_failure"
                parsed = bool(record.get("parse_failed"))
                defects = record.get("push", {}).get("admission", {}).get("defects", [])
                if not record.get("done") or failed or parsed:
                    defects = []
                unit[arm] = {
                    "defects": defects,
                    "hit": search_outcome(change, _findings(defects), tolerance=tolerance).hit,
                    "instrument_failures": int(failed),
                    "parse_failures": int(parsed),
                    "missing_records": int(not record),
                }
            units.append(unit)
    families = sorted(
        {c["family"] for c in changes if c.get("family")}
        | {d["family"] for u in units for arm in manifest.arms for d in u[arm]["defects"] if d.get("family")}
    )
    result: dict[str, Any] = {"manifest_id": manifest_id(manifest), "out_dir": str(out.resolve()), "unit": "change, repeat"}
    for scope, folds in (
        ("all", manifest.compile_folds + manifest.holdout_folds),
        ("compile", manifest.compile_folds),
        ("heldout", manifest.holdout_folds),
    ):
        part = [u for u in units if u["change"]["fold"] in folds]

        def comparison(a: str, b: str, part: list[dict[str, Any]] = part) -> dict[str, Any]:
            return {
                "pooled": _paired(part, a, b, manifest, None),
                "families": {family: _paired(part, a, b, manifest, family) for family in families},
            }

        result[scope] = {
            "units": len(part),
            "arms": {arm: _arm_summary(part, arm, tolerance) for arm in manifest.arms},
            "comparisons": {arm: comparison("full", arm) for arm in manifest.arms if arm != "full"},
            "additions": {
                arm: comparison("baseline", arm) for arm in manifest.arms if arm.startswith("with-") and "baseline" in manifest.arms
            },
        }
    from .program import INPUTS

    result["annotations_removed"] = {
        arm: sorted(
            annotations_of(mask) | {name for name, column, _ in INPUTS if name in mask or (column and column.split(".")[1] in mask)}
        )
        for arm, mask in manifest.arms.items()
    }
    result["dry_run"] = sum(c["kind"] == "vulnerability" for c in changes) < 40
    contamination_path = out / "contamination.json"
    if contamination_path.exists():
        contamination = json.loads(contamination_path.read_text(encoding="utf-8"))
        result["contaminated"] = bool(contamination["contaminated"])
        result["contaminating_repositories"] = contamination["repositories"]
        if result["contaminated"]:
            result["excluded_from_gain"] = True
    _write(out / "analysis.json", result)
    table = importance(result, annotations=[name for name, _, _ in INPUTS])
    _write(out / "importance.json", json.loads(table.to_json(orient="records")))
    decisions = decide(table, needs={name: set(deps) for name, deps in manifest.rule.get("needs", {}).items()})
    if result.get("excluded_from_gain"):
        _write(out / "decisions.json", {**decisions, "excluded_from_gain": True})
    return result


def importance(analysis: Mapping[str, Any], *, annotations: Sequence[str]) -> Any:
    """One row per annotation, with held-out removal and addition effects, intervals and unit counts.

    Removal compares without-annotation to full; addition compares with-annotation to baseline.
    Missing arms produce null cells. The output directory is carried as dataframe metadata so decide
    can persist the next round's decisions without requiring another output argument.
    """
    import pandas as pd

    heldout = analysis.get("heldout", {})
    rows = []
    for annotation in annotations:
        row: dict[str, Any] = {"annotation": annotation}
        for prefix, key, arm in (("remove", "comparisons", f"without-{annotation}"), ("add", "additions", f"with-{annotation}")):
            pooled = heldout.get(key, {}).get(arm, {}).get("pooled", {})
            for metric in ("recall", "suspicions_per_push"):
                effect = pooled.get(metric, {})
                column = f"{prefix}_{metric}"
                row[column] = effect.get("diff")
                row[column + "_ci"] = effect.get("ci")
                row[column + "_units"] = effect.get("units")
                row[column + "_groups"] = effect.get("groups")
        rows.append(row)
    table = pd.DataFrame(rows)
    table.attrs.update(scope="heldout", out_dir=analysis.get("out_dir"))
    return table


def decide(importance_table: Any, *, needs: Mapping[str, set[str]]) -> dict[str, dict[str, str]]:
    """Keep held-out benefits and their neutral dependencies; drop unsupported or noisy annotations.

    Removal must lower recall or raise suspicions with an interval excluding zero to show benefit.
    Removal that lowers suspicions while recall includes zero shows noise. Neutral dependencies are
    kept transitively from a kept annotation; dependency cycles cannot keep themselves alive.
    Missing evidence never establishes benefit. Decisions are saved when the table carries out_dir.
    """
    if importance_table.attrs.get("scope") != "heldout":
        raise ValueError("decisions require held-out importance effects")
    decisions: dict[str, dict[str, str]] = {}
    neutral = set()

    def interval(value: Any) -> tuple[float, float] | None:
        if isinstance(value, (tuple, list)) and len(value) == 2 and all(isinstance(v, int | float) and math.isfinite(v) for v in value):
            return tuple(value)
        return None

    for row in importance_table.to_dict(orient="records"):
        name = row["annotation"]
        recall, suspicions = interval(row["remove_recall_ci"]), interval(row["remove_suspicions_per_push_ci"])
        if recall and recall[1] < 0:
            decisions[name] = {"decision": "keep", "reason": "removal lowers recall"}
        elif suspicions and suspicions[0] > 0:
            decisions[name] = {"decision": "keep", "reason": "removal raises suspicions"}
        elif suspicions and suspicions[1] < 0 and recall and recall[0] <= 0 <= recall[1]:
            decisions[name] = {"decision": "drop", "reason": "raises suspicions without recall"}
        else:
            decisions[name] = {
                "decision": "drop",
                "reason": "no measurable effect" if recall and suspicions else "missing held-out effects",
            }
            if recall and suspicions and recall[0] <= 0 <= recall[1] and suspicions[0] <= 0 <= suspicions[1]:
                neutral.add(name)
    changed = True
    while changed:
        changed = False
        for name, decision in decisions.items():
            if decision["decision"] != "keep":
                continue
            for dependency in sorted(needs.get(name, set()) & neutral):
                if decisions[dependency]["decision"] != "keep":
                    decisions[dependency] = {"decision": "keep", "reason": f"needed by {name}"}
                    changed = True
    if importance_table.attrs.get("out_dir"):
        _write(Path(importance_table.attrs["out_dir"]) / "decisions.json", decisions)
    return decisions
