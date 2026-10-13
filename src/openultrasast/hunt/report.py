"""Report one accepted program on the held-out pilot, with instrument proof before scores."""

from __future__ import annotations

import fcntl
import json
import math
import os
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .. import stats
from . import accept, contamination, runner
from .ablation import _arm_summary, _findings, _write
from .metric import search_outcome
from .propose import Candidate
from .rounds import _candidate_program, _estimate, _families, _outcome, _paired


def _reserve(root: Path, program_id: str) -> Path:
    """Reserve a program under a file lock and flush the ledger before starting its run."""
    date = datetime.now(UTC).date().isoformat()
    if not program_id or any(c not in "0123456789abcdef" for c in program_id):
        raise ValueError("program ID must be a hexadecimal content address")
    root.mkdir(parents=True, exist_ok=True)
    directory = root / f"{date}-hunt-gain-{program_id[:12]}"
    with (root / "hunt-pilot-runs.jsonl").open("a+", encoding="utf-8") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        stream.seek(0)
        if any(json.loads(line)["program_id"] == program_id for line in stream if line.strip()):
            raise ValueError("this program ID already has a pilot run")
        directory.mkdir(exist_ok=False)
        stream.write(json.dumps(dict(program_id=program_id, date=date, measurement_directory=str(directory.resolve()))) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    return directory


def _records(directory: Path, changes: Sequence[Mapping]) -> list[dict]:
    """Load benchmark records and retain every expected change, even after a budget stop."""
    from benchmarks.unseen import score

    records = score.load_records(Path(directory)) if (Path(directory) / "inputs.json").exists() else []
    indexed = {r["id"]: r for r in records}
    if len(indexed) != len(records) or set(indexed) - {c["id"] for c in changes}:
        raise ValueError("records do not match the pilot population")
    result = []
    for change in changes:
        record = indexed.get(change["id"], dict(change))
        if any(record.get(key) != change.get(key) for key in ("repo", "base", "head", "kind", "family", "files", "targets")):
            raise ValueError("record describes a different pilot change")
        result.append(record)
    return result


def _instrument(records: Sequence[Mapping]) -> dict:
    """Record changed-file bytes and verified revisions; unreadable and absent changes fail."""
    from benchmarks.unseen import score

    proof = []
    for record in records:
        instrument = record.get("instrument", {})
        sizes = instrument.get("changed_bytes", {})
        failed = not record.get("done") or record.get("status") == "instrument_failure" or score.coverage(record) == "instrument_failure"
        proof.append(
            dict(
                id=record["id"],
                repo=record["repo"],
                base=record["base"],
                head=record["head"],
                base_verified=bool(instrument.get("base_verified")),
                head_verified=bool(instrument.get("head_verified")),
                changed_bytes={f["path"]: sizes.get(f["path"], 0) for f in record.get("files", [])},
                instrument=dict(instrument),
                instrument_failure=failed,
                reason=instrument.get("failure") or ("missing or unreadable record" if failed else None),
            )
        )
    failures = sum(row["instrument_failure"] for row in proof)
    return dict(
        changes=len(proof),
        failures=failures,
        failure_fraction=failures / len(proof) if proof else None,
        valid=bool(proof) and failures / len(proof) <= 0.05,
        records=proof,
    )


def _clean(records: Sequence[Mapping]) -> list[dict]:
    """Remove stale findings on failures while preserving the scorer's coverage checks."""
    from benchmarks.unseen import score

    result = []
    for original in records:
        record = deepcopy(original)
        if not record.get("done") or record.get("status") == "instrument_failure" or score.coverage(record) == "instrument_failure":
            record["status"] = "instrument_failure"
            record.setdefault("instrument", {})["failure"] = "instrument_failure"
        outcome = _outcome(record, record, 10)
        if not record.get("done") or record.get("status") == "instrument_failure" or record.get("parse_failed"):
            record["push"] = {"admission": {"defects": []}, "quick_tier": []}
        else:
            record.setdefault("push", {}).setdefault("admission", {})["defects"] = outcome["defects"]
        result.append(record)
    return result


def _rate(values: list[float], repos: list[str], *, binary: bool = False, scale: float = 1) -> dict:
    """Report a mean with its count and a repository-clustered interval, plus Wilson for proportions."""
    from benchmarks.unseen import score

    interval = score.cluster_interval(list(zip(repos, values, strict=True)), seed=0)
    result = dict(
        rate=scale * sum(values) / len(values) if values else None,
        count=sum(values),
        n=len(values),
        groups=len(set(repos)),
        ci=[scale * v for v in interval] if values else None,
    )
    if binary:
        wilson = stats.wilson(int(sum(values)), len(values))
        result["wilson95"] = [scale * v for v in wilson] if wilson else None
    return result


def _family_records(records: Sequence[Mapping], family: str | None) -> list[dict]:
    """Keep a family's positives and count only its findings over all ordinary pushes."""
    result = []
    for original in records:
        if family is not None and original["kind"] == "vulnerability" and original.get("family") != family:
            continue
        record = deepcopy(original)
        admission = record.setdefault("push", {}).setdefault("admission", {})
        admission["defects"] = [d for d in admission.get("defects", []) if family is None or d.get("family") == family]
        result.append(record)
    return result


def _summaries(records: list[dict], families: list[str]) -> dict:
    """Use the pilot functions for push metrics and the hunt metric for search outcomes."""
    from benchmarks.unseen import score
    from benchmarks.valid import metrics

    summaries = {}
    for family in ["pooled", *families]:
        part = _family_records(records, None if family == "pooled" else family)
        positives = [r for r in part if r["kind"] == "vulnerability"]
        ordinary = [r for r in part if r["kind"] == "ordinary"]
        outcomes = {r["id"]: search_outcome(r, _findings(r.get("push", {}).get("admission", {}).get("defects", []))) for r in part}
        search = dict(
            recall=_rate([int(outcomes[r["id"]].hit) for r in positives], [r["repo"] for r in positives], binary=True),
            suspicions_per_push=_rate([outcomes[r["id"]].suspicions for r in ordinary], [r["repo"] for r in ordinary]),
        )
        # The whole run already passed its instrument gate. The pilot scorer excludes these failures
        # from push denominators, while the search summaries above keep them as misses.
        usable = [r for r in part if score.coverage(r) != "instrument_failure"]
        if usable:
            scored = score.score(metrics.scoring_records(usable))
            push = metrics.summarize(usable, scored=scored)
        else:
            push = {key: score.rate([]) for key in ("recall", "precision", "false_alarms_per_100_pushes")}
        summaries[family] = dict(search=search, push=push)
    return summaries


def _curve(records: list[dict]) -> tuple[list[dict], dict]:
    """Extend ablation confidence cuts with false alarms, intervals and the two gate bounds."""
    from benchmarks.unseen import score

    units = [dict(change=r, after=_outcome(r, r, 10)) for r in records]
    curve = _arm_summary(units, "after", 10)["curve"]
    for point in curve:
        cut = point["confidence"]
        filtered = deepcopy(records)
        for record in filtered:
            defects = record.get("push", {}).get("admission", {}).get("defects", [])
            record.setdefault("push", {}).setdefault("admission", {})["defects"] = [
                d
                for d in defects
                if isinstance(d.get("confidence"), int | float) and math.isfinite(d["confidence"]) and d["confidence"] >= cut
            ]
        positives = [r for r in filtered if r["kind"] == "vulnerability"]
        ordinary = [r for r in filtered if r["kind"] == "ordinary"]
        hits = [int(search_outcome(r, _findings(r["push"]["admission"]["defects"])).hit) for r in positives]
        point["estimates"] = dict(
            recall=_rate(hits, [r["repo"] for r in positives], binary=True),
            suspicions_per_push=_rate([len(r["push"]["admission"]["defects"]) for r in ordinary], [r["repo"] for r in ordinary]),
            false_alarms_per_100_pushes=_rate(
                [int(score.false_alarm(r)) for r in ordinary], [r["repo"] for r in ordinary], binary=True, scale=100
            ),
        )
        point["false_alarms_per_100_pushes"] = point["estimates"]["false_alarms_per_100_pushes"]["rate"]
    high_recall = [p for p in curve if p["recall"] is not None and p["recall"] >= 0.9 and p["false_alarms_per_100_pushes"] is not None]
    low_alarm = [
        p
        for p in curve
        if p["false_alarms_per_100_pushes"] is not None and p["false_alarms_per_100_pushes"] < 10 and p["recall"] is not None
    ]
    return curve, dict(
        false_alarms_at_recall_90=min(high_recall, key=lambda p: p["false_alarms_per_100_pushes"]) if high_recall else None,
        recall_under_10_false_alarms=max(low_alarm, key=lambda p: p["recall"]) if low_alarm else None,
    )


def _precision(column: Any) -> float | None:
    """Reduce paired (correctly flagged, flagged) counts to push precision."""
    flagged = sum(value[1] for value in column)
    return sum(value[0] for value in column) / flagged if flagged else None


def _baseline_comparison(baselines: list[list[dict]], records: list[dict], families: list[str]) -> dict:
    """Pair every baseline repeat with the one accepted run, without inventing new repetitions."""
    from benchmarks.unseen import score
    from benchmarks.valid import metrics

    units = [
        dict(change=after, repeat=repeat, a=_outcome(before, before, 10), b=_outcome(after, after, 10))
        for repeat, baseline in enumerate(baselines)
        for before, after in zip(baseline, records, strict=True)
    ]
    result = {}
    for name in ["pooled", *families]:
        family = None if name == "pooled" else name
        recall, suspicions = _paired(units, family, seed=0, resamples=stats.RESAMPLES)
        positives = [u for u in units if u["change"]["kind"] == "vulnerability" and (family is None or u["change"].get("family") == family)]
        paired = dict(
            search_recall=asdict(recall),
            suspicions_per_push=asdict(suspicions),
            mcnemar=asdict(stats.mcnemar_exact([u["a"]["hit"] for u in positives], [u["b"]["hit"] for u in positives])),
        )
        rows = {"recall": [], "false_alarms_per_100_pushes": [], "precision": []}
        for baseline in baselines:
            before = metrics.scoring_records(_family_records(baseline, family))
            after = metrics.scoring_records(_family_records(records, family))
            for a, b in zip(before, after, strict=True):
                flags = [int(score.false_alarm(r)) for r in (a, b)]
                hits = [int(bool(score.catches(r))) if r["kind"] == "vulnerability" else 0 for r in (a, b)]
                key = "recall" if a["kind"] == "vulnerability" else "false_alarms_per_100_pushes"
                values = hits if key == "recall" else [100 * v for v in flags]
                rows[key].append(dict(repo=a["repo"], a=values[0], b=values[1]))
                rows["precision"].append(dict(repo=a["repo"], a=(hits[0], flags[0]), b=(hits[1], flags[1])))
        for metric, frame in rows.items():
            paired[metric] = asdict(_estimate(frame, seed=0, resamples=stats.RESAMPLES, stat=_precision if metric == "precision" else None))
        for metric in ("recall", "false_alarms_per_100_pushes"):
            paired[metric + "_mcnemar"] = asdict(
                stats.mcnemar_exact([bool(r["a"]) for r in rows[metric]], [bool(r["b"]) for r in rows[metric]])
            )
        result[name] = paired
    return result


def _before(pilot_metrics: Mapping[str, Path]) -> dict:
    """Copy the two recorded metric files unchanged, with their source paths."""
    if set(pilot_metrics) != {"raw", "filtered"}:
        raise ValueError("pilot_metrics must map raw and filtered to their recorded JSON files")
    return {name: dict(source=str(Path(path)), metrics=json.loads(Path(path).read_text())) for name, path in pilot_metrics.items()}


def _format(metric: Mapping | None) -> str:
    """Show the estimate, interval and count together, leaving missing measurements explicit."""
    if not metric or metric.get("rate") is None:
        return "not recorded" if not metric else f"not measured (n={metric.get('n', 0)})"
    intervals = []
    for key, label in (("ci", "cluster 95%"), ("cluster95", "cluster 95%"), ("wilson95", "Wilson 95%")):
        ci = metric.get(key)
        if ci and all(v is not None for v in ci):
            intervals.append(f"{label} {ci[0]:.6g} to {ci[1]:.6g}")
    return f"{metric['rate']:.6g}; {'; '.join(intervals)}; count={metric['count']}, n={metric['n']}"


def _notes(analysis: dict) -> str:
    """Write readable before-and-after tables and the evidence needed to interpret them."""
    lines = ["# Hunter pilot gain", "", f"Program: `{analysis['program_id']}`", ""]
    proof = analysis["instrument"]
    lines += [
        "## Instrument",
        "",
        f"{proof['failures']} instrument failures across {proof['changes']} changes.",
        "Bytes per changed file and verified base and head are in instrument.json.",
        "",
    ]
    if not analysis["valid"]:
        lines += [f"Run invalid: {analysis['reason']}. No performance numbers are quoted.", ""]
    else:
        lines += [
            "## Before and after",
            "",
            "Before values are quoted as recorded; unavailable family or search values are not inferred.",
            "Recall and precision are proportions. False alarms are per 100 ordinary pushes.",
            "Push metrics exclude instrument failures as in the pilot. Search metrics and paired comparisons retain failures as misses.",
            "The confidence curve describes the search output; it does not choose a threshold or change the classifier.",
            "",
            "| Family | Metric | Before raw | Before filtered | After |",
            "|---|---|---|---|---|",
        ]
        for family, summary in analysis["after"].items():
            for stage, key, label in (
                ("search", "recall", "Search recall"),
                ("search", "suspicions_per_push", "Suspicions per ordinary push"),
                ("push", "recall", "Push recall"),
                ("push", "false_alarms_per_100_pushes", "False alarms per 100"),
                ("push", "precision", "Precision"),
            ):
                before = [
                    analysis["before"][name]["metrics"].get(key) if family == "pooled" and stage == "push" else None
                    for name in ("raw", "filtered")
                ]
                lines.append(f"| {family} | {label} | {_format(before[0])} | {_format(before[1])} | {_format(summary[stage][key])} |")
        for name, recorded in analysis["before"].items():
            lines += ["", f"Recorded {name} source: `{recorded['source']}`."]
        if analysis.get("baseline"):
            lines += [
                "",
                "## Baseline repeats",
                "",
                "Each repeat is paired with the single accepted run; intervals resample repositories.",
                "",
                "| Repeat | Family | Metric | Baseline | After |",
                "|---|---|---|---|---|",
            ]
            for repeat, baseline in enumerate(analysis["baseline"]):
                if not baseline["valid"]:
                    lines += [f"Baseline repeat {repeat} is invalid; its performance numbers and paired gain are not quoted."]
                    continue
                for family, summary in baseline["summary"].items():
                    for stage, keys in (
                        ("search", ("recall", "suspicions_per_push")),
                        ("push", ("recall", "false_alarms_per_100_pushes", "precision")),
                    ):
                        for key in keys:
                            lines.append(
                                f"| {repeat} | {family} | {stage} {key} | {_format(summary[stage][key])} | "
                                f"{_format(analysis['after'][family][stage][key])} |"
                            )
            if "paired" in analysis:
                lines += [
                    "",
                    "Paired differences and exact McNemar results:",
                    "",
                    "```json",
                    json.dumps(analysis["paired"], indent=2),
                    "```",
                ]
        lines += ["", "## Workload", ""]
        for name, value in analysis["workload"].items():
            lines.append(f"{name.replace('_', ' ')}: {_format(value)}.")
        lines += ["", "## Gate distance", ""]
        for name, point in analysis["gate_distance"].items():
            label = (
                "Lowest false alarms at recall at least 0.9"
                if name == "false_alarms_at_recall_90"
                else "Highest recall under 10 false alarms per 100"
            )
            lines.append(
                f"{label}: "
                + (
                    "the curve never reaches this gate bound."
                    if point is None
                    else f"recall {_format(point['estimates']['recall'])}; "
                    f"false alarms {_format(point['estimates']['false_alarms_per_100_pushes'])}."
                )
            )
    lines += ["", "## Acceptance comparison", "", "```json", json.dumps(analysis["comparison"], indent=2), "```", ""]
    return "\n".join(lines)


def pilot_gain(
    candidate: Candidate,
    decision: accept.Decision,
    *,
    pilot_manifest: Path,
    repos: Mapping[str, str],
    training_runs: Sequence[Path],
    out_root: Path,
    lm: Any,
    budget: Mapping[str, float],
    baseline_runs: Sequence[Path] = (),
    pilot_metrics: Mapping[str, Path],
    tools_for: Any = None,
    load_changes: Any = None,
) -> dict:
    """Run an accepted program once and write analysis.json, instrument.json and NOTES.md.

    pilot_metrics maps raw and filtered to the original metric JSON files. Baseline runs are
    single-repeat pilot record directories, each paired with this one accepted run. No command
    line scorers or real model clients are constructed here. Budget exhaustion or more than five
    percent instrument failures leaves an invalid measurement without performance numbers.
    """
    import dspy

    from benchmarks.unseen import score
    from benchmarks.unseen.replay import load_slice

    from .program import repository_tools

    if not decision.accepted or decision.comparison.get("candidate_id") != candidate.program_id:
        raise ValueError("pilot gain requires the accepted decision for this candidate")
    training_runs = [Path(p) for p in training_runs]
    if contamination.clean_runs(training_runs) != training_runs:
        raise ValueError("contaminated training runs cannot report pilot gain")
    before = _before(pilot_metrics)
    program = _candidate_program(candidate, tools_for)
    changes = list((load_changes or load_slice)(Path(pilot_manifest), "1"))
    if not changes or len({c["id"] for c in changes}) != len(changes):
        raise ValueError("pilot changes must be nonempty and have unique IDs")
    directory = _reserve(Path(out_root), candidate.program_id)
    with dspy.context(lm=lm, adapter=dspy.ChatAdapter()):
        artifact = runner.run(
            Path(pilot_manifest),
            repos,
            directory / "records",
            program=program,
            program_id=candidate.program_id,
            mask=candidate.mask,
            pilot_report=True,
            only="all",
            budget=budget,
            tools_for=tools_for or repository_tools,
            load_changes=lambda _path, _slice: changes,
            versions={"dspy": dspy.__version__},
        )
    records = _records(directory / "records", changes)
    proof = _instrument(records)
    _write(directory / "instrument.json", proof)
    analysis = dict(
        program_id=candidate.program_id,
        comparison=decision.comparison,
        measurement_directory=directory.name,
        valid=proof["valid"] and artifact is not None,
        instrument={k: v for k, v in proof.items() if k != "records"},
    )
    if not analysis["valid"]:
        analysis["reason"] = "more than 5% instrument failures" if not proof["valid"] else "runner budget exhausted"
    else:
        records = _clean(records)
        # Run the same overall instrument gate and scorer as the pilot before quoting any scores.
        score.score(records)
        families = _families([dict(change=r, after=_outcome(r, r, 10)) for r in records], ("after",))
        baseline_records = [_clean(_records(Path(path), changes)) for path in baseline_runs]
        for baseline in baseline_records:
            families = sorted(set(families) | set(_families([dict(change=r, before=_outcome(r, r, 10)) for r in baseline], ("before",))))
        curve, distance = _curve(records)
        counts = [search_outcome(r, _findings(r["push"]["admission"]["defects"])).suspicions for r in records]
        analysis.update(
            before=before,
            after=_summaries(records, families),
            curve=curve,
            gate_distance=distance,
            workload=dict(
                suspicions_per_100_pushes=_rate(counts, [r["repo"] for r in records], scale=100),
                flagged_pushes_per_100_pushes=_rate([int(n > 0) for n in counts], [r["repo"] for r in records], binary=True, scale=100),
            ),
        )
        if baseline_records:
            analysis["baseline"] = []
            for path, baseline in zip(baseline_runs, baseline_records, strict=True):
                instrument = _instrument(baseline)
                entry = dict(directory=str(path), valid=instrument["valid"], instrument=instrument)
                if entry["valid"]:
                    entry["summary"] = _summaries(baseline, families)
                analysis["baseline"].append(entry)
            if all(row["valid"] for row in analysis["baseline"]):
                analysis["paired"] = _baseline_comparison(baseline_records, records, families)
    # Return the same JSON types that a reader of analysis.json receives.
    analysis = json.loads(json.dumps(analysis))
    _write(directory / "analysis.json", analysis)
    (directory / "NOTES.md").write_text(_notes(analysis), encoding="utf-8")
    return analysis
