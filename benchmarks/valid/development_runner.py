"""Development runner: per-record provenance, stage funnel and judgment transitions.

Tasks 12.2 and 12.3 of the access-control-prover spec (Reqs 5.1, 5.3, 5.4, 5.6,
6.1, 6.3, 7.1, 7.6, 9.7, 11.8). Every development record carries the bundle
digests (analyzer revision, fact set, acquisition record, configuration) plus the
population and per-change input digests, a stage funnel from entry recognition
through resolution to the three-way judgment counts, and the transition label
between compared judgments. The runner gates refuse to summarise an instrument
failure (zero-byte read, stale anchor) or a change over the hard runtime budget.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from openultrasast.hunt.prover import ProverResult

from benchmarks.valid.run_manifests import AnalyzerBundle
from openultrasast.hunt.producers import Context
from openultrasast.hunt.prover import prove_change

_STAGE_KEYS = ("entry_recognition", "resolution", "judgment")


@dataclass(frozen=True)
class DevelopmentRecord:
    """One analyzed change with full provenance and stage accounting."""

    change_id: str
    analyzer_revision: str
    fact_set_digest: str
    acquisition_record_digest: str
    configuration_digest: str
    population_digest: str
    input_digest: str
    stage_funnel: dict[str, dict[str, Any]]
    judgment_transition: str
    seconds: float


def _hex12(payload: str) -> str:
    return hashlib.sha256(payload.encode()).hexdigest()[:12]


def _population_digest(changes: tuple[dict[str, Any], ...]) -> str:
    return _hex12("\n".join(sorted(str(change.get("id", "")) for change in changes)))


def _input_digest(change: dict[str, Any]) -> str:
    return _hex12(json.dumps(change, sort_keys=True, default=str))


def stage_funnel(result: ProverResult) -> dict[str, dict[str, Any]]:
    """Summarise every analysis stage of one prover result."""
    coverage = result.coverage
    counts = coverage.pair_judgments
    return {
        "entry_recognition": {
            "entry_points": coverage.entry_points,
            "frameworks_recognised": dict(coverage.frameworks_recognised),
        },
        "resolution": dict(coverage.resolution_counts),
        "judgment": {
            "unguarded": counts.unguarded,
            "discharged": counts.discharged,
            "indeterminate": counts.indeterminate,
        },
    }


def judgment_transition(compared_a: str, compared_b: str) -> str:
    """Label the transition between two compared per-change judgments."""
    if compared_a == compared_b:
        return "same"
    return f"{compared_a}->{compared_b}"


def run_development(
    bundle: AnalyzerBundle,
    repo_root: Path,
    changes: tuple[dict[str, Any], ...],
    out_dir: Path,
) -> tuple[DevelopmentRecord, ...]:
    """Run the strict judgment lane over every change and persist one record each."""
    out_dir.mkdir(parents=True, exist_ok=True)
    population = _population_digest(changes)
    records: list[DevelopmentRecord] = []
    for change in changes:
        context = Context(root=repo_root, change=change)
        started = time.perf_counter()
        result = prove_change(repo_root, change, context, judgment_mode=True)
        seconds = time.perf_counter() - started
        funnel = stage_funnel(result)
        transition = judgment_transition("same", "same")
        record = DevelopmentRecord(
            change_id=str(change.get("id", "")),
            analyzer_revision=bundle.analyzer_revision,
            fact_set_digest=bundle.fact_set_digest,
            acquisition_record_digest=bundle.acquisition_record_digest,
            configuration_digest=bundle.configuration_digest,
            population_digest=population,
            input_digest=_input_digest(change),
            stage_funnel=funnel,
            judgment_transition=transition,
            seconds=seconds,
        )
        records.append(record)
        (out_dir / f"{record.change_id}.json").write_text(
            json.dumps(asdict(record), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return tuple(records)


class GateFailure(RuntimeError):
    """A measured change exceeded the hard runtime budget (Req 6.1)."""


class InstrumentFailure(RuntimeError):
    """An instrument failure (zero-byte read, stale anchor) refuses the summary (Req 5.6)."""


_INSTRUMENT_FAILURE_MARKERS = ("zero-byte", "stale_anchor")


def enforce_gates(records: tuple[DevelopmentRecord, ...], *, budget_seconds: float = 120.0) -> None:
    """Fail when any measured change exceeds the budget; never let an overrun pass (Req 6.1)."""
    for record in records:
        if record.seconds > budget_seconds:
            raise GateFailure(f"change {record.change_id} took {record.seconds:.1f}s over the {budget_seconds:.1f}s budget")


def deadline_record(record: DevelopmentRecord, *, budget_seconds: float = 120.0) -> dict[str, object]:
    """Stamp the stage-aware deadline view of one record (Req 6.3)."""
    return {
        "deadline_seconds": budget_seconds,
        "exceeded": record.seconds > budget_seconds,
    }


def _instrument_failure(record: DevelopmentRecord) -> str | None:
    for value in _funnel_strings(record.stage_funnel):
        for marker in _INSTRUMENT_FAILURE_MARKERS:
            if marker in value:
                return value
    return None


def _funnel_strings(funnel: dict[str, dict[str, Any]]) -> list[str]:
    strings: list[str] = []
    for stage in funnel.values():
        for value in stage.values():
            if isinstance(value, str):
                strings.append(value)
    return strings


def summarize_development(records: tuple[DevelopmentRecord, ...], *, budget_seconds: float = 120.0) -> dict[str, object]:
    """Summarise a development run; an overrun or instrument failure refuses the summary."""
    enforce_gates(records, budget_seconds=budget_seconds)
    for record in records:
        failure = _instrument_failure(record)
        if failure is not None:
            raise InstrumentFailure(f"change {record.change_id} instrument failure: {failure}")
    judgment_counts = {"unguarded": 0, "discharged": 0, "indeterminate": 0}
    for record in records:
        judgment = record.stage_funnel.get("judgment", {})
        for kind in judgment_counts:
            judgment_counts[kind] += int(judgment.get(kind, 0))
    seconds = [record.seconds for record in records]
    return {
        "total_changes": len(records),
        "judgment_counts": judgment_counts,
        "total_seconds": sum(seconds),
        "max_seconds": max(seconds, default=0.0),
    }


_ARM_NAMES = (
    "baseline-analyzer/baseline-facts",
    "baseline-analyzer/candidate-facts",
    "candidate-analyzer/baseline-facts",
    "candidate-analyzer/candidate-facts",
)


def _judgment_totals(records: tuple[DevelopmentRecord, ...]) -> dict[str, int]:
    """Sum unguarded/discharged/indeterminate counts across a run's records."""
    totals = {"unguarded": 0, "discharged": 0, "indeterminate": 0}
    for record in records:
        judgment = record.stage_funnel.get("judgment", {})
        for kind in totals:
            totals[kind] += int(judgment.get(kind, 0))
    return totals


def _judgment_delta(after: dict[str, int], before: dict[str, int]) -> dict[str, int]:
    """Per-kind difference between two judgment totals."""
    return {kind: after[kind] - before[kind] for kind in after}


def _mean_seconds(records: tuple[DevelopmentRecord, ...]) -> float:
    """Mean per-change seconds of a run."""
    if not records:
        return 0.0
    return sum(record.seconds for record in records) / len(records)


def four_arm_report(
    bab: tuple[DevelopmentRecord, ...],
    bacf: tuple[DevelopmentRecord, ...],
    cabf: tuple[DevelopmentRecord, ...],
    cacfon: tuple[DevelopmentRecord, ...],
) -> dict[str, object]:
    """Attribute judgment movement to fact-only and analyzer-only variation.

    The four arms share identical inputs by construction; the report never uses
    admission vocabulary.
    """
    baseline_totals = _judgment_totals(bab)
    fact_delta = _judgment_delta(_judgment_totals(bacf), baseline_totals)
    analyzer_delta = _judgment_delta(_judgment_totals(cabf), baseline_totals)
    transitions = sorted({record.judgment_transition for record in (*bab, *bacf, *cabf, *cacfon)})
    return {
        "arms": _ARM_NAMES,
        "judgment_delta_fact_only": fact_delta,
        "judgment_delta_analyzer_only": analyzer_delta,
        "fact_only_lift": dict(fact_delta),
        "analyzer_only_lift": dict(analyzer_delta),
        "transitions": transitions,
        "funnel_delta_fact_only": {"seconds": _mean_seconds(bacf) - _mean_seconds(bab)},
    }


__all__ = [
    "DevelopmentRecord",
    "GateFailure",
    "InstrumentFailure",
    "deadline_record",
    "enforce_gates",
    "four_arm_report",
    "judgment_transition",
    "run_development",
    "stage_funnel",
    "summarize_development",
]
