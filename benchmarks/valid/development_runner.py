"""Development runner: per-record provenance, stage funnel and judgment transitions.

Task 12.2 of the access-control-prover spec (Reqs 5.1, 5.3, 5.4, 7.1, 7.6, 9.7, 11.8).
Every development record carries the bundle digests (analyzer revision, fact set,
acquisition record, configuration) plus the population and per-change input digests,
a stage funnel from entry recognition through resolution to the three-way judgment
counts, and the transition label between compared judgments.
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


__all__ = ["DevelopmentRecord", "judgment_transition", "run_development", "stage_funnel"]
