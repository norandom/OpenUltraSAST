"""Paired scoring and the admission report for the access-control prover arm.

Task 12.6 of the access-control-prover specification (Reqs 5.2, 12.4, 12.5,
12.7, 12.8, 12.9). The scorer consumes a validated admission manifest plus the
judgments measured on its population: it scores paired vulnerable/fixed twins
and reviewed ordinary changes, keeps sample counts and Wilson 95% intervals on
every rate, and returns NO-GO when the budget gate, the instrument gate or any
pre-registered quality criterion fails. Indeterminate pairs are reported as
indeterminate and never converted to clean results; ordinary changes whose
review found a real missing-authorization defect are refused before scoring.
"""

from dataclasses import dataclass
from typing import Any

from benchmarks.unseen import score
from benchmarks.valid.prover_admission import AdmissionManifest

__all__ = ["AdmissionCase", "AdmissionScoringError", "OrdinaryChange", "admission_report"]

_JUDGMENTS = ("unguarded", "discharged", "indeterminate")


class AdmissionScoringError(ValueError):
    """Raised when a population cannot be scored; the message names the reason."""


@dataclass(frozen=True)
class AdmissionCase:
    """One scored vulnerable/fixed twin pair."""

    case_id: str
    vulnerable_judgment: str
    fixed_judgment: str
    location_verified: bool
    seconds: float


@dataclass(frozen=True)
class OrdinaryChange:
    """One reviewed ordinary change forming the false-alarm denominator."""

    change_id: str
    judgment: str
    mislabeled_defect: bool


def _refuse_inputs(
    manifest: AdmissionManifest,
    cases: tuple[AdmissionCase, ...],
    ordinary: tuple[OrdinaryChange, ...],
    coverage: float,
) -> None:
    """Refuse unscorable populations; check order is fixed for determinism."""
    if manifest.population_role != "admission":
        raise AdmissionScoringError(f"population-role: {manifest.population_role} population cannot be used for admission claims")
    for case in cases:
        for side, judgment in (("vulnerable", case.vulnerable_judgment), ("fixed", case.fixed_judgment)):
            if judgment not in _JUDGMENTS:
                raise AdmissionScoringError(f"judgment: {judgment!r} at {case.case_id}/{side}")
    for change in ordinary:
        if change.judgment not in _JUDGMENTS:
            raise AdmissionScoringError(f"judgment: {change.judgment!r} at {change.change_id}")
        if change.mislabeled_defect:
            raise AdmissionScoringError(
                f"mislabeled: ordinary change {change.change_id} contains a real "
                "missing-authorization defect and must be removed or relabelled before scoring"
            )
    if not 0.0 <= coverage <= 1.0:
        raise AdmissionScoringError(f"coverage: {coverage} is outside [0, 1]")


def admission_report(
    manifest: AdmissionManifest,
    cases: tuple[AdmissionCase, ...],
    ordinary: tuple[OrdinaryChange, ...],
    *,
    coverage: float,
    instrument_failures: int = 0,
    budget_seconds: float = 120.0,
    criteria: dict[str, float] | None = None,
) -> dict[str, Any]:
    """Score paired twins and reviewed ordinary changes; return the admission report.

    The report carries every rate with its sample count and Wilson 95% interval
    and a GO/NO-GO decision with the named failed gates.
    """
    _refuse_inputs(manifest, cases, ordinary, coverage)
    detected = tuple(case.vulnerable_judgment == "unguarded" for case in cases)
    pair_correct = tuple(detected[index] and cases[index].fixed_judgment == "discharged" for index in range(len(cases)))
    flagged = tuple(change.judgment == "unguarded" for change in ordinary)
    per_100 = score.rate(flagged)
    scaled = {
        "n": per_100["n"],
        "count": per_100["count"],
        "rate": None if per_100["rate"] is None else per_100["rate"] * 100,
        "wilson95": [None if value is None else value * 100 for value in per_100["wilson95"]],
    }
    side_judgments = [case.vulnerable_judgment for case in cases]
    side_judgments += [case.fixed_judgment for case in cases]
    side_judgments += [change.judgment for change in ordinary]
    pair_correctness = score.rate(list(pair_correct))
    fix_recall = score.rate(list(detected))
    verified_location_recall = score.rate([case.location_verified for case in cases if case.vulnerable_judgment == "unguarded"])
    precision = score.rate([*detected, *(False for _ in range(sum(flagged)))])
    indeterminate_rate = score.rate([judgment == "indeterminate" for judgment in side_judgments])
    report: dict[str, Any] = {
        "manifest": {
            "population_role": manifest.population_role,
            "analyzer_revision": manifest.analyzer_revision,
            "fact_set_digest": manifest.fact_set_digest,
            "acquisition_record_digest": manifest.acquisition_record_digest,
            "configuration_digest": manifest.configuration_digest,
            "population_digest": manifest.population_digest,
        },
        "pairs": {"n": len(cases), "correct": sum(pair_correct)},
        "pair_correctness": pair_correctness,
        "fix_recall": fix_recall,
        "verified_location_recall": verified_location_recall,
        "flagged_ordinary_per_100": scaled,
        "precision": precision,
        "indeterminate_rate": indeterminate_rate,
        "coverage": coverage,
        "runtime": {
            "n": len(cases),
            "mean_seconds": sum(case.seconds for case in cases) / len(cases) if cases else 0.0,
            "max_seconds": max((case.seconds for case in cases), default=0.0),
        },
        "instrument_failures": instrument_failures,
        "families": list(manifest.families),
    }
    failed_gates: list[str] = []
    for case in cases:
        if case.seconds > budget_seconds:
            failed_gates.append(f"budget:{case.case_id}:{case.seconds:g}s>{budget_seconds:g}s")
    if instrument_failures:
        failed_gates.append(f"instrument:{instrument_failures} failures")
    rates: dict[str, dict[str, Any]] = {
        "min_fix_recall": fix_recall,
        "min_pair_correctness": pair_correctness,
        "min_verified_location_recall": verified_location_recall,
        "min_precision": precision,
        "max_flagged_ordinary_per_100": scaled,
        "max_indeterminate_rate": indeterminate_rate,
    }
    for key, threshold in (criteria or {}).items():
        if key not in rates:
            raise AdmissionScoringError(f"criterion: unknown pre-registered criterion {key!r}")
        actual = rates[key]["rate"]
        if actual is None:
            failed_gates.append(f"{key}: not measured (n=0) vs {threshold}")
        elif key.startswith("min_") and actual < threshold:
            failed_gates.append(f"{key}: {actual} < {threshold}")
        elif key.startswith("max_") and actual > threshold:
            failed_gates.append(f"{key}: {actual} > {threshold}")
    report["failed_gates"] = failed_gates
    report["decision"] = "GO" if not failed_gates else "NO-GO"
    return report
