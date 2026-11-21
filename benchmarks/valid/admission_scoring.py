"""Scoring authority for the valid-detection benchmark (task 9.2).

The replacement admission path computes its metrics and gates, validates
cases, proofs, and replays exclusively through the pinned detection-core V3
facade reached via ``benchmarks.valid.core_conformance``; no benchmark-owned
scorer may substitute for that root. The legacy aggregate helpers below are
the frozen access-control prover pilot's paired scorer (task 12.6 of the
access-control-prover specification): they remain available only for
historical V2 replay, never own a replacement decision, and their pooled or
target-specific output is structurally refused as a replacement admission
root before the core boundary is reached.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol, TypeVar

from benchmarks.unseen import score
from benchmarks.valid.core_conformance import decode_scoped_admission_v3, require_scoped_admission_v3
from openultrasast.core import canonical, evaluation_admission
from openultrasast.core.admission_case import AdmissionCaseRelease, AdmissionCaseResult
from openultrasast.core.admission_context import AdmissionValidationContext
from openultrasast.core.admission_report import AdmissionReplay, score_admission, validate_admission_replay
from openultrasast.core.admission_review import AdmissionManifestV2
from openultrasast.core.admission_spend import AdmissionPreparation
from openultrasast.core.custody import PopulationCustodyPort, PopulationUseReceipt
from openultrasast.core.evaluation_authority import EvaluationAdmissionManifestV3, EvaluationPlanManifestV3
from openultrasast.core.evaluation_feasibility import EvaluationFeasibilityV3
from openultrasast.core.evaluation_release import AdmissionCaseReleaseV3, ArmAdmissionCasesV3
from openultrasast.core.evaluation_replay import EvaluationReplayV3
from openultrasast.core.evaluation_report import ArmEvaluationReportV3
from openultrasast.core.evaluation_spend import EvaluationPreparationV3, EvaluationSpendBindingV3
from openultrasast.core.measurement import DenominatorPolicy
from openultrasast.core.readiness import ReadinessResult

__all__ = [
    "AdmissionCase",
    "AdmissionScoringError",
    "OrdinaryChange",
    "ReplacementScoringRefusal",
    "ReplacementScoringRefusalReason",
    "V3_EVALUATION_SCHEMA",
    "admission_report",
    "decode_replacement_root",
    "preflight_replacement_gates",
    "score_replacement_replay",
    "score_v2_admission",
    "validate_replacement_replay",
]

V3_EVALUATION_SCHEMA = "openultrasast.detection-core.evaluation-admission.v3"

_RootT = TypeVar("_RootT")


class ReplacementScoringRefusalReason(StrEnum):
    """Closed reasons a root can be refused on the replacement scoring path."""

    LEGACY_AGGREGATE_ROOT = "legacy_aggregate_root"


class ReplacementScoringRefusal(ValueError):
    """Refuse non-V3 roots on the replacement path with a closed reason."""

    def __init__(self, reason: ReplacementScoringRefusalReason) -> None:
        self.reason = reason
        super().__init__(f"replacement_scoring_{reason.value}")


_LEGACY_AGGREGATE_KEYS = frozenset(
    {
        "fix_recall",
        "flagged_ordinary_per_100",
        "indeterminate_rate",
        "verified_location_recall",
    }
)
_LEGACY_REPORT_SCHEMA_PREFIX = "openultrasast.detection-core.admission-report."


def _is_legacy_aggregate_root(value: Mapping[object, object]) -> bool:
    """True when a mapping carries the legacy aggregate scorer's vocabulary."""
    schema = value.get("schema_version")
    return bool(_LEGACY_AGGREGATE_KEYS & set(value)) or (isinstance(schema, str) and schema.startswith(_LEGACY_REPORT_SCHEMA_PREFIX))


def _carries_legacy_aggregate(value: Mapping[object, object]) -> bool:
    """True when a pooled wrapper carries legacy aggregate output inside it."""
    for item in value.values():
        if isinstance(item, Mapping) and _is_legacy_aggregate_root(item):
            return True
        if isinstance(item, (list, tuple)) and any(isinstance(entry, Mapping) and _is_legacy_aggregate_root(entry) for entry in item):
            return True
    return False


def _refuse_legacy_aggregate_root(value: object) -> None:
    """Refuse legacy aggregate output (flat, target-specific, or pooled) as a replacement root."""
    if not isinstance(value, Mapping):
        return
    if _is_legacy_aggregate_root(value) or _carries_legacy_aggregate(value):
        raise ReplacementScoringRefusal(ReplacementScoringRefusalReason.LEGACY_AGGREGATE_ROOT)


def decode_replacement_root(schema: str, value: object, expected_type: type[_RootT]) -> _RootT:
    """Decode one replacement admission root through the pinned core facade.

    Legacy aggregate scoring output (pooled or target-specific) is refused
    here with a closed reason before the core boundary is reached; only an
    exact V3 root decodes.
    """
    _refuse_legacy_aggregate_root(value)
    return decode_scoped_admission_v3(schema, value, expected_type)


def preflight_replacement_gates(
    plan_manifest: EvaluationPlanManifestV3,
    context: AdmissionValidationContext,
    resolver: canonical.ContentResolver,
) -> EvaluationFeasibilityV3:
    """Derive replacement gate and metric feasibility only through the pinned facade."""
    require_scoped_admission_v3()
    return evaluation_admission.preflight_evaluation(plan_manifest, context, resolver)


def score_replacement_replay(
    admission_manifest: EvaluationAdmissionManifestV3,
    feasibility: EvaluationFeasibilityV3,
    preparation: EvaluationPreparationV3,
    receipt: PopulationUseReceipt,
    spend_binding: EvaluationSpendBindingV3,
    release: AdmissionCaseReleaseV3,
    cases_by_arm: tuple[ArmAdmissionCasesV3, ...],
    readiness: tuple[ReadinessResult, ...],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> EvaluationReplayV3:
    """Replacement metrics, case validation, proof validation, and one replay.

    Every argument is an exact core V3 root and the pinned facade derives all
    metrics, gates, and the complete replay, so no alternative scorer exists
    on this path.
    """
    require_scoped_admission_v3()
    return evaluation_admission.score_and_replay(
        admission_manifest,
        feasibility,
        preparation,
        receipt,
        spend_binding,
        release,
        cases_by_arm,
        readiness,
        context,
        custody,
        resolver,
    )


def validate_replacement_replay(
    replay: EvaluationReplayV3,
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> tuple[ArmEvaluationReportV3, ...]:
    """Validate one complete replacement replay only through the pinned facade."""
    _refuse_legacy_aggregate_root(replay)
    require_scoped_admission_v3()
    return evaluation_admission.validate_evaluation_replay(replay, context, custody, resolver)


# Frozen historical replay helpers (access-control prover pilot, task 12.6).
# These aggregate helpers never authorize replacement admission: any pooled or
# target-specific output they produce is refused at the replacement roots above.

_JUDGMENTS = ("unguarded", "discharged", "indeterminate")


class AdmissionManifest(Protocol):
    """Structural shape used only by the parked legacy scoring helpers."""

    population_role: str
    analyzer_revision: str
    fact_set_digest: str
    acquisition_record_digest: str
    configuration_digest: str
    population_digest: str
    families: tuple[str, ...]


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


def score_v2_admission(
    manifest: AdmissionManifestV2,
    denominator: DenominatorPolicy,
    readiness: Sequence[ReadinessResult],
    preparation: AdmissionPreparation,
    receipt: PopulationUseReceipt,
    release: AdmissionCaseRelease,
    cases: Sequence[AdmissionCaseResult],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> AdmissionReplay:
    """Delegate v2 scoring and authoritative replay to detection core."""
    replay = score_admission(
        manifest,
        denominator,
        tuple(readiness),
        preparation,
        receipt,
        release,
        tuple(cases),
        context,
        custody,
        resolver,
    )
    validate_admission_replay(replay, context, custody, resolver)
    return replay


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
