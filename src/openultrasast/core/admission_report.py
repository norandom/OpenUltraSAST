"""Evidence-backed admission gates and canonical final reports."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum

from openultrasast.core import canonical
from openultrasast.core._admission_gates import (
    AdmissionReportError,
    CaseBudgetEvaluation,
    GateKind,
    GateResult,
    ThresholdEvaluation,
    budget_evaluation_value,
    budget_gate,
    gate_value,
    instrument_gate,
    make_budget_evaluations,
    make_threshold_evaluations,
    quality_gate,
    readiness_gate,
    threshold_evaluation_value,
)
from openultrasast.core._admission_replay import (
    ADMISSION_REPLAY_SCHEMA,
    AdmissionReplay,
    _replay_value,
    admission_replay_value,
    validate_admission_replay_structure,
)
from openultrasast.core.admission_case import AdmissionCaseRelease, AdmissionCaseResult
from openultrasast.core.admission_context import AdmissionValidationContext
from openultrasast.core.admission_metrics import AdmissionMetricEvidence, derive_admission_metrics
from openultrasast.core.admission_review import AdmissionManifestV2
from openultrasast.core.admission_spend import AdmissionPreparation
from openultrasast.core.custody import PopulationCustodyPort, PopulationUseReceipt
from openultrasast.core.measurement import (
    BaselineIdentity,
    DenominatorPolicy,
    derive_baseline_identity_digest,
)
from openultrasast.core.measurement_factory import create_measurement_record
from openultrasast.core.measurement_record import MeasurementRecordV2, ReadinessReference, measurement_record_value
from openultrasast.core.readiness import ReadinessResult, ReadinessStage

ADMISSION_REPORT_SCHEMA = "openultrasast.detection-core.admission-report.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_PREREQUISITE_STAGES = tuple(ReadinessStage)[:6]


class AdmissionDecision(Enum):
    GO = "go"
    NO_GO = "no_go"


@dataclass(frozen=True)
class AdmissionReportV2:
    identity: BaselineIdentity
    census_digest: str
    validation_context_digest: str
    authorization_digest: str
    label_release_receipt_digest: str
    case_release_digest: str
    case_result_digests: tuple[str, ...]
    in_scope_case_count: int
    whole_population_case_count: int
    budget_evaluations: tuple[CaseBudgetEvaluation, ...]
    quality_evaluations: tuple[ThresholdEvaluation, ...]
    measurement: MeasurementRecordV2
    instrument_results: tuple[GateResult, ...]
    budget_results: tuple[GateResult, ...]
    readiness_results: tuple[GateResult, ...]
    quality_results: tuple[GateResult, ...]
    decision: AdmissionDecision
    report_digest: str

    def __post_init__(self) -> None:
        _validate_report_structure(self)


def _digest(value: object, field: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise AdmissionReportError(f"{field} must be a full lowercase SHA-256 digest")


def _case_digests(value: object, count: int) -> tuple[str, ...]:
    if not isinstance(value, tuple) or not all(isinstance(item, str) for item in value):
        raise AdmissionReportError("case result digests must be a tuple of digests")
    for item in value:
        _digest(item, "case result digest")
    if value != tuple(sorted(set(value))) or len(value) != count:
        raise AdmissionReportError("case result digests must identify every case exactly once in canonical order")
    return value


def _report_value(value: AdmissionReportV2) -> canonical.JsonValue:
    return {
        "schema_version": ADMISSION_REPORT_SCHEMA,
        "baseline_identity_digest": derive_baseline_identity_digest(value.identity),
        "census_digest": value.census_digest,
        "validation_context_digest": value.validation_context_digest,
        "authorization_digest": value.authorization_digest,
        "label_release_receipt_digest": value.label_release_receipt_digest,
        "case_release_digest": value.case_release_digest,
        "case_result_digests": value.case_result_digests,
        "in_scope_case_count": value.in_scope_case_count,
        "whole_population_case_count": value.whole_population_case_count,
        "budget_evaluations": tuple(
            {**budget_evaluation_value(item), "evaluation_digest": item.evaluation_digest} for item in value.budget_evaluations
        ),
        "quality_evaluations": tuple(
            {**threshold_evaluation_value(item), "evaluation_digest": item.evaluation_digest} for item in value.quality_evaluations
        ),
        "measurement_record_digest": value.measurement.record_digest,
        "instrument_results": tuple(gate_value(item) for item in value.instrument_results),
        "budget_results": tuple(gate_value(item) for item in value.budget_results),
        "readiness_results": tuple(gate_value(item) for item in value.readiness_results),
        "quality_results": tuple(gate_value(item) for item in value.quality_results),
        "decision": value.decision.value,
    }


def _validate_report_bindings(value: AdmissionReportV2) -> None:
    baseline_digest = derive_baseline_identity_digest(value.identity)
    if baseline_digest != derive_baseline_identity_digest(value.measurement.identity):
        raise AdmissionReportError("measurement baseline identity does not match report")
    measurement_record_value(value.measurement)
    for item, field in (
        (value.census_digest, "census digest"),
        (value.validation_context_digest, "validation context digest"),
        (value.authorization_digest, "authorization digest"),
        (value.label_release_receipt_digest, "label release receipt digest"),
        (value.case_release_digest, "case release digest"),
    ):
        _digest(item, field)
    if isinstance(value.in_scope_case_count, bool) or not isinstance(value.in_scope_case_count, int):
        raise AdmissionReportError("in-scope case count must be an integer")
    if isinstance(value.whole_population_case_count, bool) or not isinstance(value.whole_population_case_count, int):
        raise AdmissionReportError("whole-population case count must be an integer")
    if not 0 < value.in_scope_case_count <= value.whole_population_case_count:
        raise AdmissionReportError("case counts must be positive and in-scope cannot exceed whole-population")
    _case_digests(value.case_result_digests, value.whole_population_case_count)


def _require_exact_gate(value: object, expected: GateResult) -> tuple[GateResult, ...]:
    if not isinstance(value, tuple) or value != (expected,):
        raise AdmissionReportError(f"{expected.kind.value} gate does not match its derived evidence and outcome")
    return value


def _derived_gates(value: AdmissionReportV2) -> tuple[GateResult, GateResult, GateResult, GateResult]:
    cases = tuple(item.case for item in value.budget_evaluations)
    return (
        instrument_gate(value.case_result_digests, cases),
        budget_gate(value.case_result_digests, value.budget_evaluations),
        readiness_gate(value.measurement.prerequisite_readiness),
        quality_gate(value.identity, value.measurement, value.quality_evaluations),
    )


def _validate_report_fields(value: AdmissionReportV2) -> None:
    if type(value) is not AdmissionReportV2:
        raise AdmissionReportError("report must be an exact AdmissionReportV2")
    _validate_report_bindings(value)
    instrument, budget, readiness, quality = _derived_gates(value)
    actual = (
        _require_exact_gate(value.instrument_results, instrument),
        _require_exact_gate(value.budget_results, budget),
        _require_exact_gate(value.readiness_results, readiness),
        _require_exact_gate(value.quality_results, quality),
    )
    if not isinstance(value.decision, AdmissionDecision):
        raise AdmissionReportError("decision must use AdmissionDecision")
    all_passed = all(item.passed for group in actual for item in group)
    expected = AdmissionDecision.GO if all_passed else AdmissionDecision.NO_GO
    if value.decision is not expected:
        raise AdmissionReportError("decision does not match every re-derived mandatory gate")


def _validate_report_structure(value: AdmissionReportV2) -> None:
    _validate_report_fields(value)
    _digest(value.report_digest, "report digest")
    if value.report_digest != canonical.content_digest(_report_value(value)):
        raise AdmissionReportError("report digest does not match admission content")


def admission_report_value(value: AdmissionReportV2) -> canonical.JsonValue:
    _validate_report_structure(value)
    return _report_value(value)


def _readiness_references(readiness: tuple[ReadinessResult, ...]) -> tuple[ReadinessReference, ...]:
    references = tuple(ReadinessReference(item.stage, item.result, item.result_digest) for item in readiness)
    if tuple(item.stage for item in references) != _PREREQUISITE_STAGES:
        raise AdmissionReportError("admission measurement requires instrument through development readiness")
    return references


def _measurement(
    manifest: AdmissionManifestV2,
    evidence: AdmissionMetricEvidence,
    readiness: tuple[ReadinessResult, ...],
) -> MeasurementRecordV2:
    return create_measurement_record(
        identity=manifest.identity,
        family_decision_vocabulary=evidence.family_decision_vocabulary,
        family_decision_counts=evidence.family_decision_counts,
        neutral_outcome_counts=evidence.neutral_outcome_counts,
        evidence_basis_counts=evidence.evidence_basis_counts,
        metrics=evidence.metrics,
        stage_funnel=evidence.stage_funnel,
        instrument_failures=(),
        model_outcome_counts=evidence.model_outcome_counts,
        model_failures=evidence.model_failures,
        runtime_ms=evidence.runtime_ms,
        prerequisite_readiness=_readiness_references(readiness),
    )


def _quality_gate(manifest: AdmissionManifestV2, measurement: MeasurementRecordV2) -> GateResult:
    evaluations = make_threshold_evaluations(manifest.thresholds, measurement)
    return quality_gate(manifest.identity, measurement, evaluations)


def _make_report(
    manifest: AdmissionManifestV2,
    preparation: AdmissionPreparation,
    receipt: PopulationUseReceipt,
    release: AdmissionCaseRelease,
    cases: tuple[AdmissionCaseResult, ...],
    evidence: AdmissionMetricEvidence,
    measurement: MeasurementRecordV2,
) -> AdmissionReportV2:
    budgets = make_budget_evaluations(cases)
    quality = make_threshold_evaluations(manifest.thresholds, measurement)
    gates = (
        instrument_gate(evidence.case_result_digests, cases),
        budget_gate(evidence.case_result_digests, budgets),
        readiness_gate(measurement.prerequisite_readiness),
        quality_gate(manifest.identity, measurement, quality),
    )
    decision = AdmissionDecision.GO if all(item.passed for item in gates) else AdmissionDecision.NO_GO
    values = (
        manifest.identity,
        manifest.census.census_digest,
        preparation.authorization.validation_context_digest,
        preparation.authorization.authorization_digest,
        receipt.receipt_digest,
        release.release_digest,
        evidence.case_result_digests,
        evidence.in_scope_case_count,
        evidence.whole_population_case_count,
        budgets,
        quality,
        measurement,
        (gates[0],),
        (gates[1],),
        (gates[2],),
        (gates[3],),
        decision,
    )
    draft = object.__new__(AdmissionReportV2)
    fields = tuple(AdmissionReportV2.__dataclass_fields__)
    for field, item in zip(fields, (*values, "0" * 64), strict=True):
        object.__setattr__(draft, field, item)
    _validate_report_fields(draft)
    return AdmissionReportV2(*values, canonical.content_digest(_report_value(draft)))


def score_admission(
    manifest: AdmissionManifestV2,
    denominator: DenominatorPolicy,
    readiness: Sequence[ReadinessResult],
    preparation: AdmissionPreparation,
    label_release_receipt: PopulationUseReceipt,
    case_release: AdmissionCaseRelease,
    cases: Sequence[AdmissionCaseResult],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> AdmissionReplay:
    """Revalidate exact admission evidence and freeze its authoritative replay."""
    frozen_readiness = tuple(readiness)
    frozen_cases = tuple(sorted(tuple(cases), key=lambda item: item.case_id_digest))
    report = _derive_report(
        manifest,
        denominator,
        frozen_readiness,
        preparation,
        label_release_receipt,
        case_release,
        frozen_cases,
        context,
        custody,
        resolver,
    )
    return _make_replay(
        manifest,
        denominator,
        frozen_readiness,
        preparation,
        label_release_receipt,
        case_release,
        frozen_cases,
        report,
    )


def _derive_report(
    manifest: AdmissionManifestV2,
    denominator: DenominatorPolicy,
    readiness: tuple[ReadinessResult, ...],
    preparation: AdmissionPreparation,
    label_release_receipt: PopulationUseReceipt,
    case_release: AdmissionCaseRelease,
    cases: tuple[AdmissionCaseResult, ...],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> AdmissionReportV2:
    evidence = derive_admission_metrics(
        manifest,
        denominator,
        readiness,
        preparation,
        label_release_receipt,
        case_release,
        cases,
        context,
        custody,
        resolver,
    )
    measurement = _measurement(manifest, evidence, readiness)
    return _make_report(
        manifest,
        preparation,
        label_release_receipt,
        case_release,
        cases,
        evidence,
        measurement,
    )


def _make_replay(
    manifest: AdmissionManifestV2,
    denominator: DenominatorPolicy,
    readiness: tuple[ReadinessResult, ...],
    preparation: AdmissionPreparation,
    label_release_receipt: PopulationUseReceipt,
    case_release: AdmissionCaseRelease,
    cases: tuple[AdmissionCaseResult, ...],
    report: AdmissionReportV2,
) -> AdmissionReplay:
    values = (manifest, denominator, readiness, preparation, label_release_receipt, case_release, cases, report)
    draft = object.__new__(AdmissionReplay)
    for field, item in zip(AdmissionReplay.__dataclass_fields__, (*values, "0" * 64), strict=True):
        object.__setattr__(draft, field, item)
    return AdmissionReplay(*values, canonical.content_digest(_replay_value(draft)))


def validate_admission_replay(
    replay: AdmissionReplay,
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> AdmissionReportV2:
    """Re-run every carried input against independently supplied current trust state."""
    validate_admission_replay_structure(replay)
    try:
        expected = _derive_report(
            replay.manifest,
            replay.denominator,
            replay.readiness,
            replay.preparation,
            replay.label_release_receipt,
            replay.case_release,
            replay.cases,
            context,
            custody,
            resolver,
        )
    except (AttributeError, LookupError, TypeError, ValueError) as exc:
        raise AdmissionReportError(f"authoritative admission replay refused: {exc}") from exc
    actual_bytes = canonical.canonical_bytes(_report_value(replay.report))
    expected_bytes = canonical.canonical_bytes(_report_value(expected))
    if replay.report != expected or actual_bytes != expected_bytes:
        raise AdmissionReportError("report does not match the authoritative admission inputs")
    expected_replay = _make_replay(
        replay.manifest,
        replay.denominator,
        replay.readiness,
        replay.preparation,
        replay.label_release_receipt,
        replay.case_release,
        replay.cases,
        expected,
    )
    if replay != expected_replay or canonical.canonical_bytes(_replay_value(replay)) != canonical.canonical_bytes(
        _replay_value(expected_replay)
    ):
        raise AdmissionReportError("replay does not match the authoritative admission inputs")
    return expected


__all__ = [
    "ADMISSION_REPLAY_SCHEMA",
    "ADMISSION_REPORT_SCHEMA",
    "AdmissionReplay",
    "AdmissionDecision",
    "AdmissionReportError",
    "AdmissionReportV2",
    "CaseBudgetEvaluation",
    "GateKind",
    "GateResult",
    "ThresholdEvaluation",
    "admission_replay_value",
    "admission_report_value",
    "score_admission",
    "validate_admission_replay",
]
