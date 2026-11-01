"""Typed evidence and re-derived gates for final admission reports."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from enum import Enum

from openultrasast.core import canonical
from openultrasast.core.admission_case import (
    AdmissionCaseResult,
    derive_admission_case_result_digest,
    validate_admission_case_shape,
)
from openultrasast.core.admission_review import AdmissionThreshold, derive_threshold_set_digest
from openultrasast.core.coverage import validate_instrument
from openultrasast.core.measurement import (
    BaselineIdentity,
    Comparator,
    MetricId,
    MetricResult,
    Statistic,
    metric_passes,
)
from openultrasast.core.measurement_record import MeasurementRecordV2, ReadinessReference
from openultrasast.core.readiness import StageResult

BUDGET_EVALUATION_SCHEMA = "openultrasast.detection-core.admission-budget-evaluation.v2"
THRESHOLD_EVALUATION_SCHEMA = "openultrasast.detection-core.admission-threshold-evaluation.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_MANDATORY_METRICS = tuple(MetricId)[:6]


class AdmissionReportError(ValueError):
    """Admission evidence cannot form a valid final report."""


class GateKind(Enum):
    INSTRUMENT = "instrument"
    BUDGET = "budget"
    QUALITY = "quality"
    READINESS = "readiness"


@dataclass(frozen=True)
class GateResult:
    kind: GateKind
    gate_id: str
    passed: bool
    reasons: tuple[str, ...]
    evidence_digests: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_gate(self)


@dataclass(frozen=True)
class CaseBudgetEvaluation:
    case: AdmissionCaseResult
    case_result_digest: str
    budget_derivation_digest: str
    total_reply_ms: int
    budget_ms: int
    evaluation_digest: str

    def __post_init__(self) -> None:
        validate_budget_evaluation(self)


@dataclass(frozen=True)
class ThresholdEvaluation:
    metric_id: MetricId
    statistic: Statistic
    comparator: Comparator
    target: float
    measurement_record_digest: str
    passed: bool
    evaluation_digest: str

    def __post_init__(self) -> None:
        validate_threshold_evaluation(self)


def _digest(value: object, field: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise AdmissionReportError(f"{field} must be a full lowercase SHA-256 digest")


def _canonical_digests(value: object, field: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, tuple) or not all(isinstance(item, str) for item in value):
        raise AdmissionReportError(f"{field} must be a tuple of digests")
    for item in value:
        _digest(item, field.removesuffix("s"))
    if value != tuple(sorted(set(value))):
        raise AdmissionReportError(f"{field} must be unique and canonical")
    if not allow_empty and not value:
        raise AdmissionReportError(f"{field} must not be empty")
    return value


def validate_gate(value: GateResult) -> None:
    if type(value) is not GateResult:
        raise AdmissionReportError("gate must be an exact GateResult")
    if not isinstance(value.kind, GateKind) or not isinstance(value.gate_id, str) or not value.gate_id:
        raise AdmissionReportError("gate kind and gate_id must use closed nonempty values")
    if not isinstance(value.passed, bool):
        raise AdmissionReportError("gate passed must be boolean")
    if not isinstance(value.reasons, tuple) or not all(isinstance(item, str) and item for item in value.reasons):
        raise AdmissionReportError("gate reasons must be a tuple of nonempty text")
    if value.reasons != tuple(sorted(set(value.reasons))):
        raise AdmissionReportError("gate reasons must be unique and canonical")
    if value.passed == bool(value.reasons):
        raise AdmissionReportError("passed gates have no reasons and failed gates require reasons")
    _canonical_digests(value.evidence_digests, "gate evidence digests")


def gate_value(value: GateResult) -> dict[str, canonical.JsonValue]:
    validate_gate(value)
    return {
        "kind": value.kind.value,
        "gate_id": value.gate_id,
        "passed": value.passed,
        "reasons": value.reasons,
        "evidence_digests": value.evidence_digests,
    }


def _make_gate(kind: GateKind, gate_id: str, reasons: tuple[str, ...], evidence: tuple[str, ...]) -> GateResult:
    canonical_reasons = tuple(sorted(set(reasons)))
    canonical_evidence = tuple(sorted(set(evidence)))
    return GateResult(kind, gate_id, not canonical_reasons, canonical_reasons, canonical_evidence)


def budget_evaluation_value(value: CaseBudgetEvaluation) -> dict[str, canonical.JsonValue]:
    return {
        "schema_version": BUDGET_EVALUATION_SCHEMA,
        "case_result_digest": value.case_result_digest,
        "budget_derivation_digest": value.budget_derivation_digest,
        "total_reply_ms": value.total_reply_ms,
        "budget_ms": value.budget_ms,
    }


def validate_budget_evaluation(value: CaseBudgetEvaluation) -> None:
    if type(value) is not CaseBudgetEvaluation:
        raise AdmissionReportError("budget evaluation must use the exact type")
    if type(value.case) is not AdmissionCaseResult:
        raise AdmissionReportError("budget evaluation must carry the exact admission case")
    validate_admission_case_shape(value.case)
    if value.case.result_digest != derive_admission_case_result_digest(value.case):
        raise AdmissionReportError("budget evaluation case result digest cannot be re-derived")
    _digest(value.case_result_digest, "case result digest")
    _digest(value.budget_derivation_digest, "budget derivation digest")
    for item, field in ((value.total_reply_ms, "total reply milliseconds"), (value.budget_ms, "budget milliseconds")):
        if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
            raise AdmissionReportError(f"{field} must be a positive integer")
    _digest(value.evaluation_digest, "budget evaluation digest")
    expected = (
        value.case.result_digest,
        value.case.budget.derivation_digest,
        value.case.total_reply_ms,
        value.case.budget.budget_ms,
    )
    actual = (value.case_result_digest, value.budget_derivation_digest, value.total_reply_ms, value.budget_ms)
    if actual != expected:
        raise AdmissionReportError("budget evaluation does not match the exact case-to-budget derivation")
    if value.evaluation_digest != canonical.content_digest(budget_evaluation_value(value)):
        raise AdmissionReportError("budget evaluation digest does not match content")


def make_budget_evaluations(cases: tuple[AdmissionCaseResult, ...]) -> tuple[CaseBudgetEvaluation, ...]:
    values = []
    for case in cases:
        fields = (
            case,
            case.result_digest,
            case.budget.derivation_digest,
            case.total_reply_ms,
            case.budget.budget_ms,
        )
        draft = object.__new__(CaseBudgetEvaluation)
        for field, item in zip(CaseBudgetEvaluation.__dataclass_fields__, (*fields, "0" * 64), strict=True):
            object.__setattr__(draft, field, item)
        digest = canonical.content_digest(budget_evaluation_value(draft))
        values.append(CaseBudgetEvaluation(*fields, digest))
    return tuple(sorted(values, key=lambda item: item.case_result_digest))


def threshold_evaluation_value(value: ThresholdEvaluation) -> dict[str, canonical.JsonValue]:
    return {
        "schema_version": THRESHOLD_EVALUATION_SCHEMA,
        "metric_id": value.metric_id.value,
        "statistic": value.statistic.value,
        "comparator": value.comparator.value,
        "target": value.target,
        "measurement_record_digest": value.measurement_record_digest,
        "passed": value.passed,
    }


def validate_threshold_evaluation(value: ThresholdEvaluation) -> None:
    if type(value) is not ThresholdEvaluation:
        raise AdmissionReportError("threshold evaluation must use the exact type")
    if not isinstance(value.metric_id, MetricId) or not isinstance(value.statistic, Statistic):
        raise AdmissionReportError("threshold evaluation metric and statistic must use closed enums")
    if not isinstance(value.comparator, Comparator):
        raise AdmissionReportError("threshold evaluation comparator must use the closed enum")
    if isinstance(value.target, bool) or not isinstance(value.target, float) or not math.isfinite(value.target):
        raise AdmissionReportError("threshold evaluation target must be a finite float")
    _digest(value.measurement_record_digest, "threshold measurement record digest")
    if not isinstance(value.passed, bool):
        raise AdmissionReportError("threshold evaluation passed must be boolean")
    _digest(value.evaluation_digest, "threshold evaluation digest")
    if value.evaluation_digest != canonical.content_digest(threshold_evaluation_value(value)):
        raise AdmissionReportError("threshold evaluation digest does not match content")


def make_threshold_evaluations(
    thresholds: tuple[AdmissionThreshold, ...],
    measurement: MeasurementRecordV2,
) -> tuple[ThresholdEvaluation, ...]:
    by_metric = {item.metric_id: item for item in measurement.metrics}
    values = []
    for threshold in thresholds:
        passed = metric_passes(by_metric[threshold.metric_id], threshold.statistic, threshold.comparator, threshold.target)
        fields = (
            threshold.metric_id,
            threshold.statistic,
            threshold.comparator,
            threshold.target,
            measurement.record_digest,
            passed,
        )
        draft = object.__new__(ThresholdEvaluation)
        for field, item in zip(ThresholdEvaluation.__dataclass_fields__, (*fields, "0" * 64), strict=True):
            object.__setattr__(draft, field, item)
        digest = canonical.content_digest(threshold_evaluation_value(draft))
        values.append(ThresholdEvaluation(*fields, digest))
    return tuple(values)


def _thresholds(evaluations: tuple[ThresholdEvaluation, ...]) -> tuple[AdmissionThreshold, ...]:
    return tuple(AdmissionThreshold(item.metric_id, item.statistic, item.comparator, item.target) for item in evaluations)


def instrument_gate(
    case_result_digests: tuple[str, ...],
    cases: tuple[AdmissionCaseResult, ...],
) -> GateResult:
    evidence = _canonical_digests(case_result_digests, "case result digests")
    identities = tuple(sorted(item.result_digest for item in cases))
    if identities != evidence or len(identities) != len(cases):
        raise AdmissionReportError("instrument cases must cover the exact complete case-result set")
    try:
        for case in cases:
            validate_instrument(case.input_manifest, case.input_receipts)
    except (TypeError, ValueError) as exc:
        raise AdmissionReportError(f"instrument gate evidence is invalid: {exc}") from exc
    return _make_gate(GateKind.INSTRUMENT, "instrument:all_cases", (), evidence)


def budget_gate(
    case_result_digests: tuple[str, ...],
    evaluations: tuple[CaseBudgetEvaluation, ...],
) -> GateResult:
    if not isinstance(evaluations, tuple) or not all(type(item) is CaseBudgetEvaluation for item in evaluations):
        raise AdmissionReportError("budget evaluations must use the exact typed tuple")
    for item in evaluations:
        validate_budget_evaluation(item)
    identities = tuple(item.case_result_digest for item in evaluations)
    if identities != case_result_digests or len(set(identities)) != len(identities):
        raise AdmissionReportError("budget evaluations must cover the exact complete case-result set")
    reasons = tuple(f"budget_exceeded:{item.case_result_digest}" for item in evaluations if item.total_reply_ms > item.budget_ms)
    evidence = tuple(item.evaluation_digest for item in evaluations)
    return _make_gate(GateKind.BUDGET, "budget:all_cases", reasons, evidence)


def readiness_gate(references: tuple[ReadinessReference, ...]) -> GateResult:
    reasons = tuple(f"readiness_failed:{item.stage.value}" for item in references if item.result is not StageResult.PASSED)
    evidence = tuple(item.result_digest for item in references)
    return _make_gate(GateKind.READINESS, "readiness:prerequisites", reasons, evidence)


def quality_gate(
    identity: BaselineIdentity,
    measurement: MeasurementRecordV2,
    evaluations: tuple[ThresholdEvaluation, ...],
) -> GateResult:
    if not isinstance(evaluations, tuple) or not all(type(item) is ThresholdEvaluation for item in evaluations):
        raise AdmissionReportError("quality threshold evaluations must use the exact typed tuple")
    by_metric = {item.metric_id: item for item in measurement.metrics}
    reasons = _mandatory_metric_reasons(by_metric)
    model = by_metric[MetricId.MODEL_SUCCESS_RATE]
    reasons.extend(_model_reasons(identity, model, evaluations))
    for item in evaluations:
        validate_threshold_evaluation(item)
        if item.measurement_record_digest != measurement.record_digest:
            raise AdmissionReportError("threshold evaluation does not bind the exact measurement")
        expected = metric_passes(by_metric[item.metric_id], item.statistic, item.comparator, item.target)
        if item.passed is not expected:
            raise AdmissionReportError("threshold evaluation outcome does not match the exact metric")
        if not expected:
            reasons.append(f"threshold_failed:{item.metric_id.value}:{item.statistic.value}")
    thresholds = _thresholds(evaluations)
    try:
        threshold_set_digest = derive_threshold_set_digest(thresholds)
    except ValueError as exc:
        raise AdmissionReportError(f"quality threshold evaluations are invalid: {exc}") from exc
    if threshold_set_digest != identity.threshold_set_digest:
        raise AdmissionReportError("threshold evaluations do not match the exact threshold set")
    evidence = (identity.threshold_set_digest, measurement.record_digest, *(item.evaluation_digest for item in evaluations))
    return _make_gate(GateKind.QUALITY, "quality:threshold_set", tuple(reasons), evidence)


def _model_reasons(
    identity: BaselineIdentity,
    model: MetricResult,
    evaluations: tuple[ThresholdEvaluation, ...],
) -> list[str]:
    reasons: list[str] = []
    model_configured = bool(identity.model_program_digests)
    model_executed = model.denominator > 0
    model_applicable = model_configured or model_executed
    model_threshold_count = sum(item.metric_id is MetricId.MODEL_SUCCESS_RATE for item in evaluations)
    if model_applicable and model_threshold_count == 0:
        reasons.append("mandatory_model_success_threshold_missing")
    if model_configured and not model_executed:
        reasons.append("mandatory_model_success_has_no_attempted_calls")
    if model_executed and model.numerator < model.denominator:
        reasons.append("mandatory_model_call_failed")
    return reasons


def _mandatory_metric_reasons(by_metric: dict[MetricId, MetricResult]) -> list[str]:
    reasons = []
    for metric in _MANDATORY_METRICS:
        result = by_metric.get(metric)
        if result is None or result.denominator == 0:
            reasons.append(f"mandatory_metric_missing_or_zero:{metric.value}")
    return reasons
