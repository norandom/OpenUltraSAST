"""Completed non-authorizing scope decisions and arm evidence for evaluation V3."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import ClassVar

from openultrasast.core import canonical
from openultrasast.core._admission_gates import GateKind, GateResult, gate_value
from openultrasast.core._evaluation_report_validation import (
    derive_operational_evidence as _operational,
)
from openultrasast.core._evaluation_report_validation import funnel_value as _funnel_value
from openultrasast.core._evaluation_report_validation import (
    validate_complete_report_inputs as _validate_complete_inputs,
)
from openultrasast.core._evaluation_report_validation import (
    validate_report_input_types as _validate_inputs,
)
from openultrasast.core.admission_report import AdmissionDecision
from openultrasast.core.coverage import CoverageFunnel
from openultrasast.core.evaluation_combination import CombinationLineageV3
from openultrasast.core.evaluation_measurement import (
    ArmScopeKey,
    Comparator,
    MetricId,
    ScopedMetricResultV3,
    ScopedThresholdV3,
    Statistic,
)
from openultrasast.core.evaluation_observation import ArmObservationSetV3
from openultrasast.core.evaluation_ordinary_projection import WholePopulationProjectionV3
from openultrasast.core.evaluation_plan import EvaluationBaselineIdentityV3, EvaluationPlanManifestV3
from openultrasast.core.evaluation_release import ArmAdmissionCaseResultV3, ArmAdmissionCasesV3
from openultrasast.core.evaluation_version import (
    EVALUATION_ADMISSION_V3_SCHEMA,
    EvaluationV3Contract,
    NonAuthorizingV3,
    require_exact_v3_contract,
)
from openultrasast.core.readiness import ReadinessResult

_DIGEST = re.compile(r"[0-9a-f]{64}")
_SCHEMA = "openultrasast.detection-core.evaluation-report.v3"


class EvaluationReportError(ValueError):
    """Completed reports cannot be derived from incomplete or impaired evidence."""


class DegradationReasonV3(Enum):
    INSTRUMENT = "instrument"
    MODEL = "model"
    BUDGET = "budget"
    COVERAGE = "coverage"
    DEFERRED = "deferred"


def _digest(value: object, field: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise EvaluationReportError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _count(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise EvaluationReportError(f"{field} must be a non-negative integer")
    return value


def _bind(value: object, field: str, expected: str) -> None:
    actual = getattr(value, field)
    if actual == "":
        object.__setattr__(value, field, expected)
    elif _digest(actual, field) != expected:
        raise EvaluationReportError(f"{field} does not match canonical content")


def _value(kind: str, payload: canonical.JsonValue) -> canonical.JsonValue:
    return {"schema_version": _SCHEMA, "kind": kind, "payload": payload}


def _key_value(key: ArmScopeKey) -> canonical.JsonValue:
    return {"arm_id": key.arm_id, "family_id": key.scope.family_id, "ecosystem": key.scope.ecosystem}


def _metric_value(metric: ScopedMetricResultV3) -> canonical.JsonValue:
    return {
        "key": _key_value(metric.key),
        "metric_id": metric.metric_id.value,
        "numerator": metric.numerator,
        "denominator": metric.denominator,
        "sample_count": metric.sample_count,
        "value": metric.value,
        "interval_method": metric.interval_method.value,
        "interval_lower": metric.interval_lower,
        "interval_upper": metric.interval_upper,
    }


def _metric_digest(metric: ScopedMetricResultV3) -> str:
    metric.__post_init__()
    return canonical.content_digest(_value("scoped_metric_result", _metric_value(metric)))


@dataclass(frozen=True)
class ScopeAdmissionResultV3(EvaluationV3Contract, NonAuthorizingV3):
    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    key: ArmScopeKey
    metrics: tuple[ScopedMetricResultV3, ...]
    instrument_gate: GateResult
    budget_gate: GateResult
    readiness_gate: GateResult
    quality_gate: GateResult
    decision: AdmissionDecision
    result_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, ScopeAdmissionResultV3, field="scope admission result")
        _validate_scope_result(self)
        _bind(self, "result_digest", canonical.content_digest(_value("scope_admission_result", _scope_result_value(self))))


def _scope_result_value(value: ScopeAdmissionResultV3) -> canonical.JsonValue:
    return {
        "key": _key_value(value.key),
        "metric_digests": tuple(_metric_digest(item) for item in value.metrics),
        "instrument_gate": gate_value(value.instrument_gate),
        "budget_gate": gate_value(value.budget_gate),
        "readiness_gate": gate_value(value.readiness_gate),
        "quality_gate": gate_value(value.quality_gate),
        "decision": value.decision.value,
    }


def _validate_scope_result(value: ScopeAdmissionResultV3) -> None:
    if type(value.key) is not ArmScopeKey or type(value.metrics) is not tuple:
        raise EvaluationReportError("scope result requires an exact key and metric tuple")
    value.key.__post_init__()
    if tuple(item.metric_id for item in value.metrics if type(item) is ScopedMetricResultV3) != tuple(MetricId):
        raise EvaluationReportError("scope result requires every standard metric in canonical order")
    if any(item.key != value.key for item in value.metrics):
        raise EvaluationReportError("scope result metrics belong to another key")
    gates = (value.instrument_gate, value.budget_gate, value.readiness_gate, value.quality_gate)
    expected_kinds = (GateKind.INSTRUMENT, GateKind.BUDGET, GateKind.READINESS, GateKind.QUALITY)
    if tuple(item.kind for item in gates if type(item) is GateResult) != expected_kinds:
        raise EvaluationReportError("scope result requires the four exact mandatory gates")
    expected = AdmissionDecision.GO if all(item.passed for item in gates) else AdmissionDecision.NO_GO
    if type(value.decision) is not AdmissionDecision or value.decision is not expected:
        raise EvaluationReportError("scope decision does not match all mandatory gates")


@dataclass(frozen=True)
class ArmOperationalEvidenceV3(EvaluationV3Contract, NonAuthorizingV3):
    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    completed_count: int
    deferred_count: int
    completed_case_digests: tuple[str, ...]
    deferred_case_digests: tuple[str, ...]
    stage_funnel: CoverageFunnel
    instrument_failures: tuple[str, ...]
    model_failures: tuple[str, ...]
    runtime_ms: int
    degradation_reasons: tuple[DegradationReasonV3, ...]
    evidence_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, ArmOperationalEvidenceV3, field="arm operational evidence")
        _validate_operational(self)
        _bind(self, "evidence_digest", canonical.content_digest(_value("arm_operational_evidence", _operational_value(self))))


def _canonical_text(values: object, field: str) -> tuple[str, ...]:
    if type(values) is not tuple or any(type(item) is not str or not item for item in values):
        raise EvaluationReportError(f"{field} must be an exact tuple of nonempty text")
    if values != tuple(sorted(set(values))):
        raise EvaluationReportError(f"{field} must be unique and canonical")
    return values


def _validate_operational(value: ArmOperationalEvidenceV3) -> None:
    completed = _count(value.completed_count, "completed count")
    deferred = _count(value.deferred_count, "deferred count")
    for digests, count, field in (
        (value.completed_case_digests, completed, "completed case digests"),
        (value.deferred_case_digests, deferred, "deferred case digests"),
    ):
        if type(digests) is not tuple or len(digests) != count:
            raise EvaluationReportError(f"{field} must match its count")
        for digest in digests:
            _digest(digest, field)
        if digests != tuple(sorted(set(digests))):
            raise EvaluationReportError(f"{field} must be unique and canonical")
    _funnel_value(value.stage_funnel)
    _canonical_text(value.instrument_failures, "instrument failures")
    _canonical_text(value.model_failures, "model failures")
    _count(value.runtime_ms, "runtime milliseconds")
    expected = tuple(reason for reason in DegradationReasonV3 if reason in set(value.degradation_reasons))
    if type(value.degradation_reasons) is not tuple or value.degradation_reasons != expected:
        raise EvaluationReportError("degradation reasons must be unique and canonical")


def _operational_value(value: ArmOperationalEvidenceV3) -> canonical.JsonValue:
    return {
        "completed_count": value.completed_count,
        "deferred_count": value.deferred_count,
        "completed_case_digests": value.completed_case_digests,
        "deferred_case_digests": value.deferred_case_digests,
        "stage_funnel": _funnel_value(value.stage_funnel),
        "instrument_failures": value.instrument_failures,
        "model_failures": value.model_failures,
        "runtime_ms": value.runtime_ms,
        "degradation_reasons": tuple(item.value for item in value.degradation_reasons),
    }


@dataclass(frozen=True)
class WholePopulationCoverageV3(EvaluationV3Contract, NonAuthorizingV3):
    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    underlying_push_count: int
    completed_underlying_push_count: int
    deferred_underlying_push_count: int
    coverage_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, WholePopulationCoverageV3, field="whole population coverage")
        total = _count(self.underlying_push_count, "underlying push count")
        completed = _count(self.completed_underlying_push_count, "completed underlying push count")
        deferred = _count(self.deferred_underlying_push_count, "deferred underlying push count")
        if total != completed + deferred:
            raise EvaluationReportError("whole population completed and deferred counts must reconcile")
        payload = {"underlying_push_count": total, "completed_count": completed, "deferred_count": deferred}
        _bind(self, "coverage_digest", canonical.content_digest(_value("whole_population_coverage", payload)))


@dataclass(frozen=True)
class ArmEvaluationReportV3(EvaluationV3Contract, NonAuthorizingV3):
    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    baseline: EvaluationBaselineIdentityV3
    scoped_results: tuple[ScopeAdmissionResultV3, ...]
    operational_evidence: ArmOperationalEvidenceV3
    combination_lineage: CombinationLineageV3 | None
    report_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, ArmEvaluationReportV3, field="arm evaluation report")
        _validate_report(self)
        _bind(self, "report_digest", canonical.content_digest(_value("arm_evaluation_report", _report_value(self))))


def _validate_report(value: ArmEvaluationReportV3) -> None:
    if type(value.baseline) is not EvaluationBaselineIdentityV3 or type(value.scoped_results) is not tuple:
        raise EvaluationReportError("report requires an exact baseline and scoped result tuple")
    value.baseline.__post_init__()
    if not value.scoped_results or any(type(item) is not ScopeAdmissionResultV3 for item in value.scoped_results):
        raise EvaluationReportError("report requires completed exact scope results")
    for item in value.scoped_results:
        item.__post_init__()
    keys = tuple(item.key for item in value.scoped_results)
    if keys != tuple(sorted(set(keys))) or any(key.arm_id != value.baseline.arm_id for key in keys):
        raise EvaluationReportError("report scopes must be unique, canonical, and belong to its arm")
    if type(value.operational_evidence) is not ArmOperationalEvidenceV3:
        raise EvaluationReportError("report operational evidence must use exact ArmOperationalEvidenceV3")
    value.operational_evidence.__post_init__()
    if value.combination_lineage is not None:
        if type(value.combination_lineage) is not CombinationLineageV3:
            raise EvaluationReportError("report combination lineage must use exact CombinationLineageV3")
        value.combination_lineage.__post_init__()
        if value.combination_lineage.rule.combined_arm_id != value.baseline.arm_id:
            raise EvaluationReportError("report combination lineage belongs to another arm")


def _report_value(value: ArmEvaluationReportV3) -> canonical.JsonValue:
    return {
        "baseline_digest": value.baseline.baseline_digest,
        "scoped_result_digests": tuple(item.result_digest for item in value.scoped_results),
        "operational_evidence_digest": value.operational_evidence.evidence_digest,
        "combination_lineage_digest": None if value.combination_lineage is None else value.combination_lineage.lineage_digest,
    }


def _gate(kind: GateKind, key: ArmScopeKey, reasons: tuple[str, ...], evidence: tuple[str, ...]) -> GateResult:
    return GateResult(kind, f"{kind.value}:{key.arm_id}:{key.scope.family_id}:{key.scope.ecosystem}", not reasons, reasons, evidence)


def _threshold_value(result: ScopedMetricResultV3, threshold: ScopedThresholdV3) -> float:
    values = {
        Statistic.COUNT: float(result.numerator),
        Statistic.RATE: result.value,
        Statistic.PER_100: result.value,
        Statistic.WILSON_LOWER: result.interval_lower,
        Statistic.WILSON_UPPER: result.interval_upper,
    }
    selected = values[threshold.statistic]
    if selected is None:
        raise EvaluationReportError("completed metric threshold requires a finite observed value")
    return selected


def _scope_result(
    key: ArmScopeKey,
    metrics: tuple[ScopedMetricResultV3, ...],
    cases: tuple[ArmAdmissionCaseResultV3, ...],
    thresholds: tuple[ScopedThresholdV3, ...],
    readiness: tuple[ReadinessResult, ...],
    observations: tuple[ArmObservationSetV3, ...],
) -> ScopeAdmissionResultV3:
    case_evidence = tuple(sorted(case.result_digest for case in cases))
    observation_evidence = tuple(
        sorted({digest for item in observations for digest in (item.input_read_evidence_digest, item.stage_execution_evidence_digest)})
    )
    instrument = _gate(GateKind.INSTRUMENT, key, (), tuple(sorted(set(case_evidence + observation_evidence))))
    exceeded = tuple(sorted(f"budget_exceeded:{case.result_digest}" for case in cases if case.total_reply_ms > case.budget.budget_ms))
    budget = _gate(GateKind.BUDGET, key, exceeded, case_evidence)
    readiness_gate = _gate(GateKind.READINESS, key, (), tuple(sorted(item.result_digest for item in readiness)))
    by_metric = {item.metric_id: item for item in metrics}
    failed = tuple(
        sorted(
            f"threshold_failed:{item.metric_id.value}:{item.statistic.value}"
            for item in thresholds
            if not _threshold_passes(_threshold_value(by_metric[item.metric_id], item), item)
        )
    )
    quality_evidence = tuple(sorted({*(_metric_digest(item) for item in metrics), *(item.threshold_digest for item in thresholds)}))
    quality = _gate(GateKind.QUALITY, key, failed, quality_evidence)
    gates = (instrument, budget, readiness_gate, quality)
    decision = AdmissionDecision.GO if all(item.passed for item in gates) else AdmissionDecision.NO_GO
    return ScopeAdmissionResultV3(key, metrics, *gates, decision, "")


def _threshold_passes(observed: float, threshold: ScopedThresholdV3) -> bool:
    return observed >= threshold.target if threshold.comparator is Comparator.AT_LEAST else observed <= threshold.target


def derive_completed_evaluation_reports_v3(
    plan: EvaluationPlanManifestV3,
    cases_by_arm: tuple[ArmAdmissionCasesV3, ...],
    metrics: tuple[ScopedMetricResultV3, ...],
    readiness: tuple[ReadinessResult, ...],
    observations: tuple[ArmObservationSetV3, ...],
    combination_lineages: tuple[CombinationLineageV3, ...],
    whole_projection: WholePopulationProjectionV3,
) -> tuple[tuple[ArmEvaluationReportV3, ...], WholePopulationCoverageV3]:
    """Derive decisions only after every supplied report input is complete and canonical."""
    try:
        values = _validate_inputs(plan, cases_by_arm, metrics, readiness, observations, combination_lineages, whole_projection)
        _validate_complete_inputs(*values)
        configurations = {item.arm_id: item for item in plan.declaration.arm_configurations}
        metrics_by_key = {key: tuple(item for item in metrics if item.key == key) for key in {item.key for item in metrics}}
        observations_by_arm = {arm_id: tuple(item for item in observations if item.arm_id == arm_id) for arm_id in configurations}
        lineage_by_arm = {item.rule.combined_arm_id: item for item in combination_lineages}
        reports = []
        for baseline, group in zip(plan.baselines, cases_by_arm, strict=True):
            configuration = configurations[baseline.arm_id]
            scoped = tuple(
                _scope_result(
                    policy.key,
                    metrics_by_key[policy.key],
                    tuple(case for case in group.cases if case.key == policy.key),
                    tuple(item for item in configuration.thresholds if item.key == policy.key),
                    readiness,
                    observations_by_arm[baseline.arm_id],
                )
                for policy in configuration.denominator_policies
            )
            reports.append(ArmEvaluationReportV3(baseline, scoped, _operational(group.cases), lineage_by_arm.get(baseline.arm_id), ""))
        whole = WholePopulationCoverageV3(whole_projection.underlying_push_count, whole_projection.underlying_push_count, 0, "")
        return tuple(reports), whole
    except EvaluationReportError:
        raise
    except (AttributeError, KeyError, LookupError, TypeError, ValueError) as exc:
        raise EvaluationReportError(f"completed report derivation refused invalid or incomplete evidence: {exc}") from exc


__all__ = [
    "ArmEvaluationReportV3",
    "ArmOperationalEvidenceV3",
    "DegradationReasonV3",
    "EvaluationReportError",
    "ScopeAdmissionResultV3",
    "WholePopulationCoverageV3",
    "derive_completed_evaluation_reports_v3",
]
