"""Complete measurement records and repository-holdout reports."""

from __future__ import annotations

import re
from dataclasses import dataclass

from openultrasast.core import canonical
from openultrasast.core.coverage import CoverageFunnel, ReasonCount
from openultrasast.core.evidence import EvidenceBasis, NeutralOutcome
from openultrasast.core.measurement import (
    BaselineIdentity,
    MetricId,
    MetricResult,
    derive_baseline_identity_digest,
    metric_result_value,
)
from openultrasast.core.readiness import ReadinessEvidenceUse, ReadinessStage, StageResult

MEASUREMENT_RECORD_SCHEMA = "openultrasast.detection-core.measurement-record.v2"
REPOSITORY_HOLDOUT_REPORT_SCHEMA = "openultrasast.detection-core.repository-holdout-report.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_PREREQUISITE_STAGES = tuple(ReadinessStage)[:6]


class MeasurementRecordError(ValueError):
    """A measurement or holdout report violates the fixed schema."""


def _digest(value: object, field: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise MeasurementRecordError(f"{field} must be a full lowercase SHA-256 digest")


def _count(value: object, field: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        qualifier = "positive" if positive else "non-negative"
        raise MeasurementRecordError(f"{field} must be a {qualifier} integer")
    return value


def _text_tuple(value: object, field: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, tuple) or (not value and not allow_empty):
        qualifier = "a tuple" if allow_empty else "a nonempty tuple"
        raise MeasurementRecordError(f"{field} must be {qualifier} of nonempty text")
    if not all(isinstance(item, str) and item for item in value):
        raise MeasurementRecordError(f"{field} must contain nonempty text")
    if len(set(value)) != len(value):
        raise MeasurementRecordError(f"{field} contains a duplicate")
    return value


def _canonical_digest_tuple(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, tuple) or not value:
        raise MeasurementRecordError(f"{field} must be a nonempty tuple")
    for item in value:
        _digest(item, field.removesuffix("s"))
    if value != tuple(sorted(value)):
        raise MeasurementRecordError(f"{field} must use canonical order")
    if len(set(value)) != len(value):
        raise MeasurementRecordError(f"{field} contains a duplicate")
    return value


@dataclass(frozen=True)
class OutcomeCount:
    outcome: NeutralOutcome
    count: int

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, NeutralOutcome):
            raise MeasurementRecordError("outcome count must use NeutralOutcome")
        _count(self.count, "outcome count")


@dataclass(frozen=True)
class BasisCount:
    basis: EvidenceBasis
    count: int

    def __post_init__(self) -> None:
        if not isinstance(self.basis, EvidenceBasis):
            raise MeasurementRecordError("basis count must use EvidenceBasis")
        _count(self.count, "basis count")


@dataclass(frozen=True)
class ReadinessReference:
    stage: ReadinessStage
    result: StageResult
    result_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.stage, ReadinessStage):
            raise MeasurementRecordError("readiness stage must use ReadinessStage")
        if not isinstance(self.result, StageResult):
            raise MeasurementRecordError("readiness result must use StageResult")
        _digest(self.result_digest, "readiness digest")


@dataclass(frozen=True)
class MeasurementRecordV2:
    identity: BaselineIdentity
    family_decision_vocabulary: tuple[str, ...]
    family_decision_counts: tuple[ReasonCount, ...]
    neutral_outcome_counts: tuple[OutcomeCount, ...]
    evidence_basis_counts: tuple[BasisCount, ...]
    metrics: tuple[MetricResult, ...]
    stage_funnel: CoverageFunnel
    instrument_failures: tuple[str, ...]
    model_outcome_counts: tuple[ReasonCount, ...]
    model_failures: tuple[str, ...]
    runtime_ms: int
    prerequisite_readiness: tuple[ReadinessReference, ...]
    record_digest: str

    def __post_init__(self) -> None:
        validate_measurement_record(self)


@dataclass(frozen=True)
class RepositoryHoldoutReport:
    component_digest: str
    role: ReadinessEvidenceUse
    training_population_manifest: canonical.ContentRef
    holdout_population_manifest: canonical.ContentRef
    training_repository_digests: tuple[str, ...]
    holdout_repository_digests: tuple[str, ...]
    fitting_lineage_manifest_digest: str
    measurement: MeasurementRecordV2
    report_digest: str

    def __post_init__(self) -> None:
        validate_repository_holdout_report(self)


def _reason_count_value(value: ReasonCount) -> canonical.JsonValue:
    return {"reason": value.reason, "count": value.count}


def _outcome_count_value(value: OutcomeCount) -> canonical.JsonValue:
    return {"outcome": value.outcome.value, "count": value.count}


def _basis_count_value(value: BasisCount) -> canonical.JsonValue:
    return {"basis": value.basis.value, "count": value.count}


def _readiness_value(value: ReadinessReference) -> canonical.JsonValue:
    return {"stage": value.stage.value, "result": value.result.value, "result_digest": value.result_digest}


def _funnel_value(value: CoverageFunnel) -> canonical.JsonValue:
    return {
        "inputs_read": value.inputs_read,
        "questions_formed": value.questions_formed,
        "sites_considered": value.sites_considered,
        "sites_recognized": value.sites_recognized,
        "transitions_materialized": value.transitions_materialized,
        "security_objects_constructed": value.security_objects_constructed,
        "constraints_evaluated": value.constraints_evaluated,
        "determinate_outcomes": value.determinate_outcomes,
        "findings_emitted": value.findings_emitted,
        "relation_status_counts": tuple({"status": item.status.value, "count": item.count} for item in value.relation_status_counts),
        "unresolved_by_reason": tuple(_reason_count_value(item) for item in value.unresolved_by_reason),
    }


def _content_ref_value(value: canonical.ContentRef) -> canonical.JsonValue:
    return {
        "artifact_id": value.artifact_id,
        "content_digest": value.content_digest,
        "media_type": value.media_type,
        "byte_length": value.byte_length,
        "retention_policy_digest": value.retention_policy_digest,
        "storage_receipt_digest": value.storage_receipt_digest,
    }


def _validate_named_counts(
    values: object,
    field: str,
    *,
    allowed: tuple[str, ...] | None = None,
    canonical_order: bool = True,
) -> tuple[ReasonCount, ...]:
    if not isinstance(values, tuple) or not all(isinstance(item, ReasonCount) for item in values):
        raise MeasurementRecordError(f"{field} must be a tuple of ReasonCount values")
    for item in values:
        item.__post_init__()
    names = tuple(item.reason for item in values)
    if len(names) != len(set(names)):
        raise MeasurementRecordError(f"{field} contains a duplicate")
    if canonical_order and names != tuple(sorted(names)):
        raise MeasurementRecordError(f"{field} must use canonical order")
    if allowed is not None and any(name not in allowed for name in names):
        raise MeasurementRecordError("family decision counts must use the decision vocabulary")
    return values


def _validate_enum_counts(value: MeasurementRecordV2) -> None:
    if not isinstance(value.neutral_outcome_counts, tuple) or tuple(
        item.outcome for item in value.neutral_outcome_counts if isinstance(item, OutcomeCount)
    ) != tuple(NeutralOutcome):
        raise MeasurementRecordError("outcome counts must contain every neutral outcome in canonical order")
    if not isinstance(value.evidence_basis_counts, tuple) or tuple(
        item.basis for item in value.evidence_basis_counts if isinstance(item, BasisCount)
    ) != tuple(EvidenceBasis):
        raise MeasurementRecordError("basis counts must contain every evidence basis in canonical order")
    for outcome_count in value.neutral_outcome_counts:
        outcome_count.__post_init__()
    for basis_count in value.evidence_basis_counts:
        basis_count.__post_init__()


def _validate_metrics(value: MeasurementRecordV2) -> None:
    if not isinstance(value.metrics, tuple) or not all(isinstance(item, MetricResult) for item in value.metrics):
        raise MeasurementRecordError("metrics must be a tuple of MetricResult values")
    if tuple(item.metric_id for item in value.metrics) != tuple(MetricId):
        raise MeasurementRecordError("metrics must contain every standard metric in canonical order")
    for item in value.metrics:
        metric_result_value(item)


def _validate_readiness(value: MeasurementRecordV2) -> None:
    references = value.prerequisite_readiness
    if not isinstance(references, tuple) or not all(isinstance(item, ReadinessReference) for item in references):
        raise MeasurementRecordError("prerequisite readiness must contain ReadinessReference values")
    if tuple(item.stage for item in references) != _PREREQUISITE_STAGES:
        raise MeasurementRecordError("prerequisite readiness must contain every earlier stage in canonical order")
    for item in references:
        item.__post_init__()
    if len({item.result_digest for item in references}) != len(references):
        raise MeasurementRecordError("prerequisite readiness contains a copied readiness digest")


def _validate_record_fields(value: MeasurementRecordV2) -> None:
    if not isinstance(value.identity, BaselineIdentity):
        raise MeasurementRecordError("identity must be a BaselineIdentity")
    derive_baseline_identity_digest(value.identity)
    vocabulary = _text_tuple(value.family_decision_vocabulary, "family decision vocabulary", allow_empty=False)
    decisions = _validate_named_counts(
        value.family_decision_counts,
        "family decision counts",
        allowed=vocabulary,
        canonical_order=False,
    )
    if tuple(item.reason for item in decisions) != tuple(name for name in vocabulary if name in {i.reason for i in decisions}):
        raise MeasurementRecordError("family decision counts must follow decision vocabulary order")
    _validate_enum_counts(value)
    _validate_metrics(value)
    if not isinstance(value.stage_funnel, CoverageFunnel):
        raise MeasurementRecordError("stage_funnel must be a CoverageFunnel")
    value.stage_funnel.__post_init__()
    _text_tuple(value.instrument_failures, "instrument_failures")
    _validate_named_counts(value.model_outcome_counts, "model outcome counts")
    _text_tuple(value.model_failures, "model_failures")
    _count(value.runtime_ms, "runtime", positive=True)
    _validate_readiness(value)
    _validate_record_totals(value, decisions)


def _validate_record_totals(value: MeasurementRecordV2, decisions: tuple[ReasonCount, ...]) -> None:
    question_count = value.stage_funnel.questions_formed
    if sum(item.count for item in decisions) != question_count:
        raise MeasurementRecordError("family decision counts must equal the question count")
    if sum(item.count for item in value.neutral_outcome_counts) != question_count:
        raise MeasurementRecordError("neutral outcome counts must equal the question count")
    if sum(item.count for item in value.evidence_basis_counts) != value.stage_funnel.findings_emitted:
        raise MeasurementRecordError("evidence basis counts must equal emitted findings")
    determinate = sum(item.count for item in value.neutral_outcome_counts if item.outcome is not NeutralOutcome.INDETERMINATE)
    if determinate != value.stage_funnel.determinate_outcomes:
        raise MeasurementRecordError("determinate outcome counts must equal the funnel determinate count")
    violation_count = next(item.count for item in value.neutral_outcome_counts if item.outcome is NeutralOutcome.VIOLATION)
    if value.stage_funnel.findings_emitted > violation_count:
        raise MeasurementRecordError("findings cannot exceed violation outcomes")
    _validate_model_totals(value)
    _validate_clean_measurement(value)


def _validate_model_totals(value: MeasurementRecordV2) -> None:
    model_metric = next(item for item in value.metrics if item.metric_id is MetricId.MODEL_SUCCESS_RATE)
    by_outcome = {item.reason: item.count for item in value.model_outcome_counts}
    if not set(by_outcome) <= {"failure", "success"}:
        raise MeasurementRecordError("model outcomes must use the closed success/failure vocabulary")
    successful = by_outcome.get("success", 0)
    failed = by_outcome.get("failure", 0)
    if successful != model_metric.numerator:
        raise MeasurementRecordError("successful model outcome count must equal the model-success numerator")
    if failed != model_metric.denominator - model_metric.numerator:
        raise MeasurementRecordError("model outcome counts for failure must equal model calls minus successes")
    if successful + failed != model_metric.denominator:
        raise MeasurementRecordError("model outcome counts must equal the model-call denominator")
    if failed and not value.model_failures:
        raise MeasurementRecordError("failed model calls require named model_failures")
    if not failed and value.model_failures:
        raise MeasurementRecordError("model_failures require a failed model outcome")


def _validate_clean_measurement(value: MeasurementRecordV2) -> None:
    if not (_zero_measurement(value) or _clean_looking(value)):
        return
    if value.stage_funnel.inputs_read <= 0:
        raise MeasurementRecordError("zero or clean-looking measurement requires a tracked input read")
    if any(item.result is not StageResult.PASSED for item in value.prerequisite_readiness):
        raise MeasurementRecordError("zero or clean-looking measurement requires passed readiness prerequisites")


def _zero_measurement(value: MeasurementRecordV2) -> bool:
    funnel = value.stage_funnel
    downstream = (
        funnel.questions_formed,
        funnel.sites_considered,
        funnel.sites_recognized,
        funnel.transitions_materialized,
        funnel.security_objects_constructed,
        funnel.constraints_evaluated,
        funnel.determinate_outcomes,
        funnel.findings_emitted,
    )
    return not any(downstream) and all(item.numerator == 0 for item in value.metrics)


def _clean_looking(value: MeasurementRecordV2) -> bool:
    violation = next(item.count for item in value.neutral_outcome_counts if item.outcome is NeutralOutcome.VIOLATION)
    return value.stage_funnel.findings_emitted == 0 and violation == 0 and not value.instrument_failures and not value.model_failures


def _record_value(value: MeasurementRecordV2) -> canonical.JsonValue:
    return {
        "schema_version": MEASUREMENT_RECORD_SCHEMA,
        "baseline_identity_digest": derive_baseline_identity_digest(value.identity),
        "family_decision_vocabulary": value.family_decision_vocabulary,
        "family_decision_counts": tuple(_reason_count_value(item) for item in value.family_decision_counts),
        "neutral_outcome_counts": tuple(_outcome_count_value(item) for item in value.neutral_outcome_counts),
        "evidence_basis_counts": tuple(_basis_count_value(item) for item in value.evidence_basis_counts),
        "metrics": tuple(metric_result_value(item) for item in value.metrics),
        "stage_funnel": _funnel_value(value.stage_funnel),
        "instrument_failures": value.instrument_failures,
        "model_outcome_counts": tuple(_reason_count_value(item) for item in value.model_outcome_counts),
        "model_failures": value.model_failures,
        "runtime_ms": value.runtime_ms,
        "prerequisite_readiness": tuple(_readiness_value(item) for item in value.prerequisite_readiness),
    }


def validate_measurement_record(value: MeasurementRecordV2) -> None:
    if not isinstance(value, MeasurementRecordV2):
        raise MeasurementRecordError("measurement must be a MeasurementRecordV2")
    try:
        _validate_record_fields(value)
    except MeasurementRecordError:
        raise
    except (TypeError, ValueError) as exc:
        raise MeasurementRecordError(str(exc)) from exc
    expected = canonical.content_digest(_record_value(value))
    _digest(value.record_digest, "record digest")
    if value.record_digest != expected:
        raise MeasurementRecordError("record digest does not match measurement content")


def validate_repository_holdout_report(value: RepositoryHoldoutReport) -> None:
    if not isinstance(value, RepositoryHoldoutReport):
        raise MeasurementRecordError("report must be a RepositoryHoldoutReport")
    _validate_report_fields(value)
    if value.report_digest == value.measurement.record_digest:
        raise MeasurementRecordError("report identity must be distinct from measurement identity")
    expected = canonical.content_digest(_report_value(value))
    _digest(value.report_digest, "report digest")
    if value.report_digest != expected:
        raise MeasurementRecordError("report digest does not match holdout content")


def _validate_report_fields(value: RepositoryHoldoutReport) -> None:
    _digest(value.component_digest, "component digest")
    if value.role is not ReadinessEvidenceUse.REPOSITORY_HOLDOUT:
        raise MeasurementRecordError("holdout report role must be repository_holdout")
    _validate_content_ref(value.training_population_manifest, "training population manifest")
    _validate_content_ref(value.holdout_population_manifest, "holdout population manifest")
    if value.training_population_manifest.content_digest == value.holdout_population_manifest.content_digest:
        raise MeasurementRecordError("training and holdout manifests must be distinct")
    training = _canonical_digest_tuple(value.training_repository_digests, "training repository digests")
    holdout = _canonical_digest_tuple(value.holdout_repository_digests, "holdout repository digests")
    if set(training) & set(holdout):
        raise MeasurementRecordError("training and holdout repositories must be disjoint")
    _digest(value.fitting_lineage_manifest_digest, "fitting lineage manifest digest")
    validate_measurement_record(value.measurement)
    if value.component_digest not in value.measurement.identity.model_program_digests:
        raise MeasurementRecordError("holdout component must be an exact measured model component")


def _validate_content_ref(value: object, field: str) -> None:
    if not isinstance(value, canonical.ContentRef):
        raise MeasurementRecordError(f"{field} must be a ContentRef")
    try:
        value.__post_init__()
    except (TypeError, ValueError) as exc:
        raise MeasurementRecordError(str(exc)) from exc
    if value.byte_length <= 0:
        raise MeasurementRecordError(f"{field} must have nonzero bytes")


def _report_value(value: RepositoryHoldoutReport) -> canonical.JsonValue:
    return {
        "schema_version": REPOSITORY_HOLDOUT_REPORT_SCHEMA,
        "component_digest": value.component_digest,
        "role": value.role.value,
        "training_population_manifest": _content_ref_value(value.training_population_manifest),
        "holdout_population_manifest": _content_ref_value(value.holdout_population_manifest),
        "training_repository_digests": value.training_repository_digests,
        "holdout_repository_digests": value.holdout_repository_digests,
        "fitting_lineage_manifest_digest": value.fitting_lineage_manifest_digest,
        "measurement_record_digest": value.measurement.record_digest,
    }


def measurement_record_value(value: MeasurementRecordV2) -> canonical.JsonValue:
    validate_measurement_record(value)
    return _record_value(value)


def repository_holdout_report_value(value: RepositoryHoldoutReport) -> canonical.JsonValue:
    validate_repository_holdout_report(value)
    return _report_value(value)


__all__ = [
    "BasisCount",
    "MeasurementRecordError",
    "MeasurementRecordV2",
    "OutcomeCount",
    "ReadinessReference",
    "RepositoryHoldoutReport",
    "measurement_record_value",
    "repository_holdout_report_value",
    "validate_measurement_record",
    "validate_repository_holdout_report",
]
