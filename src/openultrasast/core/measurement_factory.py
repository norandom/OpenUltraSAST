"""Canonical constructors for complete measurement aggregates."""

from __future__ import annotations

from openultrasast.core import canonical
from openultrasast.core.coverage import CoverageFunnel, ReasonCount
from openultrasast.core.measurement import BaselineIdentity, MetricResult
from openultrasast.core.measurement_record import (
    BasisCount,
    MeasurementRecordV2,
    OutcomeCount,
    ReadinessReference,
    RepositoryHoldoutReport,
    _record_value,
    _report_value,
    _validate_record_fields,
    _validate_report_fields,
)
from openultrasast.core.readiness import ReadinessEvidenceUse


def create_measurement_record(
    *,
    identity: BaselineIdentity,
    family_decision_vocabulary: tuple[str, ...],
    family_decision_counts: tuple[ReasonCount, ...],
    neutral_outcome_counts: tuple[OutcomeCount, ...],
    evidence_basis_counts: tuple[BasisCount, ...],
    metrics: tuple[MetricResult, ...],
    stage_funnel: CoverageFunnel,
    instrument_failures: tuple[str, ...],
    model_outcome_counts: tuple[ReasonCount, ...],
    model_failures: tuple[str, ...],
    runtime_ms: int,
    prerequisite_readiness: tuple[ReadinessReference, ...],
) -> MeasurementRecordV2:
    values = (
        identity,
        family_decision_vocabulary,
        family_decision_counts,
        neutral_outcome_counts,
        evidence_basis_counts,
        metrics,
        stage_funnel,
        instrument_failures,
        model_outcome_counts,
        model_failures,
        runtime_ms,
        prerequisite_readiness,
    )
    draft = object.__new__(MeasurementRecordV2)
    for field, item in zip(MeasurementRecordV2.__dataclass_fields__, (*values, "0" * 64), strict=True):
        object.__setattr__(draft, field, item)
    _validate_record_fields(draft)
    digest = canonical.content_digest(_record_value(draft))
    return MeasurementRecordV2(*values, digest)


def create_repository_holdout_report(
    *,
    component_digest: str,
    role: ReadinessEvidenceUse,
    training_population_manifest: canonical.ContentRef,
    holdout_population_manifest: canonical.ContentRef,
    training_repository_digests: tuple[str, ...],
    holdout_repository_digests: tuple[str, ...],
    fitting_lineage_manifest_digest: str,
    measurement: MeasurementRecordV2,
) -> RepositoryHoldoutReport:
    values = (
        component_digest,
        role,
        training_population_manifest,
        holdout_population_manifest,
        training_repository_digests,
        holdout_repository_digests,
        fitting_lineage_manifest_digest,
        measurement,
    )
    draft = object.__new__(RepositoryHoldoutReport)
    for field, item in zip(RepositoryHoldoutReport.__dataclass_fields__, (*values, "0" * 64), strict=True):
        object.__setattr__(draft, field, item)
    _validate_report_fields(draft)
    digest = canonical.content_digest(_report_value(draft))
    return RepositoryHoldoutReport(*values, digest)


__all__ = ["create_measurement_record", "create_repository_holdout_report"]
