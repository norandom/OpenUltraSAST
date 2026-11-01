"""Complete measurement record and repository-holdout contracts."""

from __future__ import annotations

from dataclasses import replace

import pytest
from test_core_measurement import _baseline, _scopes

from openultrasast.core import canonical
from openultrasast.core.coverage import CoverageFunnel, ReasonCount, RelationStatusCount
from openultrasast.core.evidence import EvidenceBasis, NeutralOutcome
from openultrasast.core.measurement import MetricId, evaluate_metric, standard_metric_rules
from openultrasast.core.measurement_factory import create_measurement_record, create_repository_holdout_report
from openultrasast.core.measurement_record import (
    BasisCount,
    MeasurementRecordError,
    MeasurementRecordV2,
    OutcomeCount,
    ReadinessReference,
    RepositoryHoldoutReport,
    measurement_record_value,
    repository_holdout_report_value,
    validate_measurement_record,
    validate_repository_holdout_report,
)
from openultrasast.core.readiness import ReadinessEvidenceUse, ReadinessStage, StageResult
from openultrasast.core.semantics import RelationStatus


def _digest(label: str) -> str:
    return canonical.content_digest(label)


def _funnel(*, inputs_read: int = 1, findings: int = 1) -> CoverageFunnel:
    return CoverageFunnel(
        inputs_read=inputs_read,
        questions_formed=2,
        sites_considered=2,
        sites_recognized=2,
        transitions_materialized=2,
        security_objects_constructed=2,
        constraints_evaluated=2,
        determinate_outcomes=2,
        findings_emitted=findings,
        relation_status_counts=(
            RelationStatusCount(RelationStatus.COMPLETE, 2),
            RelationStatusCount(RelationStatus.INCOMPLETE, 0),
            RelationStatusCount(RelationStatus.UNRESOLVED, 0),
        ),
        unresolved_by_reason=(),
    )


def _readiness(*, result: StageResult = StageResult.PASSED) -> tuple[ReadinessReference, ...]:
    return tuple(
        ReadinessReference(stage, result, _digest(f"readiness:{stage.value}:{result.value}")) for stage in tuple(ReadinessStage)[:5]
    )


def _metrics(*, model_numerator: int = 1, model_denominator: int = 2) -> tuple[object, ...]:
    return tuple(
        evaluate_metric(
            rule,
            numerator=model_numerator if rule.metric_id is MetricId.MODEL_SUCCESS_RATE else 1,
            denominator=model_denominator if rule.metric_id is MetricId.MODEL_SUCCESS_RATE else 2,
        )
        for rule in standard_metric_rules(_scopes())
    )


def _record(**overrides: object) -> MeasurementRecordV2:
    values: dict[str, object] = {
        "identity": _baseline(),
        "family_decision_vocabulary": ("allow", "deny"),
        "family_decision_counts": (ReasonCount("allow", 1), ReasonCount("deny", 1)),
        "neutral_outcome_counts": (
            OutcomeCount(NeutralOutcome.VIOLATION, 1),
            OutcomeCount(NeutralOutcome.SATISFIED, 1),
            OutcomeCount(NeutralOutcome.INDETERMINATE, 0),
        ),
        "evidence_basis_counts": (
            BasisCount(EvidenceBasis.DETERMINISTIC, 1),
            BasisCount(EvidenceBasis.MODEL_CORROBORATED, 0),
            BasisCount(EvidenceBasis.EXECUTION_BACKED, 0),
        ),
        "metrics": _metrics(),
        "stage_funnel": _funnel(),
        "instrument_failures": (),
        "model_outcome_counts": (ReasonCount("failure", 1), ReasonCount("success", 1)),
        "model_failures": ("timeout",),
        "runtime_ms": 12,
        "prerequisite_readiness": _readiness(),
    }
    values.update(overrides)
    values.pop("record_digest", None)
    return create_measurement_record(**values)  # type: ignore[arg-type]


def _ref(label: str, *, byte_length: int = 12) -> canonical.ContentRef:
    return canonical.ContentRef(
        label,
        _digest(f"content:{label}"),
        "application/json",
        byte_length,
        _digest(f"retention:{label}"),
        _digest(f"receipt:{label}"),
    )


def _report(measurement: MeasurementRecordV2 | None = None, **overrides: object) -> RepositoryHoldoutReport:
    record = measurement or _record()
    values: dict[str, object] = {
        "component_digest": record.identity.model_program_digests[0],
        "role": ReadinessEvidenceUse.REPOSITORY_HOLDOUT,
        "training_population_manifest": _ref("training"),
        "holdout_population_manifest": _ref("holdout"),
        "training_repository_digests": (_digest("repo:training"),),
        "holdout_repository_digests": (_digest("repo:holdout"),),
        "fitting_lineage_manifest_digest": _digest("fitting-lineage"),
        "measurement": record,
    }
    values.update(overrides)
    values.pop("report_digest", None)
    return create_repository_holdout_report(**values)  # type: ignore[arg-type]


def test_complete_measurement_record_is_canonical_and_replayable() -> None:
    record = _record()
    validate_measurement_record(record)
    assert record.record_digest == canonical.content_digest(measurement_record_value(record))
    assert tuple(item.metric_id for item in record.metrics) == tuple(MetricId)
    assert record.record_digest != record.identity.population_digest


def test_record_requires_every_fixed_metric_and_complete_count_fields() -> None:
    record = _record()
    with pytest.raises(MeasurementRecordError, match="standard metric"):
        replace(record, metrics=record.metrics[:-1], record_digest="")
    with pytest.raises(MeasurementRecordError, match="outcome count"):
        replace(record, neutral_outcome_counts=record.neutral_outcome_counts[:-1], record_digest="")
    with pytest.raises(MeasurementRecordError, match="basis count"):
        replace(record, evidence_basis_counts=record.evidence_basis_counts[:-1], record_digest="")


def test_decision_vocabulary_counts_and_funnel_totals_must_agree() -> None:
    record = _record()
    with pytest.raises(MeasurementRecordError, match="decision vocabulary"):
        replace(record, family_decision_counts=(ReasonCount("unknown", 2),), record_digest="")
    with pytest.raises(MeasurementRecordError, match="question count"):
        replace(record, family_decision_counts=(ReasonCount("allow", 1),), record_digest="")
    with pytest.raises(MeasurementRecordError, match="determinate"):
        replace(
            record,
            neutral_outcome_counts=(
                OutcomeCount(NeutralOutcome.VIOLATION, 0),
                OutcomeCount(NeutralOutcome.SATISFIED, 1),
                OutcomeCount(NeutralOutcome.INDETERMINATE, 1),
            ),
            record_digest="",
        )


def test_later_measurement_carries_canonical_prerequisite_results_and_digests() -> None:
    record = _record()
    assert tuple(item.stage for item in record.prerequisite_readiness) == tuple(ReadinessStage)[:5]
    with pytest.raises(MeasurementRecordError, match="prerequisite readiness"):
        replace(record, prerequisite_readiness=record.prerequisite_readiness[:-1], record_digest="")
    with pytest.raises(MeasurementRecordError, match="readiness digest"):
        replace(
            record,
            prerequisite_readiness=(replace(record.prerequisite_readiness[0], result_digest="bad"),) + record.prerequisite_readiness[1:],
            record_digest="",
        )


def test_clean_or_zero_looking_results_require_read_inputs_and_passed_stages() -> None:
    clean = _record(
        family_decision_counts=(ReasonCount("allow", 2),),
        neutral_outcome_counts=(
            OutcomeCount(NeutralOutcome.VIOLATION, 0),
            OutcomeCount(NeutralOutcome.SATISFIED, 2),
            OutcomeCount(NeutralOutcome.INDETERMINATE, 0),
        ),
        evidence_basis_counts=tuple(BasisCount(basis, 0) for basis in EvidenceBasis),
        metrics=_metrics(model_numerator=2, model_denominator=2),
        stage_funnel=_funnel(findings=0),
        model_outcome_counts=(ReasonCount("success", 2),),
        model_failures=(),
    )
    with pytest.raises(MeasurementRecordError, match="tracked input"):
        replace(clean, stage_funnel=_funnel(inputs_read=0, findings=0), record_digest="")
    with pytest.raises(MeasurementRecordError, match="passed readiness"):
        replace(clean, prerequisite_readiness=_readiness(result=StageResult.FAILED), record_digest="")


def test_named_instrument_failure_cannot_make_an_all_zero_run_valid() -> None:
    zero_funnel = CoverageFunnel(
        inputs_read=0,
        questions_formed=0,
        sites_considered=0,
        sites_recognized=0,
        transitions_materialized=0,
        security_objects_constructed=0,
        constraints_evaluated=0,
        determinate_outcomes=0,
        findings_emitted=0,
        relation_status_counts=tuple(RelationStatusCount(status, 0) for status in RelationStatus),
        unresolved_by_reason=(),
    )
    zero_metrics = tuple(evaluate_metric(rule, numerator=0, denominator=0) for rule in standard_metric_rules(_scopes()))
    with pytest.raises(MeasurementRecordError, match="tracked input"):
        _record(
            family_decision_counts=(),
            neutral_outcome_counts=tuple(OutcomeCount(outcome, 0) for outcome in NeutralOutcome),
            evidence_basis_counts=tuple(BasisCount(basis, 0) for basis in EvidenceBasis),
            metrics=zero_metrics,
            stage_funnel=zero_funnel,
            instrument_failures=("frontend_failed",),
            model_outcome_counts=(),
            model_failures=(),
            prerequisite_readiness=_readiness(result=StageResult.FAILED),
        )
    with pytest.raises(MeasurementRecordError, match="passed readiness"):
        _record(
            family_decision_counts=(),
            neutral_outcome_counts=tuple(OutcomeCount(outcome, 0) for outcome in NeutralOutcome),
            evidence_basis_counts=tuple(BasisCount(basis, 0) for basis in EvidenceBasis),
            metrics=zero_metrics,
            stage_funnel=replace(zero_funnel, inputs_read=1),
            instrument_failures=("one_optional_input_failed",),
            model_outcome_counts=(),
            model_failures=(),
            prerequisite_readiness=_readiness(result=StageResult.FAILED),
        )


def test_nonzero_partial_failed_measurement_preserves_named_failures() -> None:
    record = _record(
        instrument_failures=("one_optional_input_failed",),
        prerequisite_readiness=_readiness(result=StageResult.FAILED),
    )
    validate_measurement_record(record)
    assert record.instrument_failures == ("one_optional_input_failed",)


@pytest.mark.parametrize("mixed_denominators", [False, True])
def test_zero_outputs_with_positive_or_mixed_denominators_require_instrument_proof(mixed_denominators: bool) -> None:
    zero_funnel = CoverageFunnel(
        inputs_read=0,
        questions_formed=0,
        sites_considered=0,
        sites_recognized=0,
        transitions_materialized=0,
        security_objects_constructed=0,
        constraints_evaluated=0,
        determinate_outcomes=0,
        findings_emitted=0,
        relation_status_counts=tuple(RelationStatusCount(status, 0) for status in RelationStatus),
        unresolved_by_reason=(),
    )
    metrics = tuple(
        evaluate_metric(rule, numerator=0, denominator=0 if mixed_denominators and index % 2 == 0 else 2)
        for index, rule in enumerate(standard_metric_rules(_scopes()))
    )
    model_denominator = next(item.denominator for item in metrics if item.metric_id is MetricId.MODEL_SUCCESS_RATE)
    with pytest.raises(MeasurementRecordError, match="tracked input"):
        _record(
            family_decision_counts=(),
            neutral_outcome_counts=tuple(OutcomeCount(outcome, 0) for outcome in NeutralOutcome),
            evidence_basis_counts=tuple(BasisCount(basis, 0) for basis in EvidenceBasis),
            metrics=metrics,
            stage_funnel=zero_funnel,
            instrument_failures=("frontend_failed",),
            model_outcome_counts=(ReasonCount("failure", model_denominator),) if model_denominator else (),
            model_failures=("timeout",) if model_denominator else (),
            prerequisite_readiness=_readiness(result=StageResult.FAILED),
        )


def test_zero_output_is_valid_with_reads_and_passed_prerequisites() -> None:
    funnel = CoverageFunnel(
        inputs_read=1,
        questions_formed=0,
        sites_considered=0,
        sites_recognized=0,
        transitions_materialized=0,
        security_objects_constructed=0,
        constraints_evaluated=0,
        determinate_outcomes=0,
        findings_emitted=0,
        relation_status_counts=tuple(RelationStatusCount(status, 0) for status in RelationStatus),
        unresolved_by_reason=(),
    )
    metrics = tuple(evaluate_metric(rule, numerator=0, denominator=2) for rule in standard_metric_rules(_scopes()))
    record = _record(
        family_decision_counts=(),
        neutral_outcome_counts=tuple(OutcomeCount(outcome, 0) for outcome in NeutralOutcome),
        evidence_basis_counts=tuple(BasisCount(basis, 0) for basis in EvidenceBasis),
        metrics=metrics,
        stage_funnel=funnel,
        instrument_failures=(),
        model_outcome_counts=(ReasonCount("failure", 2),),
        model_failures=("timeout",),
        prerequisite_readiness=_readiness(),
    )
    validate_measurement_record(record)


def test_failures_runtime_and_record_identity_are_not_optional_or_forgeable() -> None:
    record = _record()
    with pytest.raises(MeasurementRecordError, match="instrument_failures"):
        replace(record, instrument_failures=None, record_digest="")  # type: ignore[arg-type]
    with pytest.raises(MeasurementRecordError, match="model_failures"):
        replace(record, model_failures=None, record_digest="")  # type: ignore[arg-type]
    with pytest.raises(MeasurementRecordError, match="runtime"):
        replace(record, runtime_ms=0, record_digest="")
    with pytest.raises(MeasurementRecordError, match="record digest"):
        replace(record, record_digest=_digest("forged-record"))
    with pytest.raises(MeasurementRecordError, match="record digest"):
        replace(record, record_digest="")


def test_model_outcomes_and_failures_reconcile_with_fixed_metric() -> None:
    with pytest.raises(MeasurementRecordError, match="model outcome counts"):
        _record(model_outcome_counts=(ReasonCount("success", 1),))
    with pytest.raises(MeasurementRecordError, match="named model_failures"):
        _record(model_failures=())


def test_model_success_outcome_count_must_equal_metric_numerator() -> None:
    canonical = _record(
        model_outcome_counts=(ReasonCount("failure", 1), ReasonCount("success", 1)),
        model_failures=("timeout",),
    )
    validate_measurement_record(canonical)
    with pytest.raises(MeasurementRecordError, match="successful model outcome"):
        _record(model_outcome_counts=(ReasonCount("success", 2),), model_failures=("timeout",))
    with pytest.raises(MeasurementRecordError, match="closed success/failure vocabulary"):
        _record(
            model_outcome_counts=(ReasonCount("failure", 1), ReasonCount("unknown", 1)),
            model_failures=("timeout",),
        )


def test_repository_holdout_report_binds_disjoint_manifests_and_measurement() -> None:
    report = _report()
    validate_repository_holdout_report(report)
    assert report.role is ReadinessEvidenceUse.REPOSITORY_HOLDOUT
    assert report.report_digest == canonical.content_digest(repository_holdout_report_value(report))
    assert report.report_digest != report.measurement.record_digest


def test_family_decision_counts_follow_declared_not_lexical_order() -> None:
    record = _record(
        family_decision_vocabulary=("deny", "allow"),
        family_decision_counts=(ReasonCount("deny", 1), ReasonCount("allow", 1)),
    )
    validate_measurement_record(record)
    assert tuple(item.reason for item in record.family_decision_counts) == record.family_decision_vocabulary


def test_family_decision_counts_retain_zero_entries_for_exact_vocabulary() -> None:
    record = _record(
        family_decision_vocabulary=("allow", "deny", "unknown"),
        family_decision_counts=(ReasonCount("allow", 1), ReasonCount("deny", 1), ReasonCount("unknown", 0)),
    )

    assert tuple((item.reason, item.count) for item in record.family_decision_counts) == (
        ("allow", 1),
        ("deny", 1),
        ("unknown", 0),
    )


def test_holdout_report_refuses_wrong_role_overlap_or_empty_manifests() -> None:
    report = _report()
    with pytest.raises(MeasurementRecordError, match="repository_holdout"):
        replace(report, role=ReadinessEvidenceUse.DEVELOPMENT_POPULATION, report_digest="")
    with pytest.raises(MeasurementRecordError, match="disjoint"):
        replace(report, holdout_repository_digests=report.training_repository_digests, report_digest="")
    with pytest.raises(MeasurementRecordError, match="nonempty"):
        replace(report, holdout_repository_digests=(), report_digest="")
    with pytest.raises(MeasurementRecordError, match="nonzero"):
        replace(report, holdout_population_manifest=_ref("holdout-zero", byte_length=0), report_digest="")


def test_holdout_report_refuses_component_manifest_and_identity_substitution() -> None:
    report = _report()
    with pytest.raises(MeasurementRecordError, match="component"):
        replace(report, component_digest=_digest("another-component"), report_digest="")
    with pytest.raises(MeasurementRecordError, match="distinct"):
        replace(report, holdout_population_manifest=report.training_population_manifest, report_digest="")
    with pytest.raises(MeasurementRecordError, match="report digest"):
        replace(report, report_digest=_digest("forged-report"))
    with pytest.raises(MeasurementRecordError, match="report digest"):
        replace(report, report_digest="")
    with pytest.raises(MeasurementRecordError, match="distinct from measurement"):
        replace(report, report_digest=report.measurement.record_digest)
