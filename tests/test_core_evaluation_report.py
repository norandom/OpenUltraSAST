"""Completed exact-scope decisions and operational evidence for evaluation V3."""

from __future__ import annotations

from dataclasses import replace

import pytest
from test_core_evaluation_case_validation import _bundle, _reference_authority_case

from openultrasast.core import canonical
from openultrasast.core.admission_report import AdmissionDecision
from openultrasast.core.evaluation_combination import derive_combination_lineages_v3
from openultrasast.core.evaluation_measurement import MetricId, ScopedMetricResultV3
from openultrasast.core.evaluation_release import derive_released_arm_case_binding
from openultrasast.core.readiness import StageResult


def _passing_metrics(bundle) -> tuple[ScopedMetricResultV3, ...]:
    counts = {
        MetricId.PAIRED_CORRECTNESS: (1, 1),
        MetricId.VULNERABLE_RECALL: (1, 1),
        MetricId.FIXED_FALSE_ALARM_RATE: (0, 1),
        MetricId.ORDINARY_FALSE_ALARMS_PER_100: (0, 1),
        MetricId.PRECISION: (1, 1),
        MetricId.SEMANTIC_STAGE_COVERAGE: (6, 6),
        MetricId.MODEL_SUCCESS_RATE: (1, 1),
    }
    return tuple(
        ScopedMetricResultV3.from_counts(policy.key, metric_id, numerator=counts[metric_id][0], denominator=counts[metric_id][1])
        for configuration in bundle[3].plan_manifest.declaration.arm_configurations
        for policy in configuration.denominator_policies
        for metric_id in MetricId
    )


def _inputs(*, metrics=None, readiness=None, observations=None, groups=None, lineages=None, whole=None):
    bundle = _bundle(authority_case=_reference_authority_case(), aligned_combination_cases=True)
    plan = bundle[3].plan_manifest
    selected_readiness = tuple(bundle[5][0].readiness) if readiness is None else readiness
    selected_observations = bundle[5][4] if observations is None else observations
    selected_groups = bundle[2] if groups is None else groups
    selected_lineages = _canonical_lineages(bundle) if lineages is None else lineages
    if whole is None:
        from openultrasast.core.evaluation_ordinary_projection import WholePopulationProjectionV3

        pushes = tuple(sorted({case.underlying_push_digest for group in bundle[2] for case in group.cases}))
        selected_whole = WholePopulationProjectionV3(pushes, len(pushes), "")
    else:
        selected_whole = whole
    selected_metrics = _passing_metrics(bundle) if metrics is None else metrics
    return plan, selected_groups, selected_metrics, selected_readiness, selected_observations, selected_lineages, selected_whole


def _canonical_bindings(bundle):
    plan = bundle[3].plan_manifest
    return tuple(
        sorted(
            (derive_released_arm_case_binding(case, plan) for group in bundle[2] for case in group.cases),
            key=lambda item: (item.key.arm_id, item.key.scope.family_id, item.key.scope.ecosystem, item.case_id_digest),
        )
    )


def _canonical_lineages(bundle):
    return derive_combination_lineages_v3(bundle[3].plan_manifest.declaration, _canonical_bindings(bundle))


def _derive_reports(*args):
    from openultrasast.core.evaluation_report import derive_completed_evaluation_reports_v3

    return derive_completed_evaluation_reports_v3(*args)


def test_completed_exact_scopes_receive_reproducible_go_decisions() -> None:
    reports, whole = _derive_reports(*_inputs())

    assert tuple(report.baseline.arm_id for report in reports) == ("arm-a", "arm-b", "arm-combined")
    assert all(result.decision is AdmissionDecision.GO for report in reports for result in report.scoped_results)
    assert all(result.instrument_gate.passed for report in reports for result in report.scoped_results)
    assert all(result.budget_gate.passed for report in reports for result in report.scoped_results)
    assert all(result.readiness_gate.passed for report in reports for result in report.scoped_results)
    assert all(result.quality_gate.passed for report in reports for result in report.scoped_results)
    assert whole.completed_underlying_push_count == whole.underlying_push_count == 9
    assert whole.deferred_underlying_push_count == 0


def test_completed_quality_failure_is_no_go_not_incompletion() -> None:
    bundle = _bundle(authority_case=_reference_authority_case())
    failing = tuple(
        ScopedMetricResultV3.from_counts(item.key, item.metric_id, numerator=1, denominator=1)
        if item.metric_id in {MetricId.FIXED_FALSE_ALARM_RATE, MetricId.ORDINARY_FALSE_ALARMS_PER_100}
        else item
        for item in _passing_metrics(bundle)
    )

    reports, _ = _derive_reports(*_inputs(metrics=failing))

    assert all(result.decision is AdmissionDecision.NO_GO for report in reports for result in report.scoped_results)
    assert any(not result.quality_gate.passed for report in reports for result in report.scoped_results)
    assert all(result.instrument_gate.passed and result.readiness_gate.passed for report in reports for result in report.scoped_results)


def test_operational_evidence_preserves_completed_work_funnel_runtime_and_closed_reasons() -> None:
    from openultrasast.core.evaluation_report import DegradationReasonV3

    reports, _ = _derive_reports(*_inputs())
    for report in reports:
        evidence = report.operational_evidence
        assert evidence.completed_count == 3
        assert evidence.deferred_count == 0
        assert len(evidence.completed_case_digests) == 3
        assert evidence.deferred_case_digests == ()
        assert evidence.stage_funnel.inputs_read == 3
        assert evidence.runtime_ms == 30
        assert evidence.instrument_failures == ()
        assert evidence.model_failures == ()
        assert set(evidence.degradation_reasons) <= set(DegradationReasonV3)
    assert reports[0].combination_lineage is None
    assert reports[-1].combination_lineage == _inputs()[5][0]


def test_failed_or_incomplete_readiness_is_refused_without_a_quality_decision() -> None:
    from openultrasast.core.evaluation_report import EvaluationReportError

    inputs = _inputs()
    readiness = inputs[3]
    failed = object.__new__(type(readiness[0]))
    for field, value in readiness[0].__dict__.items():
        object.__setattr__(failed, field, StageResult.FAILED if field == "result" else value)
    with pytest.raises(EvaluationReportError, match="readiness|completed"):
        _derive_reports(*_inputs(readiness=(failed,) + readiness[1:]))
    with pytest.raises(EvaluationReportError, match="readiness|complete"):
        _derive_reports(*_inputs(readiness=readiness[:-1]))


def test_unread_input_skipped_stage_and_incomplete_arm_are_refused_before_decision() -> None:
    from openultrasast.core.evaluation_report import EvaluationReportError

    inputs = _inputs()
    groups = inputs[1]
    case = groups[0].cases[0]
    unread = replace(case.input_receipts[0], opened=False, byte_count=0, content_digest=None)
    malformed = object.__new__(type(case))
    for field, value in case.__dict__.items():
        object.__setattr__(malformed, field, (unread,) + case.input_receipts[1:] if field == "input_receipts" else value)
    changed_group = object.__new__(type(groups[0]))
    for field, value in groups[0].__dict__.items():
        object.__setattr__(changed_group, field, (malformed,) + groups[0].cases[1:] if field == "cases" else value)
    with pytest.raises(EvaluationReportError, match="instrument|input|case"):
        _derive_reports(*_inputs(groups=(changed_group,) + groups[1:]))

    observations = inputs[4]
    skipped = object.__new__(type(observations[0]))
    for field, value in observations[0].__dict__.items():
        object.__setattr__(skipped, field, "0" * 64 if field == "stage_execution_evidence_digest" else value)
    with pytest.raises(EvaluationReportError, match="stage|observation"):
        _derive_reports(*_inputs(observations=(skipped,) + observations[1:]))
    missing_cases = replace(observations[0], cases=(), observation_digest="")
    with pytest.raises(EvaluationReportError, match="observed case|complete"):
        _derive_reports(*_inputs(observations=(missing_cases,) + observations[1:]))
    with pytest.raises(EvaluationReportError, match="arm|baseline|complete"):
        _derive_reports(*_inputs(groups=groups[:-1]))


def test_report_mutations_and_wrong_combination_lineage_are_refused() -> None:
    from openultrasast.core.evaluation_report import EvaluationReportError

    reports, _ = _derive_reports(*_inputs())
    with pytest.raises(EvaluationReportError, match="digest"):
        replace(reports[0], report_digest="f" * 64)


def test_combination_lineage_must_rederive_from_the_current_release() -> None:
    from openultrasast.core.evaluation_report import EvaluationReportError

    with pytest.raises(EvaluationReportError, match="combination|lineage"):
        _derive_reports(*_inputs(lineages=()))

    bundle = _bundle(authority_case=_reference_authority_case(), aligned_combination_cases=True)
    unrelated = tuple(
        sorted(
            (
                replace(
                    binding,
                    case_id_digest=canonical.content_digest(f"unrelated-case:{binding.case_id_digest}"),
                    observation_digest=canonical.content_digest(f"unrelated-observation:{binding.key.arm_id}"),
                    binding_digest="",
                )
                for binding in _canonical_bindings(bundle)
            ),
            key=lambda item: (item.key.arm_id, item.key.scope.family_id, item.key.scope.ecosystem, item.case_id_digest),
        )
    )
    unrelated_lineages = derive_combination_lineages_v3(bundle[3].plan_manifest.declaration, unrelated)
    with pytest.raises(EvaluationReportError, match="combination|lineage"):
        _derive_reports(*_inputs(lineages=unrelated_lineages))


def test_reports_and_whole_coverage_are_non_authorizing_and_v2_is_unchanged() -> None:
    from openultrasast.core.admission_report import AdmissionReportV2
    from openultrasast.core.evaluation_report import ArmEvaluationReportV3, WholePopulationCoverageV3

    assert not hasattr(ArmEvaluationReportV3, "authorize_consumer")
    assert not hasattr(WholePopulationCoverageV3, "authorize_consumer")
    assert "decision" in AdmissionReportV2.__dataclass_fields__
