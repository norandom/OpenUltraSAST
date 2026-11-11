"""Complete non-authorizing evaluation replay construction for V3."""

from __future__ import annotations

from dataclasses import replace

import pytest
from test_core_evaluation_case_validation import _bundle, _reference_authority_case
from test_core_evaluation_report import _canonical_lineages, _passing_metrics

from openultrasast.core import canonical
from openultrasast.core._admission_gates import GateResult
from openultrasast.core.admission_report import AdmissionDecision
from openultrasast.core.custody import derive_population_use_receipt_digest
from openultrasast.core.evaluation_aggregate import derive_evaluation_aggregate_v3
from openultrasast.core.evaluation_measurement import AggregateWeightV3, MetricId
from openultrasast.core.evaluation_ordinary_projection import WholePopulationProjectionV3
from openultrasast.core.evaluation_report import derive_completed_evaluation_reports_v3


def _inputs(*, aggregate: bool = True):
    bundle = _bundle(
        authority_case=_reference_authority_case(),
        aligned_combination_cases=True,
        shared_underlying_by_ecosystem=True,
    )
    plan = bundle[3].plan_manifest
    groups = bundle[2]
    metrics = _passing_metrics(bundle)
    readiness_by_digest = {item.result_digest: item for item in bundle[5][3]}
    readiness = tuple(readiness_by_digest[digest] for digest in plan.readiness_digests)
    observations = bundle[5][4]
    lineages = _canonical_lineages(bundle)
    pushes = tuple(sorted({case.underlying_push_digest for group in groups for case in group.cases}))
    projection = WholePopulationProjectionV3(pushes, len(pushes), "")
    reports, whole = derive_completed_evaluation_reports_v3(
        plan,
        groups,
        metrics,
        readiness,
        observations,
        lineages,
        projection,
    )
    keys = tuple(sorted({metric.key for metric in metrics}))
    weights = tuple(AggregateWeightV3(key, 1, len(keys), "") for key in keys)
    samples = tuple(
        next(metric.sample_count for metric in metrics if metric.key == key and metric.metric_id is MetricId.PRECISION) for key in keys
    )
    summary = derive_evaluation_aggregate_v3(metrics, samples, weights) if aggregate else None
    from openultrasast.core.evaluation_replay import EvaluationReplayReportSourceV3

    source = EvaluationReplayReportSourceV3(metrics, readiness, observations, projection, "")
    return (
        plan,
        bundle[5][2],
        bundle[3],
        bundle[6],
        bundle[7],
        bundle[8],
        bundle[9],
        bundle[1],
        groups,
        source,
        reports,
        lineages,
        bundle[3].attempt_history.head_event_digest,
        whole,
        summary,
    )


def _assemble(*args):
    from openultrasast.core.evaluation_replay import assemble_evaluation_replay_v3

    return assemble_evaluation_replay_v3(*args)


def test_complete_graph_produces_one_deterministic_non_authorizing_replay() -> None:
    from openultrasast.core.evaluation_replay import EvaluationReplayV3
    from openultrasast.core.evaluation_version import NonAuthorizingV3

    inputs = _inputs()
    replay = _assemble(*inputs)

    assert replay == _assemble(*inputs)
    assert replay.replay_digest == _assemble(*inputs).replay_digest
    assert tuple(group.arm_id for group in replay.cases_by_arm) == ("arm-a", "arm-b", "arm-combined")
    assert tuple(report.baseline.arm_id for report in replay.reports) == ("arm-a", "arm-b", "arm-combined")
    assert replay.combination_lineages == inputs[11]
    assert replay.aggregate == inputs[-1]
    assert issubclass(EvaluationReplayV3, NonAuthorizingV3)
    assert not hasattr(EvaluationReplayV3, "authorize_consumer")


def test_optional_aggregate_is_bound_when_present_and_may_be_absent() -> None:
    with_aggregate = _assemble(*_inputs())
    without_aggregate = _assemble(*_inputs(aggregate=False))

    assert with_aggregate.aggregate is not None
    assert without_aggregate.aggregate is None
    assert with_aggregate.replay_digest != without_aggregate.replay_digest


@pytest.mark.parametrize("index", (8, 10, 11))
def test_missing_cases_reports_or_combination_lineage_prevents_replay(index: int) -> None:
    from openultrasast.core.evaluation_replay import EvaluationReplayError

    inputs = list(_inputs())
    inputs[index] = inputs[index][:-1]
    with pytest.raises(EvaluationReplayError, match="complete|planned|lineage|report|case"):
        _assemble(*inputs)


def test_substituted_custody_attempt_coverage_and_aggregate_are_refused() -> None:
    from openultrasast.core.evaluation_replay import EvaluationReplayError

    inputs = list(_inputs())
    changed_receipt = replace(inputs[5], reasons=("substituted",))
    changed_receipt = replace(changed_receipt, receipt_digest=derive_population_use_receipt_digest(changed_receipt))
    inputs[5] = changed_receipt
    with pytest.raises(EvaluationReplayError, match="receipt|spend|custody"):
        _assemble(*inputs)

    inputs = list(_inputs())
    inputs[12] = canonical.content_digest("other-attempt-head")
    with pytest.raises(EvaluationReplayError, match="attempt"):
        _assemble(*inputs)

    inputs = list(_inputs())
    inputs[13] = replace(
        inputs[13],
        completed_underlying_push_count=inputs[13].completed_underlying_push_count - 1,
        deferred_underlying_push_count=1,
        coverage_digest="",
    )
    with pytest.raises((EvaluationReplayError, ValueError), match="coverage|push|reconcile"):
        _assemble(*inputs)

    inputs = list(_inputs())
    aggregate = inputs[14]
    assert aggregate is not None
    changed_metric = replace(aggregate.metrics[0], weighted_value=0.25, metric_digest="")
    inputs[14] = replace(aggregate, metrics=(changed_metric,) + aggregate.metrics[1:], aggregate_digest="")
    with pytest.raises((EvaluationReplayError, ValueError), match="aggregate|reproduce|canonical"):
        _assemble(*inputs)


def _forged_reports(reports, mutation: str):
    report = reports[0]
    scoped = report.scoped_results[0]
    if mutation in {"instrument_gate", "budget_gate", "readiness_gate", "quality_gate"}:
        original_gate = getattr(scoped, mutation)
        gate = GateResult(original_gate.kind, original_gate.gate_id, False, ("forged",), original_gate.evidence_digests)
        changed_scope = replace(scoped, **{mutation: gate}, decision=AdmissionDecision.NO_GO, result_digest="")
        changed_report = replace(report, scoped_results=(changed_scope,) + report.scoped_results[1:], report_digest="")
    elif mutation == "metrics":
        original = scoped.metrics[0]
        metric = type(original).from_counts(original.key, original.metric_id, numerator=0, denominator=original.denominator)
        changed_scope = replace(scoped, metrics=(metric,) + scoped.metrics[1:], result_digest="")
        changed_report = replace(report, scoped_results=(changed_scope,) + report.scoped_results[1:], report_digest="")
    elif mutation == "runtime":
        operational = replace(report.operational_evidence, runtime_ms=report.operational_evidence.runtime_ms + 1, evidence_digest="")
        changed_report = replace(report, operational_evidence=operational, report_digest="")
    else:
        funnel = replace(report.operational_evidence.stage_funnel, inputs_read=report.operational_evidence.stage_funnel.inputs_read + 1)
        operational = replace(report.operational_evidence, stage_funnel=funnel, evidence_digest="")
        changed_report = replace(report, operational_evidence=operational, report_digest="")
    return (changed_report,) + reports[1:]


@pytest.mark.parametrize(
    "mutation",
    ("instrument_gate", "budget_gate", "readiness_gate", "quality_gate", "metrics", "runtime", "funnel"),
)
def test_reports_must_rederive_from_replay_carried_sources_for_assembly_and_direct_construction(mutation: str) -> None:
    from openultrasast.core.evaluation_replay import EvaluationReplayError

    inputs = list(_inputs())
    forged = _forged_reports(inputs[10], mutation)
    inputs[10] = forged
    with pytest.raises(EvaluationReplayError, match="report|source|rederive|canonical"):
        _assemble(*inputs)

    canonical_replay = _assemble(*_inputs())
    with pytest.raises(EvaluationReplayError, match="report|source|rederive|canonical"):
        replace(canonical_replay, reports=forged, replay_digest="")


def test_aggregate_derived_from_forged_report_metrics_cannot_replace_source_bound_aggregate() -> None:
    from openultrasast.core.evaluation_replay import EvaluationReplayError

    inputs = list(_inputs())
    forged = _forged_reports(inputs[10], "metrics")
    forged_metrics = tuple(metric for report in forged for result in report.scoped_results for metric in result.metrics)
    original = inputs[14]
    assert original is not None
    inputs[10] = forged
    inputs[14] = derive_evaluation_aggregate_v3(forged_metrics, original.sample_counts, original.weights)
    with pytest.raises(EvaluationReplayError, match="report|source|rederive|canonical"):
        _assemble(*inputs)


def test_reversed_readiness_is_refused_in_assembly_and_direct_replay_construction() -> None:
    from openultrasast.core.evaluation_replay import EvaluationReplayError

    inputs = list(_inputs())
    source = inputs[9]
    assert len(source.readiness) > 1
    reversed_source = replace(source, readiness=tuple(reversed(source.readiness)), source_digest="")
    inputs[9] = reversed_source
    with pytest.raises(EvaluationReplayError, match="readiness|order|source"):
        _assemble(*inputs)

    canonical_replay = _assemble(*_inputs())
    with pytest.raises(EvaluationReplayError, match="readiness|order|source"):
        replace(canonical_replay, report_source=reversed_source, replay_digest="")


@pytest.mark.parametrize(
    "mutation",
    ("metrics", "observations", "case_groups", "reports", "readiness_duplicate", "readiness_omitted", "lineage_duplicate"),
)
def test_replay_collections_are_never_reordered_normalized_or_deduplicated(mutation: str) -> None:
    from openultrasast.core.evaluation_replay import EvaluationReplayError

    inputs = list(_inputs())
    source = inputs[9]
    if mutation == "metrics":
        inputs[9] = replace(source, metrics=tuple(reversed(source.metrics)), source_digest="")
    elif mutation == "observations":
        inputs[9] = replace(source, observations=tuple(reversed(source.observations)), source_digest="")
    elif mutation == "case_groups":
        inputs[8] = tuple(reversed(inputs[8]))
    elif mutation == "reports":
        inputs[10] = tuple(reversed(inputs[10]))
    elif mutation == "readiness_duplicate":
        inputs[9] = replace(source, readiness=source.readiness + (source.readiness[0],), source_digest="")
    elif mutation == "readiness_omitted":
        inputs[9] = replace(source, readiness=source.readiness[:-1], source_digest="")
    else:
        inputs[11] = inputs[11] + (inputs[11][0],)
    with pytest.raises(EvaluationReplayError, match="complete|canonical|order|readiness|report|case|lineage|source"):
        _assemble(*inputs)


def test_replay_refuses_subclasses_and_v2_remains_unchanged() -> None:
    from openultrasast.core.admission_report import AdmissionReplay
    from openultrasast.core.evaluation_replay import EvaluationReplayError

    class PlanSubclass(type(_inputs()[0])):
        """Exact-type substitution used only by this regression."""

    inputs = list(_inputs())
    plan = inputs[0]
    substituted = object.__new__(PlanSubclass)
    for field, value in plan.__dict__.items():
        object.__setattr__(substituted, field, value)
    inputs[0] = substituted
    with pytest.raises(EvaluationReplayError, match="exact|plan"):
        _assemble(*inputs)
    assert "replay_digest" in AdmissionReplay.__dataclass_fields__
