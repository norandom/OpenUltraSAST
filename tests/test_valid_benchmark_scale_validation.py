"""Task 11.5 streaming scale, bounded validation, and execution back-pressure.

Drives the committed population, store, serialization, projection, replay,
and reporting operations over one synthetic scale population of forty
positives and eight hundred ordinary pushes (two ecosystems, two families).
Case/object batches stream one batch at a time through validation with
per-batch nonzero read receipts, cold/warm and per-arm runtime receipts, a
bounded execution lane whose busy refusal is an impairment rather than a
detector result or an infrastructure diagnosis, and truncated streams that
report impairment instead of a partial clean result.
"""

from __future__ import annotations

import json
import sys
import tracemalloc
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from valid_benchmark_e2e_fixtures import (  # noqa: E402
    FAMILY_JS,
    FAMILY_PY,
    PLANNED_ARMS,
    E2EEnvironment,
)
from valid_benchmark_scale_support import (  # noqa: E402
    CORE_REPLAY_DECLARATION,
    EXECUTION_TIER_INPUTS,
    EXECUTION_TIER_PUSHES_PER_ECOSYSTEM,
    SCALE_REQUIRED_PER_POSITIVE,
    ScaleLifecycle,
    StreamFault,
    case_objects_factory,
    component_arm_ids,
    default_population_shape,
    durable_bucket,
    impaired_stream_outcome,
    lane_refusal_texts,
    measure_cold_warm,
    operator_report_for_outcome,
    probe_objects_factory,
    prove_store_nonzero,
    redaction_findings,
    run_streaming_validation,
    scale_lifecycle,
    scale_population,
    stream_with_lane,
    vocabulary_findings,
)

from benchmarks.valid import run  # noqa: E402
from benchmarks.valid.workflow_outcome import WorkflowStatus  # noqa: E402
from openultrasast.core.custody import PopulationStatus  # noqa: E402
from openultrasast.core.evaluation_measurement import MetricId  # noqa: E402


@pytest.fixture(scope="module")
def population():
    return scale_population()


@pytest.fixture(scope="module")
def chain() -> ScaleLifecycle:
    return scale_lifecycle()


def test_scale_population_meets_target_shape_and_defaults_stay_committed() -> None:
    positives, pushes, inputs = default_population_shape()
    assert (positives, pushes, inputs) == (40, 20, 60)
    case = scale_population()
    assert case.freeze.positive_count == 40
    assert len(case.selection.pushes) == 800
    assert len(case.manifest.input_digests) == 840
    per_ecosystem: dict[str, int] = {}
    for push in case.selection.pushes:
        per_ecosystem[push.ecosystem] = per_ecosystem.get(push.ecosystem, 0) + 1
    assert per_ecosystem == {"javascript": 400, "python": 400}
    families = {row.vulnerability_family for row in case.freeze.scope_census}
    ecosystems = {row.ecosystem.value for row in case.freeze.scope_census}
    assert families == {FAMILY_PY, FAMILY_JS}
    assert ecosystems == {"python", "javascript"}
    for row in case.freeze.scope_census:
        assert row.count == 20


def test_scale_freeze_manifest_and_store_policy_validate_with_nonzero_proofs(population) -> None:
    environment = E2EEnvironment(population)
    assert prove_store_nonzero(environment.durable, durable_bucket()) > 0
    configuration = run.validated_operator_configuration(_operator_environ(), _operator_evidence())
    assert configuration.durable.bucket
    freeze = population.freeze
    assert freeze.positive_count == 40
    assert freeze.population_class.value == "admission"
    manifest = population.manifest
    assert len(manifest.input_digests) == 840
    assert manifest.positive_count == 40
    assert manifest.input_count == 840
    label_bearing = {"label", "judgment", "role", "family_of_change", "pair"}
    assert not label_bearing.intersection(manifest.__dict__)
    assert population.selection.required_per_positive == SCALE_REQUIRED_PER_POSITIVE


def test_scale_serialization_round_trip_streams_canonically(population) -> None:
    value, receipt = measure_cold_warm(lambda: _selection_bytes(population))
    assert value == _selection_bytes(population)
    assert receipt.cold_ms > 0 and receipt.warm_ms > 0
    assert receipt.warm_ms <= receipt.cold_ms or receipt.registered_reason == "warm_slower_registered"
    decoded = json.loads(value)
    assert len(decoded["pushes"]) == 800
    assert len(decoded["assignments"]) == 40 * 800
    manifest_bytes = _manifest_bytes(population)
    assert len(manifest_bytes) > 0
    assert json.loads(manifest_bytes)["input_count"] == 840


def test_streaming_validation_grows_with_supplied_artifacts_per_batch(population) -> None:
    small = run_streaming_validation(case_objects_factory(population, 256), 64, 256)
    full = run_streaming_validation(case_objects_factory(population), 64, 840)
    assert small.status is WorkflowStatus.COMPLETED and full.status is WorkflowStatus.COMPLETED
    assert small.reason_codes == () and full.reason_codes == ()
    assert small.all_batches_nonzero and full.all_batches_nonzero
    assert small.consumed_objects == 256 and full.consumed_objects == 840
    assert full.byte_count > small.byte_count > 0
    assert full.batch_count > small.batch_count > 0
    assert full.runtime_ms >= 0 and small.runtime_ms >= 0
    repeat = run_streaming_validation(case_objects_factory(population, 256), 64, 256)
    assert repeat.chain_digest == small.chain_digest


def test_streaming_memory_is_bounded_by_batch_not_population() -> None:
    """tracemalloc instrument: peak traced allocations during streaming.

    The instrument is proven honest before any boundedness claim: one full
    un-instrumented pass first establishes that every batch read nonzero
    bytes (all_batches_nonzero, consumed == declared). Only then are peaks
    compared: doubling the batch size must grow the peak, while doubling the
    total artifact count at a fixed batch size must not.
    """
    instrumented = run_streaming_validation(probe_objects_factory(128), 32, 128)
    assert instrumented.consumed_objects == 128 and instrumented.all_batches_nonzero
    batch_peak = _traced_peak(lambda: run_streaming_validation(probe_objects_factory(128), 32, 128))
    double_batch_peak = _traced_peak(lambda: run_streaming_validation(probe_objects_factory(128), 64, 128))
    double_total_peak = _traced_peak(lambda: run_streaming_validation(probe_objects_factory(256), 32, 256))
    assert double_batch_peak > batch_peak * 1.2
    assert double_total_peak < batch_peak * 1.6


def test_cold_warm_and_per_arm_runtime_receipts_are_retained(population, chain) -> None:
    _value, receipt = measure_cold_warm(lambda: run_streaming_validation(case_objects_factory(population), 64, 840))
    assert receipt.cold_ms > 0 and receipt.warm_ms > 0
    assert receipt.warm_ms <= receipt.cold_ms or receipt.registered_reason == "warm_slower_registered"
    component_arms = component_arm_ids(chain.population)
    lane_arms = {arm for arm, _ms in chain.arm_runtimes}
    assert lane_arms == set(component_arms)
    assert "arm-combined" not in lane_arms
    for _arm, runtime_ms in chain.arm_runtimes:
        assert runtime_ms >= 0
    assert len(chain.arm_runtimes) == len(component_arms)


def test_execution_tier_projection_covers_every_input_without_scoring(chain: ScaleLifecycle) -> None:
    projection = chain.projection
    inputs = chain.population.manifest.input_digests
    assert projection.whole_coverage.change_input_count == len(inputs) == EXECUTION_TIER_INPUTS
    assert len(projection.whole_coverage.change_input_digests) == EXECUTION_TIER_INPUTS
    for row in projection.scopes:
        assert len(row.ordinary_case_digests) == EXECUTION_TIER_PUSHES_PER_ECOSYSTEM
        assert len(row.vulnerable_case_digests) == len(row.fixed_case_digests) == 10
    assert chain.execution.refusal_reason is None
    assert chain.environment.store.current_log(chain.population.freeze.population_digest).status is PopulationStatus.SPENT


def test_scale_core_replay_reports_exact_scopes_for_every_planned_arm(chain: ScaleLifecycle) -> None:
    assert CORE_REPLAY_DECLARATION
    replay = chain.replay
    assert tuple(report.baseline.arm_id for report in replay.reports) == PLANNED_ARMS
    expected_scopes = {(FAMILY_PY, "python"), (FAMILY_JS, "javascript")}
    for report in replay.reports:
        assert {(result.key.scope.family_id, result.key.scope.ecosystem) for result in report.scoped_results} == (
            expected_scopes
        )
        for result in report.scoped_results:
            for metric in result.metrics:
                assert metric.denominator > 0
                assert tuple(metric.metric_id for metric in result.metrics) == tuple(MetricId)
    unique = {case.underlying_push_digest for group in replay.cases_by_arm for case in group.cases}
    assert replay.whole_population_coverage.underlying_push_count == len(unique) == EXECUTION_TIER_INPUTS


def test_scale_reporting_is_deterministic_and_redacted(chain: ScaleLifecycle) -> None:
    assert chain.result.outcome.status is WorkflowStatus.COMPLETED
    first = chain.result.report_bytes
    second = chain.render_again()
    assert first == second
    assert redaction_findings(first) == ()
    document = json.loads(first)
    assert document["status"] == "completed"
    assert {arm["arm_id"] for arm in document["replay"]["arms"]} == set(PLANNED_ARMS)


def test_back_pressure_bounds_pending_and_busy_lane_is_an_impairment_not_a_result() -> None:
    lane, record = _saturated_lane()
    assert record.max_pending <= lane.maxsize
    assert lane.maxsize == 2
    assert record.refused_batches > 0
    assert record.accepted_batches == lane.maxsize
    assert record.outcome.status is WorkflowStatus.IMPAIRED
    assert record.outcome.evaluation_replay_ref is None
    assert WorkflowStatus.COMPLETED is not record.outcome.status
    assert record.outcome.reason_codes
    serialized = json.dumps(record.outcome.reason_codes[0].value)
    assert vocabulary_findings(serialized) == ()
    drained = lane.drain(lane.maxsize)
    assert drained == lane.maxsize
    assert lane.pending() == 0


def test_busy_lane_refusal_carries_no_detector_or_infrastructure_diagnosis() -> None:
    _lane, record = _saturated_lane()
    assert record.refusals
    for text in lane_refusal_texts(record):
        assert vocabulary_findings(text) == ()
    impaired = impaired_stream_outcome(record.receipt)
    assert impaired.status is WorkflowStatus.IMPAIRED
    report = operator_report_for_outcome(impaired)
    document = json.loads(report)
    assert document["status"] == "impaired"
    assert "replay" not in document and "metrics" not in document
    assert vocabulary_findings(report.decode("ascii")) == ()
    assert record.receipt.reason_codes


@pytest.mark.parametrize(
    "fault",
    [StreamFault.MISSING_BATCH, StreamFault.SHORT_BATCH, StreamFault.UNREADABLE_OBJECT],
)
def test_incomplete_scale_stream_reports_impairment_never_partial_clean(fault: StreamFault) -> None:
    receipt = run_streaming_validation(probe_objects_factory(840), 60, 840, fault=fault)
    assert receipt.status is WorkflowStatus.IMPAIRED
    assert receipt.reason_codes
    assert receipt.consumed_objects < 840
    outcome = impaired_stream_outcome(receipt)
    assert outcome.status is WorkflowStatus.IMPAIRED
    assert outcome.evaluation_replay_ref is None
    report = operator_report_for_outcome(outcome)
    document = json.loads(report)
    assert document["status"] == "impaired"
    assert "replay" not in document and "metrics" not in document
    assert vocabulary_findings(report.decode("ascii")) == ()


def _operator_environ():
    from test_valid_benchmark_run import _environ  # noqa: E402

    return _environ()


def _operator_evidence():
    from test_valid_benchmark_run import _evidence  # noqa: E402

    return _evidence()


def _selection_bytes(population) -> bytes:
    from benchmarks.valid.ordinary_change_contract import ordinary_selection_bytes  # noqa: E402

    return ordinary_selection_bytes(population.selection)


def _manifest_bytes(population) -> bytes:
    from benchmarks.valid.population_label_blind_contract import (  # noqa: E402
        label_blind_population_manifest_bytes,
    )

    return label_blind_population_manifest_bytes(population.manifest)


def _traced_peak(operation) -> int:
    tracemalloc.start()
    operation()
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak


def _saturated_lane():
    from valid_benchmark_scale_support import BoundedExecutionLane  # noqa: E402

    lane = BoundedExecutionLane(maxsize=2)
    record = stream_with_lane(probe_objects_factory(840), 60, 840, lane)
    return lane, record
