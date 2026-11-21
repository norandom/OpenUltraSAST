"""Task 7.3 deterministic transport-neutral operator projections."""

from __future__ import annotations

import re
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from test_core_evaluation_end_to_end import _complete_replay

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import operator_report  # noqa: E402
from benchmarks.valid.replacement_artifact_contract import (  # noqa: E402
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
    artifact_reference,
    canonical_artifact_bytes,
)
from benchmarks.valid.workflow_outcome import (  # noqa: E402
    BenchmarkWorkflowOutcomeV1,
    WorkflowCounts,
    WorkflowGate,
    WorkflowPhase,
    WorkflowReasonCode,
    WorkflowStatus,
)
from openultrasast.core import canonical  # noqa: E402
from openultrasast.core.admission_report import AdmissionDecision  # noqa: E402
from openultrasast.core.canonical import ContentRef  # noqa: E402
from openultrasast.core.evaluation_aggregate import derive_evaluation_aggregate_v3  # noqa: E402
from openultrasast.core.evaluation_measurement import AggregateWeightV3, ArmScopeKey, MetricId  # noqa: E402
from openultrasast.core.proof import (  # noqa: E402
    DIFFERENTIAL_PROOF_SCHEMA,
    ControlBinding,
    DifferentialProofRecord,
    ProofAttachment,
    ProofOutcome,
    ProofProducerIdentity,
    ProofSideResult,
    ProofVerificationReceipt,
)

_HEX64 = re.compile(r"[0-9a-f]{64}")
_FORBIDDEN = re.compile("block|rollout|eligib|authoriz|enable|confidence", re.IGNORECASE)


def _digest(seed: str) -> str:
    return canonical.content_digest({"seed": seed})


def _counts(**overrides: object) -> WorkflowCounts:
    value: dict[str, object] = {
        "planned_arms": 3,
        "completed_arms": 3,
        "planned_inputs": 6,
        "completed_inputs": 6,
        "deferred_inputs": 0,
    }
    value.update(overrides)
    return WorkflowCounts(**value)  # type: ignore[arg-type]


def _outcome(**overrides: object) -> BenchmarkWorkflowOutcomeV1:
    value: dict[str, object] = {
        "status": WorkflowStatus.COMPLETED,
        "phase": WorkflowPhase.REPORTING,
        "reason_codes": (),
        "population_digest": _digest("population"),
        "freeze_digest": _digest("freeze"),
        "plan_digest": _digest("plan"),
        "workflow_digest": _digest("workflow"),
        "labels_spent": True,
        "counts": _counts(),
        "failed_gate_names": (),
        "degradation_codes": (),
        "runtime_ms": 4500,
        "input_read_evidence_digest": _digest("input-reads"),
        "stage_execution_evidence_digest": _digest("stage-executions"),
        "evaluation_replay_ref": None,
        "outcome_digest": "",
    }
    value.update(overrides)
    return BenchmarkWorkflowOutcomeV1(**value)  # type: ignore[arg-type]


def _insufficient() -> BenchmarkWorkflowOutcomeV1:
    return _outcome(
        status=WorkflowStatus.INSUFFICIENT,
        phase=WorkflowPhase.PREFLIGHT,
        reason_codes=(WorkflowReasonCode.SCOPE_INSUFFICIENT,),
        labels_spent=False,
        counts=_counts(planned_arms=2, completed_arms=0, planned_inputs=12, completed_inputs=0, deferred_inputs=12),
        failed_gate_names=(WorkflowGate.PREFLIGHT_FEASIBILITY,),
        runtime_ms=90,
        input_read_evidence_digest="",
        stage_execution_evidence_digest="",
    )


def _impaired() -> BenchmarkWorkflowOutcomeV1:
    return _outcome(
        status=WorkflowStatus.IMPAIRED,
        phase=WorkflowPhase.ARM_EXECUTION,
        reason_codes=(WorkflowReasonCode.INTERRUPTED,),
        labels_spent=False,
        counts=_counts(planned_arms=2, completed_arms=1, planned_inputs=12, completed_inputs=5, deferred_inputs=0),
        runtime_ms=1200,
        input_read_evidence_digest="",
        stage_execution_evidence_digest="",
    )


def _envelope(replay_digest: str) -> tuple[bytes, ArtifactReference]:
    content = canonical_artifact_bytes(
        ArtifactKind.REPLAY,
        {"replay_digest": replay_digest},
        access_class=ArtifactAccessClass.OPERATOR_SAFE,
        provenance_digest=_digest("replay-provenance"),
    )
    return content, artifact_reference(content)


@pytest.fixture(scope="module")
def completed() -> tuple[object, object]:
    with pytest.MonkeyPatch.context() as monkeypatch:
        bundle, replay, *_ = _complete_replay(monkeypatch)
        return bundle, replay


def _resolved(monkeypatch: pytest.MonkeyPatch, replay: object) -> operator_report.ResolvedOperatorReplay:
    content, reference = _envelope(replay.replay_digest)  # type: ignore[attr-defined]
    return operator_report.resolve_operator_replay(reference, content, replay)


def _completed_outcome(reference: ArtifactReference) -> BenchmarkWorkflowOutcomeV1:
    return _outcome(evaluation_replay_ref=reference)


def _failed(result: object, gate: object, reason: str) -> object:
    return replace(gate, passed=False, reasons=(reason,))


def _no_go_scope(result: object) -> object:
    quality = _failed(result, result.quality_gate, "threshold_failed:precision:wilson_lower")  # type: ignore[attr-defined]
    budget = _failed(result, result.budget_gate, f"budget_exceeded:{_digest('budget-case')}")  # type: ignore[attr-defined]
    return replace(result, quality_gate=quality, budget_gate=budget, decision=AdmissionDecision.NO_GO, result_digest="")


def _no_go_variant(resolved: operator_report.ResolvedOperatorReplay) -> operator_report.ResolvedOperatorReplay:
    report = resolved.reports[0]
    passing, failing = report.scoped_results[0], report.scoped_results[1]
    scoped = (passing, _no_go_scope(failing))
    reports = (replace(report, scoped_results=scoped, report_digest=""), *resolved.reports[1:])
    return replace(resolved, reports=reports)


def _demonstrated_attachment(case: object) -> ProofAttachment:
    producer = ProofProducerIdentity(
        "prover-arm", "verifier-v1", _digest("sandbox"), _digest("oracle"), _digest("producer-review")
    )
    affected = ProofSideResult(_digest("affected-input"), True, _digest("affected-obs"), 2, "")
    safe = ProofSideResult(_digest("safe-input"), False, _digest("safe-obs"), 2, "")
    witness = ContentRef("witness", _digest("witness"), "application/json", 64, _digest("retention"), _digest("receipt"))
    control = ControlBinding(_digest("affected-input"), _digest("safe-input"), witness, _digest("prover-reviewer"), "")
    proof = DifferentialProofRecord(
        DIFFERENTIAL_PROOF_SCHEMA, producer, affected, safe, control, witness, ProofOutcome.DEMONSTRATED, ""
    )
    verification = ProofVerificationReceipt(
        _digest("producer"), _digest("record"), _digest("aff"), _digest("safe"), _digest("witness"), witness, ""
    )
    return ProofAttachment("", case.key.scope.family_id, _digest("packet"), case.claims[0].location, proof, verification)  # type: ignore[attr-defined]


def _demonstrated_variant(
    resolved: operator_report.ResolvedOperatorReplay,
) -> operator_report.ResolvedOperatorReplay:
    group = resolved.cases_by_arm[0]
    cases = tuple(
        replace(case, proof_attachments=(_demonstrated_attachment(case),))
        if case.role.value == "vulnerable"  # type: ignore[attr-defined]
        else case
        for case in group.cases
    )
    groups = (replace(group, cases=cases, cases_digest=""), *resolved.cases_by_arm[1:])
    return replace(resolved, cases_by_arm=groups)


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for entry in value.values() for item in _strings(entry)]
    if isinstance(value, (list, tuple)):
        return [item for entry in value for item in _strings(entry)]
    return []


def test_completion_shows_multi_arm_scopes_metrics_intervals_and_separate_whole_coverage(
    monkeypatch: pytest.MonkeyPatch, completed: tuple[object, object]
) -> None:
    _, replay = completed
    resolved = _resolved(monkeypatch, replay)
    value = operator_report.operator_report_json(_completed_outcome(resolved.reference), resolved)

    assert value["status"] == "completed"
    report_replay = value["replay"]
    arms = report_replay["arms"]
    assert tuple(arm["arm_id"] for arm in arms) == ("arm-a", "arm-b", "arm-combined")
    for arm in arms:
        assert len(arm["scopes"]) == 2
        for scope in arm["scopes"]:
            assert scope["status"] == "go"
            assert scope["failed_gates"] == ()
            metrics = scope["metrics"]
            assert tuple(metric["metric_id"] for metric in metrics) == tuple(item.value for item in MetricId)
            for metric in metrics:
                assert metric["sample_count"] == metric["denominator"] > 0
                assert metric["interval_method"] == "wilson_95"
                assert metric["interval_lower"] <= metric["interval_upper"]
                assert metric["numerator"] <= metric["denominator"]
            assert _HEX64.fullmatch(scope["result_digest"])
        assert "scopes" not in arm["operational"]
        assert _HEX64.fullmatch(arm["baseline_digest"]) and _HEX64.fullmatch(arm["report_digest"])
    assert "whole_population_coverage" in report_replay
    assert all("whole_population_coverage" not in arm for arm in arms)
    coverage = report_replay["whole_population_coverage"]
    assert coverage == {
        "underlying_push_count": 6,
        "completed_underlying_push_count": 6,
        "deferred_underlying_push_count": 0,
        "coverage_digest": replay.whole_population_coverage.coverage_digest,  # type: ignore[attr-defined]
    }
    assert report_replay["replay_digest"] == replay.replay_digest  # type: ignore[attr-defined]
    assert report_replay["content_digest"] == resolved.reference.content_digest
    assert value["input_read_evidence_digest"] and value["stage_execution_evidence_digest"]


def test_completion_names_failed_gates_for_no_go_scopes(
    monkeypatch: pytest.MonkeyPatch, completed: tuple[object, object]
) -> None:
    _, replay = completed
    resolved = _no_go_variant(_resolved(monkeypatch, replay))
    value = operator_report.operator_report_json(_completed_outcome(resolved.reference), resolved)

    arm = value["replay"]["arms"][0]
    statuses = {f"{scope['family_id']}/{scope['ecosystem']}": scope["status"] for scope in arm["scopes"]}
    assert set(statuses.values()) == {"go", "no_go"}
    failing = next(scope for scope in arm["scopes"] if scope["status"] == "no_go")
    assert failing["failed_gates"] == ("budget", "quality")
    assert arm["failed_gate_names"] == ("budget", "quality")
    passing = next(scope for scope in arm["scopes"] if scope["status"] == "go")
    assert passing["failed_gates"] == ()
    for other in value["replay"]["arms"][1:]:
        assert other["failed_gate_names"] == ()


def test_scope_status_vocabulary_is_go_no_go_insufficient_and_cannot_express_blocking() -> None:
    assert tuple(sorted(item.value for item in operator_report.OperatorScopeStatus)) == ("go", "insufficient", "no_go")
    assert tuple(sorted(item.value for item in operator_report.OperatorDemonstrationStatus)) == (
        "demonstrated",
        "no_flagged_positives",
        "not_demonstrated",
    )
    scopes = {item.value for item in operator_report.OperatorScopeStatus}
    demonstrations = {item.value for item in operator_report.OperatorDemonstrationStatus}
    assert scopes.isdisjoint(demonstrations)
    assert not any(_FORBIDDEN.search(item) for item in [*scopes, *demonstrations])
    assert "confidence" not in demonstrations


def test_demonstrated_status_counts_flagged_positives_and_differential_proofs(
    monkeypatch: pytest.MonkeyPatch, completed: tuple[object, object]
) -> None:
    _, replay = completed
    resolved = _demonstrated_variant(_resolved(monkeypatch, replay))
    value = operator_report.operator_report_json(_completed_outcome(resolved.reference), resolved)

    for arm in value["replay"]["arms"]:
        demonstrated = arm["demonstrated"]
        assert demonstrated["flagged_positive_cases"] == 2
        assert demonstrated["proof_candidate_cases"] == 6
    first, second = (arm["demonstrated"] for arm in value["replay"]["arms"][:2])
    assert first["status"] == "demonstrated"
    assert first["demonstrated_proof_cases"] == 2
    assert second["status"] == "not_demonstrated"
    assert second["demonstrated_proof_cases"] == 0
    plain_resolved = _resolved(monkeypatch, replay)
    plain = operator_report.operator_report_json(_completed_outcome(plain_resolved.reference), plain_resolved)
    assert all(arm["demonstrated"]["status"] == "not_demonstrated" for arm in plain["replay"]["arms"])


def test_insufficient_outcome_renders_insufficient_scope_with_named_gates() -> None:
    value = operator_report.operator_report_json(_insufficient(), None)

    assert value["status"] == "insufficient"
    assert value["scope_status"] == "insufficient"
    assert value["reason_codes"] == ("scope_insufficient",)
    assert value["failed_gate_names"] == ("preflight_feasibility",)
    assert value["labels_spent"] is False
    assert "replay" not in value
    text = operator_report.operator_report_text(_insufficient(), None)
    assert "scope_status=insufficient" in text
    assert "failed_gates=preflight_feasibility" in text


def test_impaired_projection_is_limited_to_closed_safe_fields() -> None:
    value = operator_report.operator_report_json(_impaired(), None)

    assert set(value) == {
        "schema_version",
        "outcome_digest",
        "status",
        "labels_spent",
        "runtime_ms",
        "reason_codes",
        "counts",
        "degradation_codes",
    }
    assert value["status"] == "impaired"
    assert value["reason_codes"] == ("interrupted",)
    assert value["counts"]["completed_arms"] == 1
    assert value["labels_spent"] is False
    text = operator_report.operator_report_text(_impaired(), None)
    assert "reasons=interrupted" in text
    assert "completed_arms=1" in text


def test_absent_replay_is_valid_for_non_completed_outcomes_only() -> None:
    assert operator_report.operator_report_json(_insufficient(), None)["status"] == "insufficient"
    assert operator_report.operator_report_json(_impaired(), None)["status"] == "impaired"


def test_completed_outcome_fails_closed_without_a_matching_valid_replay(
    monkeypatch: pytest.MonkeyPatch, completed: tuple[object, object]
) -> None:
    _, replay = completed
    resolved = _resolved(monkeypatch, replay)

    with pytest.raises(operator_report.OperatorReportError) as missing:
        operator_report.operator_report_json(_completed_outcome(resolved.reference), None)
    assert missing.value.reason is operator_report.OperatorReportErrorReason.REPLAY_REQUIRED

    other_content = canonical_artifact_bytes(
        ArtifactKind.REPLAY,
        {"replay_digest": _digest("other-replay")},
        access_class=ArtifactAccessClass.OPERATOR_SAFE,
        provenance_digest=_digest("replay-provenance"),
    )
    with pytest.raises(operator_report.OperatorReportError) as mismatched:
        operator_report.operator_report_json(_completed_outcome(artifact_reference(other_content)), resolved)
    assert mismatched.value.reason is operator_report.OperatorReportErrorReason.REPLAY_MISMATCH

    wrong_arms = _outcome(evaluation_replay_ref=resolved.reference, counts=_counts(planned_arms=2, completed_arms=2))
    with pytest.raises(operator_report.OperatorReportError) as inconsistent:
        operator_report.operator_report_json(wrong_arms, resolved)
    assert inconsistent.value.reason is operator_report.OperatorReportErrorReason.INCONSISTENT_STATE

    with pytest.raises(operator_report.OperatorReportError) as unexpected:
        operator_report.operator_report_json(_impaired(), resolved)
    assert unexpected.value.reason is operator_report.OperatorReportErrorReason.INCONSISTENT_STATE


def test_invalid_replay_material_fails_closed_at_resolution(
    monkeypatch: pytest.MonkeyPatch, completed: tuple[object, object]
) -> None:
    _, replay = completed
    content, reference = _envelope(replay.replay_digest)  # type: ignore[attr-defined]

    with pytest.raises(operator_report.OperatorReportError) as wrong_type:
        operator_report.resolve_operator_replay(reference, content, object())
    assert wrong_type.value.reason is operator_report.OperatorReportErrorReason.REPLAY_INVALID

    tampered = replace(replay)
    object.__setattr__(tampered, "replay_digest", "0" * 64)
    with pytest.raises(operator_report.OperatorReportError) as tamper:
        operator_report.resolve_operator_replay(reference, content, tampered)
    assert tamper.value.reason is operator_report.OperatorReportErrorReason.REPLAY_INVALID

    unbound, unbound_reference = _envelope(_digest("another-replay"))
    with pytest.raises(operator_report.OperatorReportError) as unbound_error:
        operator_report.resolve_operator_replay(unbound_reference, unbound, replay)
    assert unbound_error.value.reason is operator_report.OperatorReportErrorReason.REPLAY_MISMATCH

    empty = b""
    with pytest.raises(operator_report.OperatorReportError) as empty_error:
        operator_report.resolve_operator_replay(reference, empty, replay)
    assert empty_error.value.reason is operator_report.OperatorReportErrorReason.REPLAY_INVALID

    with pytest.raises(operator_report.OperatorReportError) as wrong_kind:
        operator_report.resolve_operator_replay(
            ArtifactReference(
                ArtifactKind.REPORT,
                reference.content_digest,
                1,
                reference.provenance_digest,
                ArtifactAccessClass.OPERATOR_SAFE,
            ),
            content,
            replay,
        )
    assert wrong_kind.value.reason is operator_report.OperatorReportErrorReason.INVALID_REQUEST


def test_projections_are_deterministic_and_byte_identical(
    monkeypatch: pytest.MonkeyPatch, completed: tuple[object, object]
) -> None:
    _, replay = completed
    resolved = _resolved(monkeypatch, replay)
    outcome = _completed_outcome(resolved.reference)

    first = operator_report.operator_report_bytes(outcome, resolved)
    second = operator_report.operator_report_bytes(outcome, resolved)
    assert first == second and first
    assert operator_report.operator_report_json(outcome, resolved) == operator_report.operator_report_json(outcome, resolved)
    assert operator_report.operator_report_text(outcome, resolved) == operator_report.operator_report_text(outcome, resolved)
    assert canonical.canonical_bytes(operator_report.operator_report_json(outcome, resolved)) == first
    impaired_text = operator_report.operator_report_text(_impaired(), None)
    assert impaired_text == operator_report.operator_report_text(_impaired(), None)


def test_text_and_json_are_equivalent_ascii_projections(
    monkeypatch: pytest.MonkeyPatch, completed: tuple[object, object]
) -> None:
    _, replay = completed
    resolved = _no_go_variant(_demonstrated_variant(_resolved(monkeypatch, replay)))
    outcome = _completed_outcome(resolved.reference)
    value = operator_report.operator_report_json(outcome, resolved)
    text = operator_report.operator_report_text(outcome, resolved)

    text.encode("ascii")
    for arm in value["replay"]["arms"]:
        assert f"arm: {arm['arm_id']}" in text
        assert f"  demonstrated: status={arm['demonstrated']['status']}" in text
        assert f"flagged_positive_cases={arm['demonstrated']['flagged_positive_cases']}" in text
        for scope in arm["scopes"]:
            assert f"scope: {scope['family_id']}/{scope['ecosystem']} status={scope['status']}" in text
            failed = ",".join(scope["failed_gates"]) or "none"
            assert f"failed_gates={failed}" in text
            for metric in scope["metrics"]:
                assert f"metric: {metric['metric_id']} count={metric['numerator']}/{metric['denominator']}" in text
                assert f"sample={metric['sample_count']}" in text
                assert f"interval=[{metric['interval_lower']!r},{metric['interval_upper']!r}]" in text
    coverage = value["replay"]["whole_population_coverage"]
    assert (
        f"whole_population_coverage: underlying_pushes={coverage['underlying_push_count']} "
        f"completed={coverage['completed_underlying_push_count']} deferred={coverage['deferred_underlying_push_count']}" in text
    )
    assert f"outcome_digest: {value['outcome_digest']}" in text
    assert f"replay: digest={value['replay']['replay_digest']}" in text
    counts = value["counts"]
    assert (
        f"counts: planned_arms={counts['planned_arms']} completed_arms={counts['completed_arms']} "
        f"planned_inputs={counts['planned_inputs']} completed_inputs={counts['completed_inputs']} "
        f"deferred_inputs={counts['deferred_inputs']}" in text
    )


def test_rendered_bytes_stay_redacted(
    monkeypatch: pytest.MonkeyPatch, completed: tuple[object, object]
) -> None:
    _, replay = completed
    resolved = _resolved(monkeypatch, replay)
    rendered = operator_report.operator_report_bytes(_completed_outcome(resolved.reference), resolved)
    impaired = operator_report.operator_report_bytes(_impaired(), None)
    insufficient = operator_report.operator_report_bytes(_insufficient(), None)

    for content in (rendered, impaired, insufficient):
        assert b"/" not in content
        assert b"Traceback" not in content
        assert b"pytest" not in content
        assert b".py" not in content
        assert b"secret" not in content.lower()
        assert not _FORBIDDEN.search(content.decode("ascii"))

    report = resolved.reports[0]
    unsafe_id = "../../etc/passwd"
    unsafe_baseline = replace(report.baseline, arm_id=unsafe_id, baseline_digest="")
    unsafe_scopes = tuple(
        replace(
            item,
            key=ArmScopeKey(unsafe_id, item.key.scope),
            metrics=tuple(replace(metric, key=ArmScopeKey(unsafe_id, item.key.scope)) for metric in item.metrics),
            result_digest="",
        )
        for item in report.scoped_results
    )
    unsafe = replace(report, baseline=unsafe_baseline, scoped_results=unsafe_scopes, report_digest="")
    with pytest.raises(operator_report.OperatorReportError) as unsafe_error:
        operator_report.operator_report_json(
            _completed_outcome(resolved.reference), replace(resolved, reports=(unsafe, *resolved.reports[1:]))
        )
    assert unsafe_error.value.reason is operator_report.OperatorReportErrorReason.INVALID_REQUEST
    assert str(unsafe_error.value) == "operator_report_invalid_request"


def test_optional_aggregate_declares_constituents_and_weighting_without_decisions(
    monkeypatch: pytest.MonkeyPatch, completed: tuple[object, object]
) -> None:
    _, replay = completed
    resolved = _resolved(monkeypatch, replay)
    plain = operator_report.operator_report_json(_completed_outcome(resolved.reference), resolved)
    assert plain["replay"]["optional_aggregate"] is None

    metrics = replay.report_source.metrics  # type: ignore[attr-defined]
    keys = tuple(sorted({metric.key for metric in metrics}))
    samples = tuple(
        next(m.sample_count for m in metrics if m.key == key and m.metric_id is MetricId.PRECISION) for key in keys
    )
    weights = tuple(AggregateWeightV3(key, 1, len(keys), "") for key in keys)
    aggregate = derive_evaluation_aggregate_v3(metrics, samples, weights)
    aggregated = replace(resolved, aggregate=aggregate)
    value = operator_report.operator_report_json(_completed_outcome(aggregated.reference), aggregated)

    projection = value["replay"]["optional_aggregate"]
    assert projection is not None
    assert projection["aggregate_digest"] == aggregate.aggregate_digest
    assert len(projection["constituents"]) == len(keys)
    assert len(projection["weights"]) == len(keys)
    assert set(projection["constituents"][0]) == {"arm_id", "family_id", "ecosystem", "sample_count"}
    assert set(projection["weights"][0]) == {"arm_id", "family_id", "ecosystem", "numerator", "denominator"}
    assert not any("decision" in key or "gate" in key for key in _strings(projection))
