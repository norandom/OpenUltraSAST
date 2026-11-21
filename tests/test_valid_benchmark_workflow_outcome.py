"""Task 7.1 closed workflow outcomes and redacted deterministic serialization."""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import workflow_outcome  # noqa: E402
from benchmarks.valid.replacement_artifact_contract import (  # noqa: E402
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
    canonical_json_bytes,
)
from openultrasast.core import canonical  # noqa: E402

_HEX64 = re.compile(r"[0-9a-f]{64}")


def _digest(seed: str) -> str:
    return canonical.content_digest({"seed": seed})


def _replay_reference(
    kind: ArtifactKind = ArtifactKind.REPLAY,
    access: ArtifactAccessClass = ArtifactAccessClass.OPERATOR_SAFE,
) -> ArtifactReference:
    return ArtifactReference(kind, _digest("replay-content"), 512, _digest("replay-provenance"), access)


def _counts(**overrides: object) -> workflow_outcome.WorkflowCounts:
    value: dict[str, object] = {
        "planned_arms": 2,
        "completed_arms": 2,
        "planned_inputs": 12,
        "completed_inputs": 12,
        "deferred_inputs": 0,
    }
    value.update(overrides)
    return workflow_outcome.WorkflowCounts(**value)  # type: ignore[arg-type]


def _build(fields: dict[str, object]) -> workflow_outcome.BenchmarkWorkflowOutcomeV1:
    return workflow_outcome.BenchmarkWorkflowOutcomeV1(**fields)  # type: ignore[arg-type]


def _outcome(**overrides: object) -> workflow_outcome.BenchmarkWorkflowOutcomeV1:
    value: dict[str, object] = {
        "status": workflow_outcome.WorkflowStatus.COMPLETED,
        "phase": workflow_outcome.WorkflowPhase.SCORING,
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
        "evaluation_replay_ref": _replay_reference(),
        "outcome_digest": "",
    }
    value.update(overrides)
    return _build(value)


def _completed(**overrides: object) -> workflow_outcome.BenchmarkWorkflowOutcomeV1:
    return _outcome(**overrides)


def _insufficient(**overrides: object) -> workflow_outcome.BenchmarkWorkflowOutcomeV1:
    value: dict[str, object] = {
        "status": workflow_outcome.WorkflowStatus.INSUFFICIENT,
        "phase": workflow_outcome.WorkflowPhase.PREFLIGHT,
        "reason_codes": (workflow_outcome.WorkflowReasonCode.SCOPE_INSUFFICIENT,),
        "population_digest": _digest("population"),
        "freeze_digest": _digest("freeze"),
        "plan_digest": _digest("plan"),
        "workflow_digest": _digest("workflow"),
        "labels_spent": False,
        "counts": _counts(planned_arms=2, completed_arms=0, planned_inputs=12, completed_inputs=0, deferred_inputs=12),
        "failed_gate_names": (workflow_outcome.WorkflowGate.PREFLIGHT_FEASIBILITY,),
        "degradation_codes": (),
        "runtime_ms": 90,
        "input_read_evidence_digest": "",
        "stage_execution_evidence_digest": "",
        "evaluation_replay_ref": None,
        "outcome_digest": "",
    }
    value.update(overrides)
    return _build(value)


def _impaired(**overrides: object) -> workflow_outcome.BenchmarkWorkflowOutcomeV1:
    value: dict[str, object] = {
        "status": workflow_outcome.WorkflowStatus.IMPAIRED,
        "phase": workflow_outcome.WorkflowPhase.ARM_EXECUTION,
        "reason_codes": (workflow_outcome.WorkflowReasonCode.INTERRUPTED,),
        "population_digest": _digest("population"),
        "freeze_digest": _digest("freeze"),
        "plan_digest": _digest("plan"),
        "workflow_digest": _digest("workflow"),
        "labels_spent": False,
        "counts": _counts(planned_arms=2, completed_arms=1, planned_inputs=12, completed_inputs=5, deferred_inputs=0),
        "failed_gate_names": (),
        "degradation_codes": (),
        "runtime_ms": 1200,
        "input_read_evidence_digest": "",
        "stage_execution_evidence_digest": "",
        "evaluation_replay_ref": None,
        "outcome_digest": "",
    }
    value.update(overrides)
    return _build(value)


def _reserialized(content: bytes, mutate: Callable[[dict[str, object]], None]) -> bytes:
    value = json.loads(content)
    mutate(value)
    return canonical_json_bytes(value)


def _walk_strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        result: list[str] = []
        for key, item in value.items():
            result.append(key)
            result.extend(_walk_strings(item))
        return result
    if isinstance(value, list):
        result = []
        for item in value:
            result.extend(_walk_strings(item))
        return result
    return []


def _closed_vocabulary() -> frozenset[str]:
    members: set[str] = {
        workflow_outcome.WORKFLOW_OUTCOME_SCHEMA,
        workflow_outcome.WORKFLOW_OUTCOME_REFERENCE_SCHEMA,
    }
    for enum_type in (
        workflow_outcome.WorkflowStatus,
        workflow_outcome.WorkflowReasonCode,
        workflow_outcome.WorkflowPhase,
        workflow_outcome.DegradationCode,
        workflow_outcome.WorkflowGate,
        ArtifactAccessClass,
        ArtifactKind,
    ):
        members.update(member.value for member in enum_type)
    members.update(workflow_outcome.WORKFLOW_OUTCOME_FIELDS)
    members.update(workflow_outcome.WORKFLOW_COUNT_FIELDS)
    members.update(workflow_outcome.WORKFLOW_REFERENCE_FIELDS)
    return frozenset(members)


def test_completed_requires_exactly_one_complete_replay_reference() -> None:
    outcome = _completed()
    assert outcome.evaluation_replay_ref is not None
    assert outcome.evaluation_replay_ref.artifact_kind is ArtifactKind.REPLAY
    assert _HEX64.fullmatch(outcome.outcome_digest)
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _completed(evaluation_replay_ref=None)
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _completed(evaluation_replay_ref=_replay_reference(kind=ArtifactKind.OBSERVATION))
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _completed(evaluation_replay_ref=_replay_reference(access=ArtifactAccessClass.CUSTODIAN_SEALED))


def test_completed_rejects_missing_or_failed_required_stages() -> None:
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _completed(input_read_evidence_digest="")
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _completed(stage_execution_evidence_digest="")
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _completed(failed_gate_names=(workflow_outcome.WorkflowGate.REPLAY_VALIDATION,))
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _completed(reason_codes=(workflow_outcome.WorkflowReasonCode.INSTRUMENT_FAILURE,))
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _completed(counts=_counts(completed_arms=1))
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _completed(counts=_counts(completed_inputs=10, deferred_inputs=0))
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _completed(labels_spent=False)
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _completed(counts=_counts(completed_inputs=10, deferred_inputs=2))
    degraded = _completed(
        counts=_counts(completed_inputs=10, deferred_inputs=2),
        degradation_codes=(workflow_outcome.DegradationCode.DEFERRED_INPUTS,),
    )
    assert degraded.counts.deferred_inputs == 2
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _completed(counts=_counts(planned_inputs=0, completed_inputs=0))
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _completed(counts=_counts(planned_arms=0, completed_arms=0))


def test_insufficient_state_is_closed_and_non_authorizing() -> None:
    outcome = _insufficient()
    assert outcome.status is workflow_outcome.WorkflowStatus.INSUFFICIENT
    assert outcome.labels_spent is False
    assert outcome.evaluation_replay_ref is None
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _insufficient(reason_codes=())
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _insufficient(reason_codes=(workflow_outcome.WorkflowReasonCode.TIMED_OUT,))
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _insufficient(labels_spent=True)
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _insufficient(evaluation_replay_ref=_replay_reference())
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _insufficient(failed_gate_names=())
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _insufficient(counts=_counts(planned_arms=2, completed_arms=0, planned_inputs=12, completed_inputs=4, deferred_inputs=8))
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _insufficient(counts=_counts(planned_arms=2, completed_arms=0, planned_inputs=0, completed_inputs=0, deferred_inputs=0))
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _insufficient(input_read_evidence_digest=_digest("input-reads"))
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _insufficient(phase=workflow_outcome.WorkflowPhase.SCORING)


def test_impaired_state_is_closed_and_resumable() -> None:
    impaired_reasons = (
        workflow_outcome.WorkflowReasonCode.TIMED_OUT,
        workflow_outcome.WorkflowReasonCode.BUDGET_EXHAUSTED,
        workflow_outcome.WorkflowReasonCode.RESOURCE_EXHAUSTED,
        workflow_outcome.WorkflowReasonCode.INSTRUMENT_FAILURE,
        workflow_outcome.WorkflowReasonCode.INTERRUPTED,
        workflow_outcome.WorkflowReasonCode.STALLED,
    )
    for reason in impaired_reasons:
        outcome = _impaired(reason_codes=(reason,))
        assert _HEX64.fullmatch(outcome.outcome_digest)
    spent = _impaired(labels_spent=True, phase=workflow_outcome.WorkflowPhase.SCORING)
    assert spent.labels_spent is True
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _impaired(reason_codes=())
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _impaired(reason_codes=(workflow_outcome.WorkflowReasonCode.SCOPE_INSUFFICIENT,))
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _impaired(evaluation_replay_ref=_replay_reference())
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _impaired(stage_execution_evidence_digest=_digest("stage-executions"))
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _impaired(counts=_counts(planned_arms=2, completed_arms=0, planned_inputs=0, completed_inputs=0, deferred_inputs=0))
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _impaired(
            reason_codes=(
                workflow_outcome.WorkflowReasonCode.INSTRUMENT_FAILURE,
                workflow_outcome.WorkflowReasonCode.STALLED,
                workflow_outcome.WorkflowReasonCode.INSTRUMENT_FAILURE,
            )
        )


def test_unsafe_and_free_form_content_is_rejected_at_construction() -> None:
    unsafe_texts = (
        "Traceback (most recent call last): RuntimeError: boom",
        "/etc/passwd",
        "C:\\Users\\operator\\secrets.txt",
        "label: vuln-1234",
        "def exploit(): pass",
        "postgres://user:password@db/prod",
    )
    for text in unsafe_texts:
        with pytest.raises(workflow_outcome.WorkflowOutcomeError):
            _completed(failed_gate_names=(text,))
        with pytest.raises(workflow_outcome.WorkflowOutcomeError):
            _impaired(reason_codes=(text,))
        with pytest.raises(workflow_outcome.WorkflowOutcomeError):
            _insufficient(failed_gate_names=(workflow_outcome.WorkflowGate.PREFLIGHT_FEASIBILITY, text))
        with pytest.raises(workflow_outcome.WorkflowOutcomeError):
            _completed(status=text)
        with pytest.raises(workflow_outcome.WorkflowOutcomeError):
            _completed(population_digest=text)
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _completed(runtime_ms="4500")
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _completed(labels_spent="true")
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _completed(counts=_counts(planned_inputs=-1))
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _completed(evaluation_replay_ref="replay://operator/notes")
    error = workflow_outcome.WorkflowOutcomeError(workflow_outcome.WorkflowOutcomeErrorReason.INVALID_REQUEST)
    assert str(error) == "workflow_outcome_invalid_request"


def test_serialization_admits_only_closed_vocabulary() -> None:
    vocabulary = _closed_vocabulary()
    outcomes = (
        _completed(),
        _insufficient(),
        _impaired(),
        _impaired(
            reason_codes=(workflow_outcome.WorkflowReasonCode.INSTRUMENT_FAILURE,),
            phase=workflow_outcome.WorkflowPhase.CUSTODY_SPEND,
            failed_gate_names=(workflow_outcome.WorkflowGate.CUSTODY_COMMIT, workflow_outcome.WorkflowGate.SPEND_AUTHORITY),
            degradation_codes=(
                workflow_outcome.DegradationCode.ANALYZER_DEGRADED,
                workflow_outcome.DegradationCode.RESUMED_FROM_CHECKPOINT,
            ),
            labels_spent=True,
        ),
    )
    for outcome in outcomes:
        content = workflow_outcome.workflow_outcome_bytes(outcome)
        assert content
        for text in _walk_strings(json.loads(content)):
            assert text in vocabulary or _HEX64.fullmatch(text), text


def test_decode_rejects_unknown_missing_duplicate_and_noncanonical_content() -> None:
    content = workflow_outcome.workflow_outcome_bytes(_completed())
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        workflow_outcome.decode_workflow_outcome(_reserialized(content, lambda value: value.update({"operator_notes": "boom"})))
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        workflow_outcome.decode_workflow_outcome(_reserialized(content, lambda value: value.pop("runtime_ms")))
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        workflow_outcome.decode_workflow_outcome(_reserialized(content, lambda value: value.update({"schema_version": "other.v9"})))
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        workflow_outcome.decode_workflow_outcome(json.dumps(json.loads(content), sort_keys=True, separators=(", ", ": ")).encode())
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        workflow_outcome.decode_workflow_outcome(b'{"schema_version":"a","schema_version":"a"}')
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        workflow_outcome.decode_workflow_outcome(b"")
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        workflow_outcome.decode_workflow_outcome(b"[]")

    def _tamper(value: dict[str, object]) -> None:
        value["outcome_digest"] = _digest("tampered")

    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        workflow_outcome.decode_workflow_outcome(_reserialized(content, _tamper))


def test_deterministic_digest_and_byte_identical_serialization() -> None:
    first = _completed()
    second = _completed()
    assert first.outcome_digest == second.outcome_digest
    assert workflow_outcome.workflow_outcome_bytes(first) == workflow_outcome.workflow_outcome_bytes(second)
    explicit = _completed(outcome_digest=first.outcome_digest)
    assert explicit.outcome_digest == first.outcome_digest
    with pytest.raises(workflow_outcome.WorkflowOutcomeError):
        _completed(outcome_digest=_digest("wrong"))
    differing_runtime = _completed(runtime_ms=first.runtime_ms + 1)
    assert differing_runtime.outcome_digest != first.outcome_digest
    differing_degradations = _completed(degradation_codes=(workflow_outcome.DegradationCode.MODEL_FALLBACK,))
    assert differing_degradations.outcome_digest != first.outcome_digest


def test_every_terminal_and_resumable_state_round_trips_with_stable_digest() -> None:
    deferred = _counts(completed_inputs=10, deferred_inputs=2)
    states = (
        _completed(),
        _completed(
            phase=workflow_outcome.WorkflowPhase.REPORTING,
            degradation_codes=(workflow_outcome.DegradationCode.DEFERRED_INPUTS,),
            counts=deferred,
        ),
        _insufficient(),
        _impaired(),
        _impaired(labels_spent=True, phase=workflow_outcome.WorkflowPhase.LABEL_RELEASE),
        _impaired(
            reason_codes=(workflow_outcome.WorkflowReasonCode.STALLED,),
            failed_gate_names=(workflow_outcome.WorkflowGate.OBSERVATION_DURABILITY,),
        ),
    )
    for outcome in states:
        content = workflow_outcome.workflow_outcome_bytes(outcome)
        decoded = workflow_outcome.decode_workflow_outcome(content)
        assert decoded == outcome
        assert workflow_outcome.workflow_outcome_bytes(decoded) == content
        value = json.loads(content)
        recorded = value.pop("outcome_digest")
        assert recorded == outcome.outcome_digest
        assert canonical.bytes_digest(canonical_json_bytes(value)) == outcome.outcome_digest
