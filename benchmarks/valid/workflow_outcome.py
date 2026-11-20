"""Task 7.1 closed workflow outcomes and redacted deterministic serialization.

The outcome is the only shared workflow state that survives termination. Every
field is a closed enum, bounded integer, boolean, or full digest, so exception
text, filesystem paths, labels, repository contents, payloads, secrets, and
customer content have no field to enter and no serialization path to leak
through. Terminal and resumable states alike carry one deterministic content
digest over the canonical redacted projection.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TypeVar, cast

from benchmarks.valid.replacement_artifact_contract import (
    ArtifactAccessClass,
    ArtifactContractError,
    ArtifactKind,
    ArtifactReference,
    canonical_json_bytes,
)
from openultrasast.core import canonical
from openultrasast.core.canonical import JsonValue

WORKFLOW_OUTCOME_SCHEMA = "openultrasast.valid-detection-benchmark.workflow-outcome.v1"
WORKFLOW_OUTCOME_REFERENCE_SCHEMA = "openultrasast.valid-detection-benchmark.workflow-replay-reference.v1"
WORKFLOW_OUTCOME_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "phase",
        "reason_codes",
        "population_digest",
        "freeze_digest",
        "plan_digest",
        "workflow_digest",
        "labels_spent",
        "counts",
        "failed_gate_names",
        "degradation_codes",
        "runtime_ms",
        "input_read_evidence_digest",
        "stage_execution_evidence_digest",
        "evaluation_replay_ref",
        "outcome_digest",
    }
)
WORKFLOW_COUNT_FIELDS = frozenset(
    {
        "planned_arms",
        "completed_arms",
        "planned_inputs",
        "completed_inputs",
        "deferred_inputs",
    }
)
WORKFLOW_REFERENCE_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_kind",
        "access_class",
        "provenance_digest",
        "content_digest",
        "byte_length",
    }
)
_DIGEST = re.compile(r"[0-9a-f]{64}")
_EnumT = TypeVar("_EnumT", bound=StrEnum)


class WorkflowStatus(StrEnum):
    """Closed terminal taxonomy for a benchmark workflow."""

    COMPLETED = "completed"
    INSUFFICIENT = "insufficient"
    IMPAIRED = "impaired"


class WorkflowReasonCode(StrEnum):
    """Closed reasons; no free-form failure text is serializable."""

    SCOPE_INSUFFICIENT = "scope_insufficient"
    TIMED_OUT = "timed_out"
    BUDGET_EXHAUSTED = "budget_exhausted"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    INSTRUMENT_FAILURE = "instrument_failure"
    INTERRUPTED = "interrupted"
    STALLED = "stalled"


class WorkflowPhase(StrEnum):
    """Closed lifecycle phase the workflow occupied when the outcome was bound."""

    PREFLIGHT = "preflight"
    ARM_EXECUTION = "arm_execution"
    OBSERVATION_FREEZE = "observation_freeze"
    CUSTODY_SPEND = "custody_spend"
    LABEL_RELEASE = "label_release"
    SCORING = "scoring"
    REPORTING = "reporting"


class DegradationCode(StrEnum):
    """Closed safe degradations reported with the outcome."""

    RESUMED_FROM_CHECKPOINT = "resumed_from_checkpoint"
    AUTOMATIC_RETRY_USED = "automatic_retry_used"
    DEFERRED_INPUTS = "deferred_inputs"
    PARTIAL_COVERAGE = "partial_coverage"
    ANALYZER_DEGRADED = "analyzer_degraded"
    FACT_SOURCE_DEGRADED = "fact_source_degraded"
    MODEL_FALLBACK = "model_fallback"


class WorkflowGate(StrEnum):
    """Closed named gates; operator projections never receive ad hoc text."""

    POPULATION_FREEZE = "population_freeze"
    LABEL_BLIND_MANIFEST = "label_blind_manifest"
    PLAN_REGISTRATION = "plan_registration"
    STORE_CAPABILITY = "store_capability"
    PREFLIGHT_FEASIBILITY = "preflight_feasibility"
    RETRY_AUTHORITY = "retry_authority"
    ARM_EXECUTION = "arm_execution"
    OBSERVATION_DURABILITY = "observation_durability"
    ADMISSION_MANIFEST = "admission_manifest"
    SPEND_AUTHORITY = "spend_authority"
    CUSTODY_COMMIT = "custody_commit"
    LABEL_RELEASE = "label_release"
    SCORING = "scoring"
    REPLAY_VALIDATION = "replay_validation"


class WorkflowOutcomeErrorReason(StrEnum):
    """Closed refusal reasons; the error never echoes caller content."""

    INVALID_REQUEST = "invalid_request"
    INCONSISTENT_STATE = "inconsistent_state"
    DIGEST_MISMATCH = "digest_mismatch"
    MALFORMED_CONTENT = "malformed_content"


class WorkflowOutcomeError(ValueError):
    """Refuse unsafe or non-canonical outcome content with a closed reason."""

    def __init__(self, reason: WorkflowOutcomeErrorReason) -> None:
        self.reason = reason
        super().__init__(f"workflow_outcome_{reason.value}")


_IMPAIRED_REASONS = frozenset(
    {
        WorkflowReasonCode.TIMED_OUT,
        WorkflowReasonCode.BUDGET_EXHAUSTED,
        WorkflowReasonCode.RESOURCE_EXHAUSTED,
        WorkflowReasonCode.INSTRUMENT_FAILURE,
        WorkflowReasonCode.INTERRUPTED,
        WorkflowReasonCode.STALLED,
    }
)
_COMPLETED_PHASES = frozenset({WorkflowPhase.SCORING, WorkflowPhase.REPORTING})


def _digest(value: object, *, optional: bool = False) -> str:
    if optional and value == "":
        return ""
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.INVALID_REQUEST)
    return value


def _count(value: object) -> int:
    if type(value) is not int or not 0 <= value <= 1 << 31:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.INVALID_REQUEST)
    return value


def _closed_codes(value: object, enum_type: type[_EnumT]) -> tuple[_EnumT, ...]:
    if type(value) is not tuple or any(type(item) is not enum_type for item in value):
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.INVALID_REQUEST)
    expected = tuple(sorted(set(value), key=lambda item: item.value))
    if value != expected:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.INVALID_REQUEST)
    return value


@dataclass(frozen=True)
class WorkflowCounts:
    """Closed whole-population progress counts bound into every outcome."""

    planned_arms: int
    completed_arms: int
    planned_inputs: int
    completed_inputs: int
    deferred_inputs: int

    def __post_init__(self) -> None:
        if type(self) is not WorkflowCounts:
            raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.INVALID_REQUEST)
        for value in _count_fields(self):
            _count(value)
        if self.completed_arms > self.planned_arms or self.completed_inputs + self.deferred_inputs > self.planned_inputs:
            raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.INCONSISTENT_STATE)


def _count_fields(value: WorkflowCounts) -> tuple[int, ...]:
    return (
        value.planned_arms,
        value.completed_arms,
        value.planned_inputs,
        value.completed_inputs,
        value.deferred_inputs,
    )


@dataclass(frozen=True)
class BenchmarkWorkflowOutcomeV1:
    """Closed redacted outcome shared across terminal and resumable states."""

    status: WorkflowStatus
    phase: WorkflowPhase
    reason_codes: tuple[WorkflowReasonCode, ...]
    population_digest: str
    freeze_digest: str
    plan_digest: str
    workflow_digest: str
    labels_spent: bool
    counts: WorkflowCounts
    failed_gate_names: tuple[WorkflowGate, ...]
    degradation_codes: tuple[DegradationCode, ...]
    runtime_ms: int
    input_read_evidence_digest: str
    stage_execution_evidence_digest: str
    evaluation_replay_ref: ArtifactReference | None
    outcome_digest: str

    def __post_init__(self) -> None:
        _validate_outcome_shape(self)
        _validate_outcome_state(self)
        expected = canonical.content_digest(_outcome_value(self, include_digest=False))
        if not self.outcome_digest:
            object.__setattr__(self, "outcome_digest", expected)
        elif self.outcome_digest != expected:
            raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.DIGEST_MISMATCH)


def _validate_outcome_shape(value: BenchmarkWorkflowOutcomeV1) -> None:
    if (
        type(value) is not BenchmarkWorkflowOutcomeV1
        or type(value.status) is not WorkflowStatus
        or type(value.phase) is not WorkflowPhase
        or type(value.labels_spent) is not bool
        or type(value.counts) is not WorkflowCounts
    ):
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.INVALID_REQUEST)
    value.counts.__post_init__()
    _closed_codes(value.reason_codes, WorkflowReasonCode)
    _closed_codes(value.failed_gate_names, WorkflowGate)
    _closed_codes(value.degradation_codes, DegradationCode)
    for digest in (value.population_digest, value.freeze_digest, value.plan_digest, value.workflow_digest):
        _digest(digest)
    _digest(value.input_read_evidence_digest, optional=True)
    _digest(value.stage_execution_evidence_digest, optional=True)
    _digest(value.outcome_digest, optional=True)
    if value.evaluation_replay_ref is not None and type(value.evaluation_replay_ref) is not ArtifactReference:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.INVALID_REQUEST)
    _count(value.runtime_ms)


def _validate_outcome_state(value: BenchmarkWorkflowOutcomeV1) -> None:
    counts = value.counts
    if counts.planned_arms < 1 or counts.planned_inputs < 1:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.INCONSISTENT_STATE)
    if value.status is WorkflowStatus.COMPLETED:
        _require_completed(value)
    elif value.status is WorkflowStatus.INSUFFICIENT:
        _require_insufficient(value)
    else:
        _require_impaired(value)


def _require_completed(value: BenchmarkWorkflowOutcomeV1) -> None:
    """A clean status must prove one complete replay and every required stage."""
    counts = value.counts
    reference = value.evaluation_replay_ref
    if value.reason_codes or value.failed_gate_names:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.INCONSISTENT_STATE)
    if value.phase not in _COMPLETED_PHASES or not value.labels_spent:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.INCONSISTENT_STATE)
    if (
        reference is None
        or reference.artifact_kind is not ArtifactKind.REPLAY
        or reference.access_class is not ArtifactAccessClass.OPERATOR_SAFE
    ):
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.INCONSISTENT_STATE)
    if not value.input_read_evidence_digest or not value.stage_execution_evidence_digest:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.INCONSISTENT_STATE)
    if counts.completed_arms != counts.planned_arms:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.INCONSISTENT_STATE)
    if counts.completed_inputs + counts.deferred_inputs != counts.planned_inputs:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.INCONSISTENT_STATE)
    if (DegradationCode.DEFERRED_INPUTS in value.degradation_codes) != (counts.deferred_inputs > 0):
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.INCONSISTENT_STATE)


def _require_insufficient(value: BenchmarkWorkflowOutcomeV1) -> None:
    """Insufficiency is a pre-spend witness and never claims a clean result."""
    counts = value.counts
    if value.reason_codes != (WorkflowReasonCode.SCOPE_INSUFFICIENT,):
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.INCONSISTENT_STATE)
    if value.phase is not WorkflowPhase.PREFLIGHT or value.labels_spent:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.INCONSISTENT_STATE)
    if value.evaluation_replay_ref is not None or value.input_read_evidence_digest or value.stage_execution_evidence_digest:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.INCONSISTENT_STATE)
    if counts.completed_arms or counts.completed_inputs or counts.deferred_inputs != counts.planned_inputs:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.INCONSISTENT_STATE)
    if not value.failed_gate_names:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.INCONSISTENT_STATE)


def _require_impaired(value: BenchmarkWorkflowOutcomeV1) -> None:
    """Impairment stays resumable and never claims replay or stage proof."""
    if not value.reason_codes or any(code not in _IMPAIRED_REASONS for code in value.reason_codes):
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.INCONSISTENT_STATE)
    if value.evaluation_replay_ref is not None or value.input_read_evidence_digest or value.stage_execution_evidence_digest:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.INCONSISTENT_STATE)


def _reference_value(reference: ArtifactReference) -> dict[str, JsonValue]:
    return {
        "schema_version": WORKFLOW_OUTCOME_REFERENCE_SCHEMA,
        "artifact_kind": reference.artifact_kind.value,
        "access_class": reference.access_class.value,
        "provenance_digest": reference.provenance_digest,
        "content_digest": reference.content_digest,
        "byte_length": reference.byte_length,
    }


def _outcome_value(value: BenchmarkWorkflowOutcomeV1, *, include_digest: bool) -> dict[str, JsonValue]:
    counts = value.counts
    result: dict[str, JsonValue] = {
        "schema_version": WORKFLOW_OUTCOME_SCHEMA,
        "status": value.status.value,
        "phase": value.phase.value,
        "reason_codes": tuple(code.value for code in value.reason_codes),
        "population_digest": value.population_digest,
        "freeze_digest": value.freeze_digest,
        "plan_digest": value.plan_digest,
        "workflow_digest": value.workflow_digest,
        "labels_spent": value.labels_spent,
        "counts": {
            "planned_arms": counts.planned_arms,
            "completed_arms": counts.completed_arms,
            "planned_inputs": counts.planned_inputs,
            "completed_inputs": counts.completed_inputs,
            "deferred_inputs": counts.deferred_inputs,
        },
        "failed_gate_names": tuple(gate.value for gate in value.failed_gate_names),
        "degradation_codes": tuple(code.value for code in value.degradation_codes),
        "runtime_ms": value.runtime_ms,
        "input_read_evidence_digest": value.input_read_evidence_digest or None,
        "stage_execution_evidence_digest": value.stage_execution_evidence_digest or None,
        "evaluation_replay_ref": None if value.evaluation_replay_ref is None else _reference_value(value.evaluation_replay_ref),
    }
    if include_digest:
        result["outcome_digest"] = value.outcome_digest
    return result


def workflow_outcome_bytes(value: BenchmarkWorkflowOutcomeV1) -> bytes:
    """Encode a revalidated outcome as deterministic redacted canonical JSON."""
    value.__post_init__()
    return canonical.canonical_bytes(_outcome_value(value, include_digest=True))


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.MALFORMED_CONTENT)
        value[key] = item
    return value


def _decode_canonical(content: bytes) -> dict[str, object]:
    if type(content) is not bytes or not content:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.MALFORMED_CONTENT)
    try:
        decoded = json.loads(content, object_pairs_hook=_unique_object)
    except WorkflowOutcomeError:
        raise
    except (UnicodeError, json.JSONDecodeError):
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.MALFORMED_CONTENT) from None
    if type(decoded) is not dict:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.MALFORMED_CONTENT)
    try:
        encoded = canonical_json_bytes(decoded)
    except (ArtifactContractError, TypeError, ValueError, UnicodeError):
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.MALFORMED_CONTENT) from None
    if encoded != content:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.MALFORMED_CONTENT)
    return decoded


def _decode_enum(value: object, enum_type: type[_EnumT]) -> _EnumT:
    if type(value) is not str:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.MALFORMED_CONTENT)
    try:
        return enum_type(value)
    except ValueError:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.MALFORMED_CONTENT) from None


def _decode_codes(value: object, enum_type: type[_EnumT]) -> tuple[_EnumT, ...]:
    if type(value) is not list or any(type(item) is not str for item in value):
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.MALFORMED_CONTENT)
    return tuple(_decode_enum(item, enum_type) for item in value)


def _decode_digest(value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.MALFORMED_CONTENT)
    return value


def _decode_optional_digest(value: object) -> str:
    if value is None:
        return ""
    return _decode_digest(value)


def _decode_counts(value: object) -> WorkflowCounts:
    if type(value) is not dict or set(value) != WORKFLOW_COUNT_FIELDS:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.MALFORMED_CONTENT)
    try:
        return WorkflowCounts(
            _decode_int(value["planned_arms"]),
            _decode_int(value["completed_arms"]),
            _decode_int(value["planned_inputs"]),
            _decode_int(value["completed_inputs"]),
            _decode_int(value["deferred_inputs"]),
        )
    except KeyError:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.MALFORMED_CONTENT) from None


def _decode_int(value: object) -> int:
    if type(value) is not int:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.MALFORMED_CONTENT)
    return value


def _decode_replay_reference(value: object) -> ArtifactReference | None:
    if value is None:
        return None
    if type(value) is not dict or set(value) != WORKFLOW_REFERENCE_FIELDS:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.MALFORMED_CONTENT)
    if value.get("schema_version") != WORKFLOW_OUTCOME_REFERENCE_SCHEMA:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.MALFORMED_CONTENT)
    try:
        return ArtifactReference(
            ArtifactKind(value["artifact_kind"]),
            _decode_digest(value["content_digest"]),
            _decode_int(value["byte_length"]),
            _decode_digest(value["provenance_digest"]),
            ArtifactAccessClass(value["access_class"]),
        )
    except KeyError:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.MALFORMED_CONTENT) from None


def decode_workflow_outcome(content: bytes) -> BenchmarkWorkflowOutcomeV1:
    """Decode only canonical redacted outcome bytes under the closed schema."""
    value = _decode_canonical(content)
    if set(value) != WORKFLOW_OUTCOME_FIELDS or value.get("schema_version") != WORKFLOW_OUTCOME_SCHEMA:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.MALFORMED_CONTENT)
    if type(value.get("labels_spent")) is not bool or type(value.get("runtime_ms")) is not int:
        raise WorkflowOutcomeError(WorkflowOutcomeErrorReason.MALFORMED_CONTENT)
    return BenchmarkWorkflowOutcomeV1(
        _decode_enum(value.get("status"), WorkflowStatus),
        _decode_enum(value.get("phase"), WorkflowPhase),
        _decode_codes(value.get("reason_codes"), WorkflowReasonCode),
        _decode_digest(value.get("population_digest")),
        _decode_digest(value.get("freeze_digest")),
        _decode_digest(value.get("plan_digest")),
        _decode_digest(value.get("workflow_digest")),
        cast(bool, value.get("labels_spent")),
        _decode_counts(value.get("counts")),
        _decode_codes(value.get("failed_gate_names"), WorkflowGate),
        _decode_codes(value.get("degradation_codes"), DegradationCode),
        _decode_int(value.get("runtime_ms")),
        _decode_optional_digest(value.get("input_read_evidence_digest")),
        _decode_optional_digest(value.get("stage_execution_evidence_digest")),
        _decode_replay_reference(value.get("evaluation_replay_ref")),
        _decode_digest(value.get("outcome_digest")),
    )


__all__ = [
    "BenchmarkWorkflowOutcomeV1",
    "DegradationCode",
    "WorkflowCounts",
    "WorkflowGate",
    "WorkflowOutcomeError",
    "WorkflowOutcomeErrorReason",
    "WorkflowPhase",
    "WorkflowReasonCode",
    "WorkflowStatus",
    "WORKFLOW_COUNT_FIELDS",
    "WORKFLOW_OUTCOME_FIELDS",
    "WORKFLOW_OUTCOME_REFERENCE_SCHEMA",
    "WORKFLOW_OUTCOME_SCHEMA",
    "WORKFLOW_REFERENCE_FIELDS",
    "decode_workflow_outcome",
    "workflow_outcome_bytes",
]
