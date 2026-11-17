"""Closed nonzero execution receipts for one isolated component arm."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from benchmarks.valid.isolated_execution import (
    ArmProcessOutcomeV1,
    ProcessOutcomeReason,
    ProcessOutcomeStatus,
)
from benchmarks.valid.isolated_execution_bundle import LabelBlindExecutionBundleV1
from openultrasast.core import canonical
from openultrasast.core.canonical import JsonValue

EXECUTION_RECEIPT_SCHEMA = "openultrasast.valid-detection-benchmark.execution-receipt.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_OPAQUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}")
_READ_FIELDS = frozenset({"input_identity_digest", "expected_bytes", "bytes_read", "status", "read_digest"})
_STAGE_FIELDS = frozenset({"stage", "status", "evidence_digest", "stage_digest"})
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "plan_digest",
        "registration_digest",
        "bundle_digest",
        "arm_id",
        "input_set_digest",
        "budget_digest",
        "environment_digest",
        "output_destination_digest",
        "outcome_digest",
        "output_digest",
        "output_bytes",
        "runtime_ms",
        "deadline_seconds",
        "memory_bytes",
        "disk_bytes",
        "maximum_output_bytes",
        "input_reads",
        "stage_executions",
        "degradations",
        "status",
        "reason",
        "input_read_evidence_digest",
        "stage_execution_evidence_digest",
        "receipt_digest",
    }
)


class ReceiptStatus(StrEnum):
    COMPLETED = "completed"
    IMPAIRED = "impaired"


class ReceiptReason(StrEnum):
    NONE = "none"
    INPUT_UNREADABLE = "input_unreadable"
    INPUT_EMPTY = "input_empty"
    INPUT_SKIPPED = "input_skipped"
    INPUT_PARTIAL = "input_partial"
    INPUT_SET_INCOMPLETE = "input_set_incomplete"
    REQUIRED_STAGE_SKIPPED = "required_stage_skipped"
    REQUIRED_STAGE_FAILED = "required_stage_failed"
    PREMATURE_TERMINATION = "premature_termination"
    PROCESS_IMPAIRED = "process_impaired"
    BUDGET_EXHAUSTED = "budget_exhausted"
    OUTPUT_EMPTY = "output_empty"
    OUTPUT_INVALID = "output_invalid"
    IDENTITY_MISMATCH = "identity_mismatch"


class InputReadStatus(StrEnum):
    COMPLETED = "completed"
    UNREADABLE = "unreadable"
    EMPTY = "empty"
    SKIPPED = "skipped"
    PARTIAL = "partial"


class RequiredExecutionStage(StrEnum):
    INPUT_READ = "input_read"
    ANALYZE = "analyze"
    OUTPUT_WRITE = "output_write"


class StageExecutionStatus(StrEnum):
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"
    PREMATURE = "premature"


class ExecutionDegradation(StrEnum):
    ANALYZER_DEGRADED = "analyzer_degraded"
    FACT_SOURCE_DEGRADED = "fact_source_degraded"
    MODEL_FALLBACK = "model_fallback"


class ExecutionReceiptError(ValueError):
    """Receipt bytes or evidence are malformed or cross-bound."""


def _digest(value: object, field: str, *, optional: bool = False) -> str:
    if optional and value == "":
        return ""
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ExecutionReceiptError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _opaque(value: object, field: str) -> str:
    if type(value) is not str or _OPAQUE.fullmatch(value) is None:
        raise ExecutionReceiptError(f"{field} must be an opaque identifier")
    return value


def _integer(value: object, field: str, maximum: int, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if type(value) is not int or not minimum <= value <= maximum:
        raise ExecutionReceiptError(f"{field} must be a bounded integer")
    return value


def _bind(value: object, field: str, expected: str) -> None:
    actual = getattr(value, field)
    if actual == "":
        object.__setattr__(value, field, expected)
    elif _digest(actual, field) != expected:
        raise ExecutionReceiptError(f"{field} does not match canonical content")


@dataclass(frozen=True)
class InputReadReceiptV1:
    input_identity_digest: str
    expected_bytes: int
    bytes_read: int
    status: InputReadStatus
    read_digest: str

    def __post_init__(self) -> None:
        if type(self) is not InputReadReceiptV1 or type(self.status) is not InputReadStatus:
            raise ExecutionReceiptError("input read must use exact closed receipt types")
        _digest(self.input_identity_digest, "input identity")
        _integer(self.expected_bytes, "expected input bytes", 1 << 34, positive=True)
        _integer(self.bytes_read, "input bytes read", self.expected_bytes)
        if self.status is InputReadStatus.COMPLETED and self.bytes_read != self.expected_bytes:
            raise ExecutionReceiptError("completed input read must consume the exact nonzero input")
        if self.status is InputReadStatus.PARTIAL and not 0 < self.bytes_read < self.expected_bytes:
            raise ExecutionReceiptError("partial input read must be nonzero and incomplete")
        if self.status not in {InputReadStatus.COMPLETED, InputReadStatus.PARTIAL} and self.bytes_read != 0:
            raise ExecutionReceiptError("unreadable, empty, or skipped input cannot claim bytes")
        _bind(self, "read_digest", canonical.content_digest(_read_value(self, include_digest=False)))


def _read_value(value: InputReadReceiptV1, *, include_digest: bool) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "input_identity_digest": value.input_identity_digest,
        "expected_bytes": value.expected_bytes,
        "bytes_read": value.bytes_read,
        "status": value.status.value,
    }
    if include_digest:
        result["read_digest"] = value.read_digest
    return result


@dataclass(frozen=True)
class StageExecutionReceiptV1:
    stage: RequiredExecutionStage
    status: StageExecutionStatus
    evidence_digest: str
    stage_digest: str

    def __post_init__(self) -> None:
        if (
            type(self) is not StageExecutionReceiptV1
            or type(self.stage) is not RequiredExecutionStage
            or type(self.status) is not StageExecutionStatus
        ):
            raise ExecutionReceiptError("stage receipt must use exact closed receipt types")
        _digest(self.evidence_digest, "stage evidence", optional=self.status is not StageExecutionStatus.COMPLETED)
        if self.status is StageExecutionStatus.COMPLETED and not self.evidence_digest:
            raise ExecutionReceiptError("completed stage requires nonzero evidence")
        if self.status is not StageExecutionStatus.COMPLETED and self.evidence_digest:
            raise ExecutionReceiptError("incomplete stage cannot claim completion evidence")
        _bind(self, "stage_digest", canonical.content_digest(_stage_value(self, include_digest=False)))


def _stage_value(value: StageExecutionReceiptV1, *, include_digest: bool) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "stage": value.stage.value,
        "status": value.status.value,
        "evidence_digest": value.evidence_digest or None,
    }
    if include_digest:
        result["stage_digest"] = value.stage_digest
    return result


def input_read_evidence_digest(reads: tuple[InputReadReceiptV1, ...]) -> str:
    if type(reads) is not tuple or any(type(row) is not InputReadReceiptV1 for row in reads):
        raise ExecutionReceiptError("input reads must be an exact tuple")
    for row in reads:
        row.__post_init__()
    return canonical.content_digest(
        {"schema_version": EXECUTION_RECEIPT_SCHEMA, "input_read_digests": tuple(row.read_digest for row in reads)}
    )


def stage_execution_evidence_digest(stages: tuple[StageExecutionReceiptV1, ...]) -> str:
    if type(stages) is not tuple or any(type(row) is not StageExecutionReceiptV1 for row in stages):
        raise ExecutionReceiptError("stage receipts must be an exact tuple")
    for row in stages:
        row.__post_init__()
    return canonical.content_digest(
        {"schema_version": EXECUTION_RECEIPT_SCHEMA, "stage_digests": tuple(row.stage_digest for row in stages)}
    )


@dataclass(frozen=True)
class ExecutionReceiptV1:
    plan_digest: str
    registration_digest: str
    bundle_digest: str
    arm_id: str
    input_set_digest: str
    budget_digest: str
    environment_digest: str
    output_destination_digest: str
    outcome_digest: str
    output_digest: str
    output_bytes: int
    runtime_ms: int
    deadline_seconds: int
    memory_bytes: int
    disk_bytes: int
    maximum_output_bytes: int
    input_reads: tuple[InputReadReceiptV1, ...]
    stage_executions: tuple[StageExecutionReceiptV1, ...]
    degradations: tuple[ExecutionDegradation, ...]
    status: ReceiptStatus
    reason: ReceiptReason
    input_read_evidence_digest: str
    stage_execution_evidence_digest: str
    receipt_digest: str

    def __post_init__(self) -> None:
        _validate_receipt_types(self)
        for item, field in _receipt_digests(self):
            _digest(item, field, optional=field == "output")
        _opaque(self.arm_id, "receipt arm id")
        _validate_receipt_bounds(self)
        _validate_evidence_rows(self)
        if self.input_read_evidence_digest != input_read_evidence_digest(self.input_reads):
            raise ExecutionReceiptError("input-read evidence digest does not match rows")
        if self.stage_execution_evidence_digest != stage_execution_evidence_digest(self.stage_executions):
            raise ExecutionReceiptError("stage-execution evidence digest does not match rows")
        _validate_receipt_state(self)
        _validate_completed_outcome_binding(self)
        _bind(self, "receipt_digest", canonical.content_digest(_receipt_value(self, include_digest=False)))


def _validate_receipt_types(value: ExecutionReceiptV1) -> None:
    if type(value) is not ExecutionReceiptV1:
        raise ExecutionReceiptError("receipt must use exact ExecutionReceiptV1")
    if type(value.status) is not ReceiptStatus or type(value.reason) is not ReceiptReason:
        raise ExecutionReceiptError("receipt must use closed status and reason enums")
    if type(value.degradations) is not tuple or any(type(row) is not ExecutionDegradation for row in value.degradations):
        raise ExecutionReceiptError("receipt degradations must use a closed exact tuple")
    if value.degradations != tuple(sorted(set(value.degradations), key=lambda row: row.value)):
        raise ExecutionReceiptError("receipt degradations must be unique and canonical")


def _receipt_digests(value: ExecutionReceiptV1) -> tuple[tuple[str, str], ...]:
    return (
        (value.plan_digest, "plan"),
        (value.registration_digest, "registration"),
        (value.bundle_digest, "bundle"),
        (value.input_set_digest, "input set"),
        (value.budget_digest, "budget"),
        (value.environment_digest, "environment"),
        (value.output_destination_digest, "output destination"),
        (value.outcome_digest, "process outcome"),
        (value.output_digest, "output"),
        (value.input_read_evidence_digest, "input-read evidence"),
        (value.stage_execution_evidence_digest, "stage-execution evidence"),
    )


def _validate_receipt_bounds(value: ExecutionReceiptV1) -> None:
    _integer(value.output_bytes, "output bytes", 64 * 1024 * 1024)
    _integer(value.runtime_ms, "runtime", 86_400_000)
    _integer(value.deadline_seconds, "deadline", 86_400, positive=True)
    _integer(value.memory_bytes, "memory budget", 1 << 40, positive=True)
    _integer(value.disk_bytes, "disk budget", 1 << 42, positive=True)
    _integer(value.maximum_output_bytes, "output budget", 64 * 1024 * 1024, positive=True)
    if value.output_bytes > value.maximum_output_bytes:
        raise ExecutionReceiptError("output exceeds the registered bound")


def _validate_evidence_rows(value: ExecutionReceiptV1) -> None:
    if type(value.input_reads) is not tuple or any(type(row) is not InputReadReceiptV1 for row in value.input_reads):
        raise ExecutionReceiptError("input reads must use exact receipt values")
    if len({row.input_identity_digest for row in value.input_reads}) != len(value.input_reads):
        raise ExecutionReceiptError("input reads must use unique identities")
    if type(value.stage_executions) is not tuple or any(type(row) is not StageExecutionReceiptV1 for row in value.stage_executions):
        raise ExecutionReceiptError("stage executions must use exact receipt values")
    if tuple(row.stage for row in value.stage_executions) != tuple(RequiredExecutionStage):
        raise ExecutionReceiptError("stage executions must equal every required stage in canonical order")


def _validate_receipt_state(value: ExecutionReceiptV1) -> None:
    if value.status is ReceiptStatus.IMPAIRED:
        if value.reason is ReceiptReason.NONE:
            raise ExecutionReceiptError("impaired receipt requires a closed reason")
        return
    complete = (
        value.reason is ReceiptReason.NONE
        and bool(value.input_reads)
        and all(row.status is InputReadStatus.COMPLETED and row.bytes_read > 0 for row in value.input_reads)
        and all(row.status is StageExecutionStatus.COMPLETED for row in value.stage_executions)
        and bool(value.output_digest)
        and value.output_bytes > 0
        and value.runtime_ms <= value.deadline_seconds * 1000
    )
    if not complete:
        raise ExecutionReceiptError("completed receipt lacks nonzero reads, required stages, output, or budget compliance")


def _validate_completed_outcome_binding(value: ExecutionReceiptV1) -> None:
    if value.status is not ReceiptStatus.COMPLETED:
        return
    try:
        ArmProcessOutcomeV1(
            value.bundle_digest,
            value.arm_id,
            ProcessOutcomeStatus.COMPLETED,
            ProcessOutcomeReason.NONE,
            value.runtime_ms,
            value.output_digest,
            value.output_bytes,
            value.outcome_digest,
        )
    except (TypeError, ValueError):
        raise ExecutionReceiptError("completed receipt outcome digest does not match its recorded process outcome") from None


def _receipt_value(value: ExecutionReceiptV1, *, include_digest: bool) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "schema_version": EXECUTION_RECEIPT_SCHEMA,
        "plan_digest": value.plan_digest,
        "registration_digest": value.registration_digest,
        "bundle_digest": value.bundle_digest,
        "arm_id": value.arm_id,
        "input_set_digest": value.input_set_digest,
        "budget_digest": value.budget_digest,
        "environment_digest": value.environment_digest,
        "output_destination_digest": value.output_destination_digest,
        "outcome_digest": value.outcome_digest,
        "output_digest": value.output_digest or None,
        "output_bytes": value.output_bytes,
        "runtime_ms": value.runtime_ms,
        "deadline_seconds": value.deadline_seconds,
        "memory_bytes": value.memory_bytes,
        "disk_bytes": value.disk_bytes,
        "maximum_output_bytes": value.maximum_output_bytes,
        "input_reads": tuple(_read_value(row, include_digest=True) for row in value.input_reads),
        "stage_executions": tuple(_stage_value(row, include_digest=True) for row in value.stage_executions),
        "degradations": tuple(row.value for row in value.degradations),
        "status": value.status.value,
        "reason": value.reason.value,
        "input_read_evidence_digest": value.input_read_evidence_digest,
        "stage_execution_evidence_digest": value.stage_execution_evidence_digest,
    }
    if include_digest:
        result["receipt_digest"] = value.receipt_digest
    return result


def execution_receipt_bytes(value: ExecutionReceiptV1) -> bytes:
    value.__post_init__()
    return canonical.canonical_bytes(_receipt_value(value, include_digest=True))


def _reason_for_rows(bundle: LabelBlindExecutionBundleV1, reads: tuple[InputReadReceiptV1, ...]) -> ReceiptReason:
    expected = tuple((row.input_identity_digest, row.code_reference.byte_length) for row in bundle.case_inputs)
    actual = tuple((row.input_identity_digest, row.expected_bytes) for row in reads)
    if actual != expected:
        return ReceiptReason.INPUT_SET_INCOMPLETE
    mapping = {
        InputReadStatus.UNREADABLE: ReceiptReason.INPUT_UNREADABLE,
        InputReadStatus.EMPTY: ReceiptReason.INPUT_EMPTY,
        InputReadStatus.SKIPPED: ReceiptReason.INPUT_SKIPPED,
        InputReadStatus.PARTIAL: ReceiptReason.INPUT_PARTIAL,
    }
    return next((mapping[row.status] for row in reads if row.status in mapping), ReceiptReason.NONE)


def _reason_for_stages(stages: tuple[StageExecutionReceiptV1, ...]) -> ReceiptReason:
    if tuple(row.stage for row in stages) != tuple(RequiredExecutionStage):
        return ReceiptReason.REQUIRED_STAGE_SKIPPED
    mapping = {
        StageExecutionStatus.SKIPPED: ReceiptReason.REQUIRED_STAGE_SKIPPED,
        StageExecutionStatus.FAILED: ReceiptReason.REQUIRED_STAGE_FAILED,
        StageExecutionStatus.PREMATURE: ReceiptReason.PREMATURE_TERMINATION,
    }
    return next((mapping[row.status] for row in stages if row.status in mapping), ReceiptReason.NONE)


def build_execution_receipt(
    bundle: LabelBlindExecutionBundleV1,
    outcome: ArmProcessOutcomeV1,
    reads: tuple[InputReadReceiptV1, ...],
    stages: tuple[StageExecutionReceiptV1, ...],
    degradations: tuple[ExecutionDegradation, ...] = (),
) -> ExecutionReceiptV1:
    """Canonicalize instrument evidence and close every incomplete state."""
    bundle.__post_init__()
    identity_matches = type(outcome) is ArmProcessOutcomeV1
    try:
        outcome.__post_init__()
    except (AttributeError, TypeError, ValueError):
        identity_matches = False
    if identity_matches:
        identity_matches = outcome.bundle_digest == bundle.bundle_digest and outcome.arm_id == bundle.arm.arm_id
    reason = ReceiptReason.IDENTITY_MISMATCH if not identity_matches else ReceiptReason.NONE
    if reason is ReceiptReason.NONE and outcome.status is ProcessOutcomeStatus.IMPAIRED:
        reason = ReceiptReason.PROCESS_IMPAIRED
    if reason is ReceiptReason.NONE:
        reason = _reason_for_rows(bundle, reads)
    if reason is ReceiptReason.NONE:
        reason = _reason_for_stages(stages)
    if reason is ReceiptReason.NONE and outcome.runtime_ms > bundle.budget.deadline_seconds * 1000:
        reason = ReceiptReason.BUDGET_EXHAUSTED
    if reason is ReceiptReason.NONE and (outcome.output_bytes == 0 or not outcome.output_digest):
        reason = ReceiptReason.OUTPUT_EMPTY
    status = ReceiptStatus.COMPLETED if reason is ReceiptReason.NONE else ReceiptStatus.IMPAIRED
    return ExecutionReceiptV1(
        bundle.plan_digest,
        bundle.arm.registration_digest,
        bundle.bundle_digest,
        bundle.arm.arm_id,
        bundle.input_set_digest,
        bundle.budget.budget_digest,
        bundle.environment.environment_digest,
        bundle.output_destination.destination_digest,
        outcome.outcome_digest,
        outcome.output_digest,
        outcome.output_bytes,
        outcome.runtime_ms,
        bundle.budget.deadline_seconds,
        bundle.budget.memory_bytes,
        bundle.budget.disk_bytes,
        bundle.budget.maximum_output_bytes,
        reads,
        stages,
        degradations,
        status,
        reason,
        input_read_evidence_digest(reads),
        stage_execution_evidence_digest(stages),
        "",
    )


def validate_execution_receipt_for_bundle(
    bundle: LabelBlindExecutionBundleV1,
    receipt: ExecutionReceiptV1,
) -> None:
    """Require one receipt to bind every current bundle identity and input read."""
    if type(bundle) is not LabelBlindExecutionBundleV1 or type(receipt) is not ExecutionReceiptV1:
        raise ExecutionReceiptError("receipt validation requires exact execution contracts")
    bundle.__post_init__()
    receipt.__post_init__()
    expected_identity = (
        bundle.plan_digest,
        bundle.arm.registration_digest,
        bundle.bundle_digest,
        bundle.arm.arm_id,
        bundle.input_set_digest,
        bundle.budget.budget_digest,
        bundle.budget.deadline_seconds,
        bundle.budget.memory_bytes,
        bundle.budget.disk_bytes,
        bundle.budget.maximum_output_bytes,
        bundle.environment.environment_digest,
        bundle.output_destination.destination_digest,
    )
    actual_identity = (
        receipt.plan_digest,
        receipt.registration_digest,
        receipt.bundle_digest,
        receipt.arm_id,
        receipt.input_set_digest,
        receipt.budget_digest,
        receipt.deadline_seconds,
        receipt.memory_bytes,
        receipt.disk_bytes,
        receipt.maximum_output_bytes,
        receipt.environment_digest,
        receipt.output_destination_digest,
    )
    expected_reads = tuple((row.input_identity_digest, row.code_reference.byte_length) for row in bundle.case_inputs)
    actual_reads = tuple((row.input_identity_digest, row.expected_bytes) for row in receipt.input_reads)
    if actual_identity != expected_identity or actual_reads != expected_reads:
        raise ExecutionReceiptError("execution receipt does not bind the exact current bundle")
    _validate_completed_outcome_binding(receipt)


def execution_receipt_value(value: ExecutionReceiptV1) -> dict[str, JsonValue]:
    value.__post_init__()
    return _receipt_value(value, include_digest=True)


def execution_receipt_from_value(value: object) -> ExecutionReceiptV1:
    if type(value) is not dict or frozenset(value) != _RECEIPT_FIELDS or value.get("schema_version") != EXECUTION_RECEIPT_SCHEMA:
        raise ExecutionReceiptError("execution receipt must be an exact object")
    try:
        read_values = cast(object, value["input_reads"])
        stage_values = cast(object, value["stage_executions"])
        if type(read_values) is not list and type(read_values) is not tuple:
            raise ExecutionReceiptError("execution input-read fields are malformed")
        if type(stage_values) is not list and type(stage_values) is not tuple:
            raise ExecutionReceiptError("execution stage fields are malformed")
        read_rows = cast(list[object] | tuple[object, ...], read_values)
        stage_rows = cast(list[object] | tuple[object, ...], stage_values)
        if any(type(row) is not dict or frozenset(row) != _READ_FIELDS for row in read_rows):
            raise ExecutionReceiptError("execution input-read fields are malformed")
        if any(type(row) is not dict or frozenset(row) != _STAGE_FIELDS for row in stage_rows):
            raise ExecutionReceiptError("execution stage fields are malformed")
        reads = tuple(
            InputReadReceiptV1(
                cast(str, row["input_identity_digest"]),
                cast(int, row["expected_bytes"]),
                cast(int, row["bytes_read"]),
                InputReadStatus(cast(str, row["status"])),
                cast(str, row["read_digest"]),
            )
            for row in cast(list[dict[str, object]] | tuple[dict[str, object], ...], read_rows)
        )
        stages = tuple(
            StageExecutionReceiptV1(
                RequiredExecutionStage(cast(str, row["stage"])),
                StageExecutionStatus(cast(str, row["status"])),
                cast(str | None, row["evidence_digest"]) or "",
                cast(str, row["stage_digest"]),
            )
            for row in cast(list[dict[str, object]] | tuple[dict[str, object], ...], stage_rows)
        )
        return ExecutionReceiptV1(
            plan_digest=cast(str, value["plan_digest"]),
            registration_digest=cast(str, value["registration_digest"]),
            bundle_digest=cast(str, value["bundle_digest"]),
            arm_id=cast(str, value["arm_id"]),
            input_set_digest=cast(str, value["input_set_digest"]),
            budget_digest=cast(str, value["budget_digest"]),
            environment_digest=cast(str, value["environment_digest"]),
            output_destination_digest=cast(str, value["output_destination_digest"]),
            outcome_digest=cast(str, value["outcome_digest"]),
            output_digest=cast(str | None, value["output_digest"]) or "",
            output_bytes=cast(int, value["output_bytes"]),
            runtime_ms=cast(int, value["runtime_ms"]),
            deadline_seconds=cast(int, value["deadline_seconds"]),
            memory_bytes=cast(int, value["memory_bytes"]),
            disk_bytes=cast(int, value["disk_bytes"]),
            maximum_output_bytes=cast(int, value["maximum_output_bytes"]),
            input_reads=reads,
            stage_executions=stages,
            degradations=tuple(ExecutionDegradation(row) for row in cast(list[str], value["degradations"])),
            status=ReceiptStatus(cast(str, value["status"])),
            reason=ReceiptReason(cast(str, value["reason"])),
            input_read_evidence_digest=cast(str, value["input_read_evidence_digest"]),
            stage_execution_evidence_digest=cast(str, value["stage_execution_evidence_digest"]),
            receipt_digest=cast(str, value["receipt_digest"]),
        )
    except (KeyError, TypeError, ValueError, ExecutionReceiptError) as exc:
        if isinstance(exc, ExecutionReceiptError):
            raise
        raise ExecutionReceiptError("execution receipt fields are malformed") from None


def decode_execution_receipt(content: bytes) -> ExecutionReceiptV1:
    if type(content) is not bytes or not content:
        raise ExecutionReceiptError("execution receipt bytes must be nonzero")
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ExecutionReceiptError("execution receipt bytes are malformed") from None
    receipt = execution_receipt_from_value(value)
    if execution_receipt_bytes(receipt) != content:
        raise ExecutionReceiptError("execution receipt bytes are not canonical")
    return receipt


__all__ = [
    "EXECUTION_RECEIPT_SCHEMA",
    "ExecutionDegradation",
    "ExecutionReceiptError",
    "ExecutionReceiptV1",
    "InputReadReceiptV1",
    "InputReadStatus",
    "ReceiptReason",
    "ReceiptStatus",
    "RequiredExecutionStage",
    "StageExecutionReceiptV1",
    "StageExecutionStatus",
    "build_execution_receipt",
    "decode_execution_receipt",
    "execution_receipt_bytes",
    "execution_receipt_from_value",
    "execution_receipt_value",
    "input_read_evidence_digest",
    "stage_execution_evidence_digest",
    "validate_execution_receipt_for_bundle",
]
