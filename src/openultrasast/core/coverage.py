"""Coverage accounting for the detection core (Req 3).

Every input is accounted for: entry recognition, exactly one resolution bucket per
call, named reasons for unchecked operations. A zero-byte or unreadable input is an
instrument failure -- a zero from an unread input is a failed run, never a clean one.
"""

from __future__ import annotations

import enum
import re
from collections.abc import Sequence
from dataclasses import dataclass

from openultrasast.core.canonical import JsonValue, content_digest, require_unique_identities
from openultrasast.core.semantics import RelationStatus

INPUT_MANIFEST_SCHEMA = "openultrasast.detection-core.input-manifest.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class InstrumentFailure(ValueError):
    """The v2 run did not read every tracked input."""


def _require_text(value: object, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be nonempty text")


def _require_digest(value: object, field_name: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a full lowercase SHA-256 digest")


def _require_count(value: object, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")


def _validate_input_ids(value: object) -> tuple[str, ...]:
    if not isinstance(value, tuple) or not value:
        raise ValueError("tracked_input_ids must be a nonempty tuple")
    for input_id in value:
        _require_text(input_id, "tracked input id")
    require_unique_identities(value, kind="tracked input")
    return value


def derive_input_manifest_digest(tracked_input_ids: tuple[str, ...]) -> str:
    """Derive the identity of the exact ordered tracked-input manifest."""
    inputs = _validate_input_ids(tracked_input_ids)
    payload: JsonValue = {"schema_version": INPUT_MANIFEST_SCHEMA, "tracked_input_ids": inputs}
    return content_digest(payload)


@dataclass(frozen=True)
class InputManifest:
    tracked_input_ids: tuple[str, ...]
    manifest_digest: str

    def __post_init__(self) -> None:
        _validate_input_ids(self.tracked_input_ids)
        _require_digest(self.manifest_digest, "manifest_digest")


@dataclass(frozen=True)
class InputReadReceipt:
    input_id: str
    path: str
    opened: bool
    byte_count: int
    content_digest: str | None

    def __post_init__(self) -> None:
        _require_text(self.input_id, "input_id")
        _require_text(self.path, "path")
        if not isinstance(self.opened, bool):
            raise ValueError("opened must be a boolean")
        _require_count(self.byte_count, "byte_count")
        if self.content_digest is not None:
            _require_digest(self.content_digest, "content_digest")


@dataclass(frozen=True)
class RelationStatusCount:
    status: RelationStatus
    count: int

    def __post_init__(self) -> None:
        _validate_relation_status_count(self)


@dataclass(frozen=True)
class ReasonCount:
    reason: str
    count: int

    def __post_init__(self) -> None:
        _validate_reason_count(self)


@dataclass(frozen=True)
class CoverageFunnel:
    inputs_read: int
    questions_formed: int
    sites_considered: int
    sites_recognized: int
    transitions_materialized: int
    security_objects_constructed: int
    constraints_evaluated: int
    determinate_outcomes: int
    findings_emitted: int
    relation_status_counts: tuple[RelationStatusCount, ...]
    unresolved_by_reason: tuple[ReasonCount, ...]

    def __post_init__(self) -> None:
        _validate_funnel(self)


class CoverageStage(enum.Enum):
    INPUTS = "inputs"
    QUESTIONS = "questions"
    SITES_CONSIDERED = "sites_considered"
    SITES_RECOGNIZED = "sites_recognized"
    TRANSITIONS = "transitions"
    SECURITY_OBJECTS = "security_objects"
    CONSTRAINTS = "constraints"
    OUTCOMES = "outcomes"
    FINDINGS = "findings"


@dataclass(frozen=True)
class StageExpectation:
    stage: CoverageStage
    expected_nonzero_input: bool
    expected_nonzero_output: bool

    def __post_init__(self) -> None:
        _validate_stage_expectation(self)


@dataclass(frozen=True)
class StageDiagnosis:
    last_verified_nonzero_stage: CoverageStage | None
    first_failed_output_stage: CoverageStage | None
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.last_verified_nonzero_stage, "last_verified_nonzero_stage"),
            (self.first_failed_output_stage, "first_failed_output_stage"),
        ):
            if value is not None and not isinstance(value, CoverageStage):
                raise ValueError(f"{field_name} must be a CoverageStage or None")
        if not isinstance(self.reasons, tuple) or not all(isinstance(reason, str) and reason for reason in self.reasons):
            raise ValueError("reasons must be a tuple of nonempty text")


_COUNT_FIELDS = (
    "inputs_read",
    "questions_formed",
    "sites_considered",
    "sites_recognized",
    "transitions_materialized",
    "security_objects_constructed",
    "constraints_evaluated",
    "determinate_outcomes",
    "findings_emitted",
)


def _validate_relation_status_count(value: RelationStatusCount) -> None:
    if not isinstance(value.status, RelationStatus):
        raise ValueError("status must be a RelationStatus")
    _require_count(value.count, "relation status count")


def _validate_reason_count(value: ReasonCount) -> None:
    _require_text(value.reason, "reason")
    _require_count(value.count, "reason count")


def _validate_stage_expectation(value: StageExpectation) -> None:
    if not isinstance(value.stage, CoverageStage):
        raise ValueError("stage must be a CoverageStage")
    if not isinstance(value.expected_nonzero_input, bool):
        raise ValueError("expected_nonzero_input must be a boolean")
    if not isinstance(value.expected_nonzero_output, bool):
        raise ValueError("expected_nonzero_output must be a boolean")


def _validate_funnel(funnel: CoverageFunnel) -> None:
    for field_name in _COUNT_FIELDS:
        _require_count(getattr(funnel, field_name), field_name)
    _validate_stage_inequalities(funnel)
    if not isinstance(funnel.relation_status_counts, tuple):
        raise ValueError("relation_status_counts must be a tuple")
    if not all(isinstance(item, RelationStatusCount) for item in funnel.relation_status_counts):
        raise ValueError("relation_status_counts must contain RelationStatusCount values")
    for item in funnel.relation_status_counts:
        _validate_relation_status_count(item)
    statuses = tuple(item.status for item in funnel.relation_status_counts)
    if len(statuses) != len(set(statuses)):
        raise ValueError("duplicate relation status bucket")
    if set(statuses) != set(RelationStatus):
        raise ValueError("relation_status_counts must contain every relation status")
    if sum(item.count for item in funnel.relation_status_counts) != funnel.transitions_materialized:
        raise ValueError("relation status buckets must equal transitions_materialized")
    _validate_reason_counts(funnel)


def _validate_stage_inequalities(funnel: CoverageFunnel) -> None:
    inequalities = (
        (funnel.sites_recognized, funnel.sites_considered, "sites_recognized", "sites_considered"),
        (funnel.determinate_outcomes, funnel.questions_formed, "determinate_outcomes", "questions_formed"),
        (funnel.findings_emitted, funnel.determinate_outcomes, "findings_emitted", "determinate_outcomes"),
    )
    for downstream, upstream, downstream_name, upstream_name in inequalities:
        if downstream > upstream:
            raise ValueError(f"{downstream_name} cannot exceed {upstream_name}")


def _validate_reason_counts(funnel: CoverageFunnel) -> None:
    if not isinstance(funnel.unresolved_by_reason, tuple):
        raise ValueError("unresolved_by_reason must be a tuple")
    if not all(isinstance(item, ReasonCount) for item in funnel.unresolved_by_reason):
        raise ValueError("unresolved_by_reason must contain ReasonCount values")
    for item in funnel.unresolved_by_reason:
        _validate_reason_count(item)
        if item.count == 0:
            raise ValueError("unresolved reason count must be positive")
    reasons = tuple(item.reason for item in funnel.unresolved_by_reason)
    if len(reasons) != len(set(reasons)):
        raise ValueError("duplicate unresolved reason")
    unresolved = sum(item.count for item in funnel.relation_status_counts if item.status is not RelationStatus.COMPLETE)
    if sum(item.count for item in funnel.unresolved_by_reason) != unresolved:
        raise ValueError("reason counts must equal incomplete and unresolved relations")


def _validate_manifest(manifest: InputManifest) -> None:
    inputs = _validate_input_ids(manifest.tracked_input_ids)
    _require_digest(manifest.manifest_digest, "manifest digest")
    if manifest.manifest_digest != derive_input_manifest_digest(inputs):
        raise ValueError("manifest digest cannot be re-derived")


def _validate_receipt_shape(receipt: InputReadReceipt) -> None:
    _require_text(receipt.input_id, "input_id")
    _require_text(receipt.path, "path")
    if not isinstance(receipt.opened, bool):
        raise ValueError("opened must be a boolean")
    _require_count(receipt.byte_count, "byte_count")
    if receipt.content_digest is not None:
        _require_digest(receipt.content_digest, "content digest")


def validate_instrument(manifest: InputManifest, receipts: Sequence[InputReadReceipt]) -> None:
    """Refuse unread, zero-byte, missing, extra, or substituted tracked inputs."""
    try:
        if not isinstance(manifest, InputManifest):
            raise ValueError("manifest must be an InputManifest")
        _validate_manifest(manifest)
        if isinstance(receipts, (str, bytes)) or not isinstance(receipts, Sequence):
            raise ValueError("receipts must be a sequence")
        _validate_instrument_receipts(manifest, receipts)
    except InstrumentFailure:
        raise
    except (TypeError, ValueError) as exc:
        raise InstrumentFailure(str(exc)) from exc


def _validate_instrument_receipts(manifest: InputManifest, receipts: Sequence[InputReadReceipt]) -> None:
    by_id: dict[str, InputReadReceipt] = {}
    for receipt in receipts:
        if not isinstance(receipt, InputReadReceipt):
            raise InstrumentFailure("receipts must contain InputReadReceipt values")
        _validate_receipt_shape(receipt)
        if receipt.input_id in by_id:
            raise InstrumentFailure(f"duplicate input receipt: {receipt.input_id}")
        if receipt.input_id not in manifest.tracked_input_ids:
            raise InstrumentFailure(f"unexpected input receipt: {receipt.input_id}")
        by_id[receipt.input_id] = receipt
    missing = tuple(input_id for input_id in manifest.tracked_input_ids if input_id not in by_id)
    if missing:
        raise InstrumentFailure(f"missing input receipt: {', '.join(missing)}")
    for input_id in manifest.tracked_input_ids:
        receipt = by_id[input_id]
        if not receipt.opened:
            raise InstrumentFailure(f"tracked input not opened: {input_id} ({receipt.path})")
        if receipt.byte_count == 0:
            raise InstrumentFailure(f"zero-byte tracked input: {input_id} ({receipt.path})")
        if receipt.content_digest is None:
            raise InstrumentFailure(f"content digest missing for tracked input: {input_id}")


def _stage_counts(funnel: CoverageFunnel) -> dict[CoverageStage, int]:
    return dict(zip(CoverageStage, (getattr(funnel, field_name) for field_name in _COUNT_FIELDS), strict=True))


def _validate_expectations(expected: Sequence[StageExpectation]) -> tuple[StageExpectation, ...]:
    if isinstance(expected, (str, bytes)) or not isinstance(expected, Sequence):
        raise ValueError("expected must be a sequence")
    values = tuple(expected)
    if not all(isinstance(item, StageExpectation) for item in values):
        raise ValueError("expected must contain StageExpectation values")
    for item in values:
        _validate_stage_expectation(item)
    stages = tuple(item.stage for item in values)
    if len(stages) != len(set(stages)):
        raise ValueError("duplicate coverage stage expectation")
    if set(stages) != set(CoverageStage):
        raise ValueError("expectations must cover every coverage stage")
    if stages != tuple(CoverageStage):
        raise ValueError("expectations must use canonical coverage order")
    return values


def diagnose_first_zero(funnel: CoverageFunnel, expected: Sequence[StageExpectation]) -> StageDiagnosis:
    """Identify the first expected output that is zero without treating allowed zeros as failures."""
    if not isinstance(funnel, CoverageFunnel):
        raise ValueError("funnel must be a CoverageFunnel")
    _validate_funnel(funnel)
    expectations = _validate_expectations(expected)
    counts = _stage_counts(funnel)
    last_nonzero: CoverageStage | None = None
    previous_output: int | None = None
    for expectation in expectations:
        output = counts[expectation.stage]
        if expectation.expected_nonzero_input and (previous_output is None or previous_output == 0):
            reason = f"{expectation.stage.value}:expected_nonzero_input"
            return StageDiagnosis(last_nonzero, expectation.stage, (reason,))
        if expectation.expected_nonzero_output and output == 0:
            reason = f"{expectation.stage.value}:expected_nonzero_output"
            return StageDiagnosis(last_nonzero, expectation.stage, (reason,))
        if output > 0:
            last_nonzero = expectation.stage
        previous_output = output
    return StageDiagnosis(last_nonzero, None, ())


__all__ = [
    "CoverageFunnel",
    "CoverageStage",
    "InputManifest",
    "InputReadReceipt",
    "InstrumentFailure",
    "ReasonCount",
    "RelationStatusCount",
    "StageDiagnosis",
    "StageExpectation",
    "derive_input_manifest_digest",
    "diagnose_first_zero",
    "validate_instrument",
]
