"""Durable custodian-sealed checkpoints for isolated component observations."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from benchmarks.valid.arm_contract import RegisteredEvaluationPlanV1
from benchmarks.valid.artifact_repository import (
    ArtifactReadAuthority,
    ArtifactRepositoryError,
    ArtifactRepositoryReason,
    S3ArtifactRepository,
)
from benchmarks.valid.isolated_execution import ArmProcessOutcomeV1
from benchmarks.valid.isolated_execution_bundle import (
    LabelBlindExecutionBundleV1,
    label_blind_execution_bundle_bytes,
)
from benchmarks.valid.observation_receipt import (
    ExecutionDegradation,
    ExecutionReceiptError,
    ExecutionReceiptV1,
    InputReadReceiptV1,
    ReceiptReason,
    ReceiptStatus,
    StageExecutionReceiptV1,
    build_execution_receipt,
    execution_receipt_from_value,
    execution_receipt_value,
    validate_execution_receipt_for_bundle,
)
from benchmarks.valid.ordinary_change_contract import OrdinarySelectionV1
from benchmarks.valid.population_label_blind_contract import LabelBlindPopulationManifestV3
from benchmarks.valid.population_material_contract import PublicPopulationMaterialManifestV1
from benchmarks.valid.replacement_artifact_contract import (
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
    artifact_reference,
    canonical_artifact_bytes,
)
from openultrasast.core import canonical
from openultrasast.core.canonical import ContentResolver, JsonValue
from openultrasast.core.evaluation_measurement import ArmConfigurationV3, ArmKindV3
from openultrasast.core.evaluation_observation import (
    ArmObservationSetV3,
    EvaluationObservationError,
    decode_arm_observation_set,
    encode_arm_observation_set,
)
from openultrasast.core.evaluation_plan import ExpectedObservationSlotV3
from openultrasast.core.factpack import ReviewIndependencePolicy

CHECKPOINT_SCHEMA = "openultrasast.valid-detection-benchmark.component-observation-checkpoint.v1"
OBSERVATION_OUTPUT_SCHEMA = "openultrasast.valid-detection-benchmark.component-observation-output.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_CHECKPOINT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "checkpoint_digest",
        "plan_digest",
        "registration_digest",
        "arm_id",
        "bundle_digest",
        "budget_digest",
        "environment_digest",
        "input_set_digest",
        "output_destination_digest",
        "output_digest",
        "receipt_digest",
        "observation_set_digest",
        "execution_receipt",
        "observations",
    }
)


class CheckpointStatus(StrEnum):
    COMPLETE = "complete"
    IMPAIRED = "impaired"


class CheckpointReason(StrEnum):
    NONE = "none"
    BUNDLE_INVALID = "bundle_invalid"
    ADAPTER_FAILURE = "adapter_failure"
    CAPTURE_INVALID = "capture_invalid"
    RECEIPT_IMPAIRED = "receipt_impaired"
    RECEIPT_MISMATCH = "receipt_mismatch"
    OBSERVATION_INVALID = "observation_invalid"
    ARTIFACT_WRITE_FAILED = "artifact_write_failed"
    ARTIFACT_READBACK_FAILED = "artifact_readback_failed"
    CHECKPOINT_MISSING = "checkpoint_missing"
    CHECKPOINT_UNAVAILABLE = "checkpoint_unavailable"
    CHECKPOINT_MISMATCH = "checkpoint_mismatch"
    CHECKPOINT_INCOMPLETE = "checkpoint_incomplete"


class ObservationCheckpointError(ValueError):
    """Checkpoint contracts are malformed or do not bind exact execution."""


class _IncompleteCheckpointError(ObservationCheckpointError):
    """A structurally valid checkpoint contains an impaired execution receipt."""


def _digest(value: object, field: str, *, optional: bool = False) -> str:
    if optional and value == "":
        return ""
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ObservationCheckpointError(f"{field} must be a full lowercase SHA-256 digest")
    return value


@dataclass(frozen=True)
class ArmExecutionCaptureV1:
    process_outcome: ArmProcessOutcomeV1
    input_reads: tuple[InputReadReceiptV1, ...]
    stage_executions: tuple[StageExecutionReceiptV1, ...]
    degradations: tuple[ExecutionDegradation, ...]
    observations: tuple[ArmObservationSetV3, ...]

    def __post_init__(self) -> None:
        if type(self) is not ArmExecutionCaptureV1 or type(self.process_outcome) is not ArmProcessOutcomeV1:
            raise ObservationCheckpointError("capture must use exact execution contracts")
        self.process_outcome.__post_init__()
        if type(self.input_reads) is not tuple or any(type(row) is not InputReadReceiptV1 for row in self.input_reads):
            raise ObservationCheckpointError("capture input reads must use exact receipt values")
        if type(self.stage_executions) is not tuple or any(type(row) is not StageExecutionReceiptV1 for row in self.stage_executions):
            raise ObservationCheckpointError("capture stages must use exact receipt values")
        if type(self.degradations) is not tuple or any(type(row) is not ExecutionDegradation for row in self.degradations):
            raise ObservationCheckpointError("capture degradations must use exact closed values")
        if type(self.observations) is not tuple or any(type(row) is not ArmObservationSetV3 for row in self.observations):
            raise ObservationCheckpointError("capture observations must use exact core V3 values")


class ObservationCheckpointAdapter(Protocol):
    def execute(self, bundle: LabelBlindExecutionBundleV1) -> ArmExecutionCaptureV1: ...


@dataclass(frozen=True)
class CheckpointSelectorV1:
    reference: ArtifactReference
    checkpoint_digest: str

    def __post_init__(self) -> None:
        if type(self) is not CheckpointSelectorV1 or type(self.reference) is not ArtifactReference:
            raise ObservationCheckpointError("checkpoint selector must use exact reference contracts")
        self.reference.__post_init__()
        if self.reference.artifact_kind is not ArtifactKind.OBSERVATION:
            raise ObservationCheckpointError("checkpoint selector must reference an observation artifact")
        if self.reference.access_class is not ArtifactAccessClass.CUSTODIAN_SEALED:
            raise ObservationCheckpointError("checkpoint selector must reference custodian-sealed content")
        _digest(self.checkpoint_digest, "selected checkpoint")


@dataclass(frozen=True)
class ArmCheckpointResultV1:
    status: CheckpointStatus
    reason: CheckpointReason
    plan_digest: str
    arm_id: str
    checkpoint_digest: str
    reference: ArtifactReference | None
    result_digest: str

    def __post_init__(self) -> None:
        if (
            type(self) is not ArmCheckpointResultV1
            or type(self.status) is not CheckpointStatus
            or type(self.reason) is not CheckpointReason
        ):
            raise ObservationCheckpointError("checkpoint result must use exact closed contracts")
        _digest(self.plan_digest, "result plan")
        if type(self.arm_id) is not str or not self.arm_id:
            raise ObservationCheckpointError("result arm id must be nonempty")
        if self.status is CheckpointStatus.COMPLETE:
            if self.reason is not CheckpointReason.NONE or type(self.reference) is not ArtifactReference:
                raise ObservationCheckpointError("complete checkpoint result requires one exact reference")
            CheckpointSelectorV1(self.reference, self.checkpoint_digest)
        elif self.reason is CheckpointReason.NONE or self.reference is not None or self.checkpoint_digest:
            raise ObservationCheckpointError("impaired checkpoint result cannot claim complete content")
        expected = canonical.content_digest(_result_value(self, include_digest=False))
        if not self.result_digest:
            object.__setattr__(self, "result_digest", expected)
        elif _digest(self.result_digest, "checkpoint result") != expected:
            raise ObservationCheckpointError("checkpoint result digest does not match content")


def _reference_value(reference: ArtifactReference) -> dict[str, JsonValue]:
    return {
        "artifact_kind": reference.artifact_kind.value,
        "access_class": reference.access_class.value,
        "content_digest": reference.content_digest,
        "byte_length": reference.byte_length,
        "provenance_digest": reference.provenance_digest,
    }


def _result_value(value: ArmCheckpointResultV1, *, include_digest: bool) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "status": value.status.value,
        "reason": value.reason.value,
        "plan_digest": value.plan_digest,
        "arm_id": value.arm_id,
        "checkpoint_digest": value.checkpoint_digest or None,
        "reference": None if value.reference is None else _reference_value(value.reference),
    }
    if include_digest:
        result["result_digest"] = value.result_digest
    return result


def _impaired(bundle: LabelBlindExecutionBundleV1, reason: CheckpointReason) -> ArmCheckpointResultV1:
    return ArmCheckpointResultV1(CheckpointStatus.IMPAIRED, reason, bundle.plan_digest, bundle.arm.arm_id, "", None, "")


def component_observation_output_bytes(observations: tuple[ArmObservationSetV3, ...]) -> bytes:
    if type(observations) is not tuple or not observations or any(type(row) is not ArmObservationSetV3 for row in observations):
        raise ObservationCheckpointError("component output must contain nonempty exact core V3 observations")
    documents = tuple(encode_arm_observation_set(row).decode("utf-8") for row in observations)
    return canonical.canonical_bytes({"schema_version": OBSERVATION_OUTPUT_SCHEMA, "observations": documents})


def _expected_slots(
    plan: RegisteredEvaluationPlanV1,
    bundle: LabelBlindExecutionBundleV1,
) -> tuple[ExpectedObservationSlotV3, ...]:
    return tuple(row for row in plan.declaration.expected_observation_slots if row.arm_id == bundle.arm.arm_id)


def _configuration(plan: RegisteredEvaluationPlanV1, arm_id: str) -> ArmConfigurationV3:
    rows = tuple(row for row in plan.declaration.arm_configurations if row.arm_id == arm_id)
    if len(rows) != 1 or rows[0].kind is not ArmKindV3.COMPONENT:
        raise ObservationCheckpointError("checkpoint arm must resolve to one planned component")
    return rows[0]


def _validate_observations(
    plan: RegisteredEvaluationPlanV1,
    bundle: LabelBlindExecutionBundleV1,
    receipt: ExecutionReceiptV1,
    observations: tuple[ArmObservationSetV3, ...],
) -> str:
    slots = _expected_slots(plan, bundle)
    configuration = _configuration(plan, bundle.arm.arm_id)
    if tuple(row.slot_digest for row in observations) != tuple(row.slot_digest for row in slots):
        raise ObservationCheckpointError("observations do not equal every expected component slot")
    expected_inputs = tuple(row.input_identity_digest for row in bundle.case_inputs)
    if tuple(row.input_identity_digest for row in observations) != expected_inputs:
        raise ObservationCheckpointError("observations do not equal the ordered component input set")
    for slot, row in zip(slots, observations, strict=True):
        row.__post_init__()
        expected = (
            slot.arm_id,
            slot.input_identity_digest,
            slot.execution_identity,
            configuration.registered_budget_digest,
            configuration.configuration_identity_digest,
            receipt.input_read_evidence_digest,
            receipt.stage_execution_evidence_digest,
        )
        actual = (
            row.arm_id,
            row.input_identity_digest,
            row.execution_identity,
            row.registered_budget_digest,
            row.configuration_digest,
            row.input_read_evidence_digest,
            row.stage_execution_evidence_digest,
        )
        if actual != expected:
            raise ObservationCheckpointError("observation identity or instrument evidence differs from its planned slot")
        if any(case.outcome_projection.policy is not configuration.case_outcome_policy for case in row.cases):
            raise ObservationCheckpointError("observation outcome policy differs from the registered component")
    output = component_observation_output_bytes(observations)
    if canonical.bytes_digest(output) != receipt.output_digest or len(output) != receipt.output_bytes:
        raise ObservationCheckpointError("observation output identity differs from the execution receipt")
    return canonical.content_digest(
        {"schema_version": CHECKPOINT_SCHEMA, "observation_digests": tuple(row.observation_digest for row in observations)}
    )


def _checkpoint_identity(
    bundle: LabelBlindExecutionBundleV1,
    receipt: ExecutionReceiptV1,
    observation_set_digest: str,
) -> dict[str, JsonValue]:
    return {
        "schema_version": CHECKPOINT_SCHEMA,
        "plan_digest": bundle.plan_digest,
        "registration_digest": bundle.arm.registration_digest,
        "arm_id": bundle.arm.arm_id,
        "bundle_digest": bundle.bundle_digest,
        "budget_digest": bundle.budget.budget_digest,
        "environment_digest": bundle.environment.environment_digest,
        "input_set_digest": bundle.input_set_digest,
        "output_destination_digest": bundle.output_destination.destination_digest,
        "output_digest": receipt.output_digest,
        "receipt_digest": receipt.receipt_digest,
        "observation_set_digest": observation_set_digest,
    }


def _checkpoint_payload(
    bundle: LabelBlindExecutionBundleV1,
    receipt: ExecutionReceiptV1,
    observations: tuple[ArmObservationSetV3, ...],
    observation_set_digest: str,
) -> tuple[dict[str, JsonValue], str]:
    identity = _checkpoint_identity(bundle, receipt, observation_set_digest)
    checkpoint_digest = canonical.content_digest(identity)
    documents = tuple(encode_arm_observation_set(row).decode("utf-8") for row in observations)
    return (
        {
            **identity,
            "status": CheckpointStatus.COMPLETE.value,
            "checkpoint_digest": checkpoint_digest,
            "execution_receipt": execution_receipt_value(receipt),
            "observations": documents,
        },
        checkpoint_digest,
    )


def _freeze(
    plan: RegisteredEvaluationPlanV1,
    bundle: LabelBlindExecutionBundleV1,
    capture: ArmExecutionCaptureV1,
    repository: S3ArtifactRepository,
    authority: ArtifactReadAuthority,
    access_policy_digest: str,
) -> ArmCheckpointResultV1:
    try:
        receipt = build_execution_receipt(
            bundle, capture.process_outcome, capture.input_reads, capture.stage_executions, capture.degradations
        )
    except (ExecutionReceiptError, TypeError, ValueError):
        return _impaired(bundle, CheckpointReason.CAPTURE_INVALID)
    if receipt.status is not ReceiptStatus.COMPLETED:
        return _impaired(bundle, CheckpointReason.RECEIPT_IMPAIRED)
    try:
        validate_execution_receipt_for_bundle(bundle, receipt)
    except ExecutionReceiptError:
        return _impaired(bundle, CheckpointReason.RECEIPT_MISMATCH)
    try:
        observation_set_digest = _validate_observations(plan, bundle, receipt, capture.observations)
        payload, checkpoint_digest = _checkpoint_payload(bundle, receipt, capture.observations, observation_set_digest)
        content = canonical_artifact_bytes(
            ArtifactKind.OBSERVATION,
            payload,
            access_class=ArtifactAccessClass.CUSTODIAN_SEALED,
            provenance_digest=checkpoint_digest,
        )
        reference = artifact_reference(content)
    except (ObservationCheckpointError, EvaluationObservationError, TypeError, ValueError):
        return _impaired(bundle, CheckpointReason.OBSERVATION_INVALID)
    try:
        repository.put_if_absent(content, reference=reference)
    except ArtifactRepositoryError:
        return _impaired(bundle, CheckpointReason.ARTIFACT_WRITE_FAILED)
    try:
        accepted = repository.get(
            reference,
            expected_kind=ArtifactKind.OBSERVATION,
            authority=authority,
            expected_access_policy_digest=access_policy_digest,
        )
    except ArtifactRepositoryError:
        return _impaired(bundle, CheckpointReason.ARTIFACT_READBACK_FAILED)
    if accepted.content != content or accepted.reference != reference:
        return _impaired(bundle, CheckpointReason.ARTIFACT_READBACK_FAILED)
    return ArmCheckpointResultV1(
        CheckpointStatus.COMPLETE,
        CheckpointReason.NONE,
        bundle.plan_digest,
        bundle.arm.arm_id,
        checkpoint_digest,
        reference,
        "",
    )


def _decode_checkpoint(payload: object) -> tuple[dict[str, object], ExecutionReceiptV1, tuple[ArmObservationSetV3, ...]]:
    if (
        type(payload) is not dict
        or frozenset(payload) != _CHECKPOINT_FIELDS
        or payload.get("schema_version") != CHECKPOINT_SCHEMA
        or payload.get("status") != CheckpointStatus.COMPLETE.value
    ):
        raise ObservationCheckpointError("checkpoint is not complete")
    try:
        receipt = execution_receipt_from_value(payload["execution_receipt"])
        documents = cast(tuple[object, ...] | list[object], payload["observations"])
        observations = tuple(decode_arm_observation_set(cast(str, row).encode("utf-8")) for row in documents)
    except (KeyError, TypeError, ValueError, ExecutionReceiptError, EvaluationObservationError):
        raise ObservationCheckpointError("checkpoint content is malformed") from None
    if receipt.status is not ReceiptStatus.COMPLETED or receipt.reason is not ReceiptReason.NONE:
        raise _IncompleteCheckpointError("checkpoint execution receipt is impaired")
    return payload, receipt, observations


def _resume(
    plan: RegisteredEvaluationPlanV1,
    bundle: LabelBlindExecutionBundleV1,
    selector: CheckpointSelectorV1,
    repository: S3ArtifactRepository,
    authority: ArtifactReadAuthority,
    access_policy_digest: str,
) -> ArmCheckpointResultV1:
    try:
        accepted = repository.get(
            selector.reference,
            expected_kind=ArtifactKind.OBSERVATION,
            authority=authority,
            expected_access_policy_digest=access_policy_digest,
        )
    except ArtifactRepositoryError as error:
        reason = (
            CheckpointReason.CHECKPOINT_MISSING
            if error.reason is ArtifactRepositoryReason.NOT_FOUND
            else CheckpointReason.CHECKPOINT_UNAVAILABLE
        )
        return _impaired(bundle, reason)
    try:
        payload, receipt, observations = _decode_checkpoint(accepted.artifact.payload)
        validate_execution_receipt_for_bundle(bundle, receipt)
        observation_set_digest = _validate_observations(plan, bundle, receipt, observations)
        expected_identity = _checkpoint_identity(bundle, receipt, observation_set_digest)
        expected_digest = canonical.content_digest(expected_identity)
        if (
            selector.checkpoint_digest != expected_digest
            or selector.reference != accepted.reference
            or selector.reference.provenance_digest != expected_digest
            or payload.get("checkpoint_digest") != expected_digest
            or any(payload.get(key) != value for key, value in expected_identity.items())
        ):
            raise ObservationCheckpointError("checkpoint identity mismatch")
    except _IncompleteCheckpointError:
        return _impaired(bundle, CheckpointReason.CHECKPOINT_INCOMPLETE)
    except (ObservationCheckpointError, ExecutionReceiptError, EvaluationObservationError, TypeError, ValueError):
        return _impaired(bundle, CheckpointReason.CHECKPOINT_MISMATCH)
    return ArmCheckpointResultV1(
        CheckpointStatus.COMPLETE,
        CheckpointReason.NONE,
        bundle.plan_digest,
        bundle.arm.arm_id,
        selector.checkpoint_digest,
        selector.reference,
        "",
    )


def execute_or_resume_component(
    plan: RegisteredEvaluationPlanV1,
    bundle: LabelBlindExecutionBundleV1,
    adapter: ObservationCheckpointAdapter,
    repository: S3ArtifactRepository,
    authority: ArtifactReadAuthority,
    access_policy_digest: str,
    manifest: LabelBlindPopulationManifestV3,
    public_material_manifest: PublicPopulationMaterialManifestV1,
    selection: OrdinarySelectionV1,
    *,
    checkpoint: CheckpointSelectorV1 | None = None,
    strategy_review_policy: ReviewIndependencePolicy | None = None,
    strategy_resolver: ContentResolver | None = None,
) -> ArmCheckpointResultV1:
    """Execute once or resolve only the exact caller-selected completed checkpoint."""
    try:
        label_blind_execution_bundle_bytes(
            plan,
            bundle,
            manifest,
            public_material_manifest,
            selection,
            strategy_review_policy=strategy_review_policy,
            strategy_resolver=strategy_resolver,
        )
    except (TypeError, ValueError):
        return _impaired(bundle, CheckpointReason.BUNDLE_INVALID)
    if checkpoint is not None:
        try:
            checkpoint.__post_init__()
        except (TypeError, ValueError):
            return _impaired(bundle, CheckpointReason.CHECKPOINT_MISMATCH)
        return _resume(plan, bundle, checkpoint, repository, authority, access_policy_digest)
    try:
        capture = adapter.execute(bundle)
    except Exception:
        return _impaired(bundle, CheckpointReason.ADAPTER_FAILURE)
    if type(capture) is not ArmExecutionCaptureV1:
        return _impaired(bundle, CheckpointReason.CAPTURE_INVALID)
    try:
        capture.__post_init__()
    except (TypeError, ValueError):
        return _impaired(bundle, CheckpointReason.CAPTURE_INVALID)
    return _freeze(plan, bundle, capture, repository, authority, access_policy_digest)


__all__ = [
    "CHECKPOINT_SCHEMA",
    "OBSERVATION_OUTPUT_SCHEMA",
    "ArmCheckpointResultV1",
    "ArmExecutionCaptureV1",
    "CheckpointReason",
    "CheckpointSelectorV1",
    "CheckpointStatus",
    "ObservationCheckpointAdapter",
    "ObservationCheckpointError",
    "component_observation_output_bytes",
    "execute_or_resume_component",
]
