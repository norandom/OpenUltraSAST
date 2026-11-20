"""Closed pre-spend diagnostics and reviewed opening of sealed observations."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum

from benchmarks.valid.artifact_repository import (
    ArtifactActorRole,
    ArtifactReadAuthority,
    ArtifactReadPermission,
    ArtifactRepositoryError,
    S3ArtifactRepository,
)
from benchmarks.valid.isolated_execution_bundle import LabelBlindExecutionBundleV1
from benchmarks.valid.isolated_execution_contract import IsolatedExecutionError
from benchmarks.valid.lifecycle import (
    BaselineLifecycleAuthority,
    LifecycleError,
    PopulationLifecycleProjectionV1,
    PopulationLifecycleState,
    decode_lifecycle_event,
    reviewed_development_opening,
)
from benchmarks.valid.observation_checkpoint import (
    ArmCheckpointResultV1,
    CheckpointSelectorV1,
    CheckpointStatus,
    ObservationCheckpointError,
    _decode_checkpoint,
)
from benchmarks.valid.ordinary_change_contract import (
    OrdinarySelectionError,
    OrdinarySelectionV1,
    ordinary_selection_bytes,
)
from benchmarks.valid.population_label_blind_contract import (
    LabelBlindManifestError,
    LabelBlindPopulationManifestV3,
    label_blind_population_manifest_bytes,
)
from benchmarks.valid.replacement_artifact_contract import (
    AcceptedArtifact,
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
    artifact_reference,
    canonical_artifact_bytes,
    canonical_json_bytes,
)
from benchmarks.valid.reservation import (
    RepositoryIdentityResolver,
    ReservationAuthority,
    ReservationError,
    decode_influence_event,
)
from openultrasast.core import canonical
from openultrasast.core.canonical import JsonValue
from openultrasast.core.factpack import (
    FactPackValidationError,
    IndependenceAttestation,
    ReviewIndependencePolicy,
    derive_independence_attestation_digest,
    derive_review_independence_policy_digest,
)

PRE_SPEND_DIAGNOSTIC_SCHEMA = "openultrasast.valid-detection-benchmark.pre-spend-diagnostic.v1"
DEVELOPMENT_ACCESS_SCHEMA = "openultrasast.valid-detection-benchmark.development-access.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class DiagnosticStatus(StrEnum):
    COMPLETE = "complete"
    IMPAIRED = "impaired"


class DiagnosticReason(StrEnum):
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


class DiagnosticAccessReason(StrEnum):
    INVALID_REQUEST = "invalid_request"
    OBSERVATION_UNAVAILABLE = "observation_unavailable"
    REVIEW_REQUIRED = "review_required"
    LIFECYCLE_INELIGIBLE = "lifecycle_ineligible"
    AUTHORITY_PERSISTENCE_FAILED = "authority_persistence_failed"
    AUTHORITY_COMMIT_FAILED = "authority_commit_failed"
    AFFECTED_AUTHORITY_MISMATCH = "affected_authority_mismatch"


class SealedDiagnosticError(RuntimeError):
    """Closed access refusal with no provider or population diagnostic text."""

    def __init__(self, reason: DiagnosticAccessReason) -> None:
        self.reason = reason
        super().__init__(f"sealed_diagnostic_{reason.value}")


def _digest(value: object, field: str, *, optional: bool = False) -> str:
    del field
    if optional and value == "":
        return ""
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST)
    return value


def _count(value: object) -> int:
    if type(value) is not int or not 0 <= value <= 1 << 31:
        raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST)
    return value


@dataclass(frozen=True)
class PreSpendDiagnosticV1:
    status: DiagnosticStatus
    reason: DiagnosticReason
    plan_digest: str
    arm_digest: str
    checkpoint_digest: str
    receipt_digest: str
    input_evidence_digest: str
    stage_evidence_digest: str
    observation_set_digest: str
    output_digest: str
    input_count: int
    required_stage_count: int
    observation_count: int
    degradation_count: int
    runtime_ms: int
    projection_digest: str

    def __post_init__(self) -> None:
        if type(self) is not PreSpendDiagnosticV1 or type(self.status) is not DiagnosticStatus or type(self.reason) is not DiagnosticReason:
            raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST)
        _digest(self.plan_digest, "plan")
        _digest(self.arm_digest, "arm")
        for value, field in zip(_diagnostic_digests(self), range(6), strict=True):
            _digest(value, str(field), optional=True)
        counts = tuple(_count(value) for value in _diagnostic_counts(self))
        if self.status is DiagnosticStatus.COMPLETE:
            valid = self.reason is DiagnosticReason.NONE and all(counts[:3]) and all(_diagnostic_digests(self))
        else:
            valid = self.reason is not DiagnosticReason.NONE and not any(counts) and not any(_diagnostic_digests(self))
        if not valid:
            raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST)
        expected = canonical.content_digest(_diagnostic_value(self, include_digest=False))
        if not self.projection_digest:
            object.__setattr__(self, "projection_digest", expected)
        elif _digest(self.projection_digest, "projection") != expected:
            raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST)


def _diagnostic_digests(value: PreSpendDiagnosticV1) -> tuple[str, ...]:
    return (
        value.checkpoint_digest,
        value.receipt_digest,
        value.input_evidence_digest,
        value.stage_evidence_digest,
        value.observation_set_digest,
        value.output_digest,
    )


def _diagnostic_counts(value: PreSpendDiagnosticV1) -> tuple[int, ...]:
    return (value.input_count, value.required_stage_count, value.observation_count, value.degradation_count, value.runtime_ms)


def _diagnostic_value(value: PreSpendDiagnosticV1, *, include_digest: bool) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "schema_version": PRE_SPEND_DIAGNOSTIC_SCHEMA,
        "status": value.status.value,
        "reason": value.reason.value,
        "plan_digest": value.plan_digest,
        "arm_digest": value.arm_digest,
        "checkpoint_digest": value.checkpoint_digest or None,
        "receipt_digest": value.receipt_digest or None,
        "input_evidence_digest": value.input_evidence_digest or None,
        "stage_evidence_digest": value.stage_evidence_digest or None,
        "observation_set_digest": value.observation_set_digest or None,
        "output_digest": value.output_digest or None,
        "input_count": value.input_count,
        "required_stage_count": value.required_stage_count,
        "observation_count": value.observation_count,
        "degradation_count": value.degradation_count,
        "runtime_ms": value.runtime_ms,
    }
    if include_digest:
        result["projection_digest"] = value.projection_digest
    return result


def pre_spend_diagnostic_bytes(value: PreSpendDiagnosticV1) -> bytes:
    value.__post_init__()
    return canonical.canonical_bytes(_diagnostic_value(value, include_digest=True))


def _arm_digest(arm_id: str) -> str:
    if type(arm_id) is not str or not arm_id:
        raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST)
    return canonical.content_digest({"arm_id": arm_id})


def project_pre_spend_diagnostics(
    result: ArmCheckpointResultV1,
    repository: S3ArtifactRepository,
    authority: ArtifactReadAuthority,
    access_policy_digest: str,
) -> PreSpendDiagnosticV1:
    if type(result) is not ArmCheckpointResultV1:
        raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST)
    result.__post_init__()
    arm_digest = _arm_digest(result.arm_id)
    if result.status is CheckpointStatus.IMPAIRED:
        return PreSpendDiagnosticV1(
            DiagnosticStatus.IMPAIRED,
            DiagnosticReason(result.reason.value),
            result.plan_digest,
            arm_digest,
            "",
            "",
            "",
            "",
            "",
            "",
            0,
            0,
            0,
            0,
            0,
            "",
        )
    try:
        if result.reference is None:
            raise ObservationCheckpointError("complete result lacks reference")
        accepted = repository.get(
            result.reference,
            expected_kind=ArtifactKind.OBSERVATION,
            authority=authority,
            expected_access_policy_digest=access_policy_digest,
        )
        payload, receipt, observations = _decode_checkpoint(accepted.artifact.payload)
        if (
            accepted.reference != result.reference
            or payload.get("plan_digest") != result.plan_digest
            or payload.get("arm_id") != result.arm_id
            or payload.get("checkpoint_digest") != result.checkpoint_digest
            or result.reference.provenance_digest != result.checkpoint_digest
        ):
            raise ObservationCheckpointError("safe diagnostic identity mismatch")
        observation_set_digest = _digest(payload.get("observation_set_digest"), "observation set")
    except (ArtifactRepositoryError, ObservationCheckpointError, TypeError, ValueError):
        raise SealedDiagnosticError(DiagnosticAccessReason.OBSERVATION_UNAVAILABLE) from None
    return PreSpendDiagnosticV1(
        DiagnosticStatus.COMPLETE,
        DiagnosticReason.NONE,
        result.plan_digest,
        arm_digest,
        result.checkpoint_digest,
        receipt.receipt_digest,
        receipt.input_read_evidence_digest,
        receipt.stage_execution_evidence_digest,
        observation_set_digest,
        receipt.output_digest,
        len(receipt.input_reads),
        len(receipt.stage_executions),
        len(observations),
        len(receipt.degradations),
        receipt.runtime_ms,
        "",
    )


@dataclass(frozen=True, order=True)
class AffectedNetworkV1:
    canonical_repository: str
    network_identity_digest: str

    def __post_init__(self) -> None:
        if type(self) is not AffectedNetworkV1 or type(self.canonical_repository) is not str:
            raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST)
        if not self.canonical_repository or self.canonical_repository != self.canonical_repository.strip():
            raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST)
        _digest(self.network_identity_digest, "affected network")


@dataclass(frozen=True)
class DevelopmentAccessSubjectV1:
    population_digest: str
    freeze_digest: str
    predecessor_digest: str
    population_manifest_digest: str
    selection_digest: str
    affected_networks: tuple[AffectedNetworkV1, ...]
    plan_digest: str
    arm_digest: str
    checkpoint: CheckpointSelectorV1
    bundle: LabelBlindExecutionBundleV1
    artifact_access_policy_digest: str
    lifecycle_review_policy_digest: str
    subject_digest: str

    def __post_init__(self) -> None:
        _validate_access_subject_shape(self)
        _validate_access_subject_authority(self)
        expected = canonical.content_digest(_access_subject_value(self, include_digest=False))
        if not self.subject_digest:
            object.__setattr__(self, "subject_digest", expected)
        elif _digest(self.subject_digest, "access subject") != expected:
            raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST)


def _validate_access_subject_shape(value: DevelopmentAccessSubjectV1) -> None:
    if (
        type(value) is not DevelopmentAccessSubjectV1
        or type(value.checkpoint) is not CheckpointSelectorV1
        or type(value.bundle) is not LabelBlindExecutionBundleV1
        or type(value.affected_networks) is not tuple
        or not value.affected_networks
    ):
        raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST)
    value.checkpoint.__post_init__()
    try:
        value.bundle.__post_init__()
    except IsolatedExecutionError:
        raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST) from None
    if any(type(item) is not AffectedNetworkV1 for item in value.affected_networks):
        raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST)
    for item in value.affected_networks:
        item.__post_init__()
    if value.affected_networks != tuple(sorted(set(value.affected_networks))):
        raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST)


def _validate_access_subject_authority(value: DevelopmentAccessSubjectV1) -> None:
    for identity in (
        value.population_digest,
        value.freeze_digest,
        value.predecessor_digest,
        value.population_manifest_digest,
        value.selection_digest,
        value.plan_digest,
        value.arm_digest,
        value.bundle.bundle_digest,
        value.artifact_access_policy_digest,
        value.lifecycle_review_policy_digest,
    ):
        _digest(identity, "request identity")
    if (
        value.bundle.population_digest != value.population_digest
        or value.bundle.freeze_digest != value.freeze_digest
        or value.bundle.manifest_digest != value.population_manifest_digest
        or value.bundle.plan_digest != value.plan_digest
        or _arm_digest(value.bundle.arm.arm_id) != value.arm_digest
        or value.checkpoint.reference.provenance_digest != value.checkpoint.checkpoint_digest
    ):
        raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST)


def _reference_value(reference: ArtifactReference) -> dict[str, JsonValue]:
    return {
        "artifact_kind": reference.artifact_kind.value,
        "access_class": reference.access_class.value,
        "content_digest": reference.content_digest,
        "byte_length": reference.byte_length,
        "provenance_digest": reference.provenance_digest,
    }


def _access_subject_value(value: DevelopmentAccessSubjectV1, *, include_digest: bool) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "schema_version": DEVELOPMENT_ACCESS_SCHEMA,
        "population_digest": value.population_digest,
        "freeze_digest": value.freeze_digest,
        "predecessor_digest": value.predecessor_digest,
        "population_manifest_digest": value.population_manifest_digest,
        "selection_digest": value.selection_digest,
        "affected_networks": tuple(
            {
                "canonical_repository": item.canonical_repository,
                "network_identity_digest": item.network_identity_digest,
            }
            for item in value.affected_networks
        ),
        "plan_digest": value.plan_digest,
        "arm_digest": value.arm_digest,
        "checkpoint_digest": value.checkpoint.checkpoint_digest,
        "checkpoint_reference": _reference_value(value.checkpoint.reference),
        "bundle_digest": value.bundle.bundle_digest,
        "artifact_access_policy_digest": value.artifact_access_policy_digest,
        "lifecycle_review_policy_digest": value.lifecycle_review_policy_digest,
    }
    if include_digest:
        result["subject_digest"] = value.subject_digest
    return result


def _content_ref_value(value: canonical.ContentRef) -> dict[str, JsonValue]:
    return {
        "artifact_id": value.artifact_id,
        "content_digest": value.content_digest,
        "storage_receipt_digest": value.storage_receipt_digest,
        "retention_policy_digest": value.retention_policy_digest,
        "byte_length": value.byte_length,
        "media_type": value.media_type,
    }


def _review_value(value: IndependenceAttestation) -> dict[str, JsonValue]:
    return {
        "subject_digest": value.subject_digest,
        "producer_identity": value.producer_identity,
        "reviewer_identity": value.reviewer_identity,
        "conflict_disclosure": _content_ref_value(value.conflict_disclosure),
        "attestation_digest": value.attestation_digest,
    }


def _review_policy_value(value: ReviewIndependencePolicy) -> dict[str, JsonValue]:
    return {
        "reviewed_reviewer_digests": value.reviewed_reviewer_digests,
        "forbidden_identity_pairs": value.forbidden_identity_pairs,
        "trusted_store_identities": value.trusted_store_identities,
        "maximum_evidence_bytes": value.maximum_evidence_bytes,
        "policy_digest": value.policy_digest,
    }


@dataclass(frozen=True)
class DevelopmentAccessRequestV1:
    subject: DevelopmentAccessSubjectV1
    review: IndependenceAttestation
    review_policy: ReviewIndependencePolicy
    request_digest: str

    def __post_init__(self) -> None:
        if (
            type(self) is not DevelopmentAccessRequestV1
            or type(self.subject) is not DevelopmentAccessSubjectV1
            or type(self.review) is not IndependenceAttestation
            or type(self.review_policy) is not ReviewIndependencePolicy
        ):
            raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST)
        self.subject.__post_init__()
        try:
            self.review.__post_init__()
            self.review_policy.__post_init__()
        except (FactPackValidationError, TypeError, ValueError):
            raise SealedDiagnosticError(DiagnosticAccessReason.REVIEW_REQUIRED) from None
        expected = canonical.content_digest(_access_request_value(self, include_digest=False))
        if not self.request_digest or _digest(self.request_digest, "access request") != expected:
            raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST)


def _access_request_value(value: DevelopmentAccessRequestV1, *, include_digest: bool) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "schema_version": DEVELOPMENT_ACCESS_SCHEMA,
        "subject": _access_subject_value(value.subject, include_digest=True),
        "review": _review_value(value.review),
        "review_policy": _review_policy_value(value.review_policy),
    }
    if include_digest:
        result["request_digest"] = value.request_digest
    return result


def _validate_external_review(request: DevelopmentAccessRequestV1, resolver: canonical.ContentResolver) -> None:
    review = request.review
    policy = request.review_policy
    expected_policy = derive_review_independence_policy_digest(
        policy.reviewed_reviewer_digests,
        policy.forbidden_identity_pairs,
        policy.trusted_store_identities,
        policy.maximum_evidence_bytes,
    )
    valid = (
        policy.policy_digest == expected_policy == request.subject.lifecycle_review_policy_digest
        and review.subject_digest == request.subject.subject_digest
        and review.producer_identity != review.reviewer_identity
        and review.reviewer_identity in policy.reviewed_reviewer_digests
        and (review.producer_identity, review.reviewer_identity) not in policy.forbidden_identity_pairs
        and review.attestation_digest == derive_independence_attestation_digest(review)
    )
    if not valid:
        raise SealedDiagnosticError(DiagnosticAccessReason.REVIEW_REQUIRED)
    try:
        disclosure = canonical.resolve_content(
            review.conflict_disclosure,
            resolver,
            trusted_store_identities=policy.trusted_store_identities,
            maximum_bytes=policy.maximum_evidence_bytes,
        )
    except (AttributeError, LookupError, TypeError, ValueError):
        raise SealedDiagnosticError(DiagnosticAccessReason.REVIEW_REQUIRED) from None
    if not disclosure:
        raise SealedDiagnosticError(DiagnosticAccessReason.REVIEW_REQUIRED)


def _affected_networks(
    selection: OrdinarySelectionV1,
    resolver: RepositoryIdentityResolver,
    manifest: LabelBlindPopulationManifestV3,
    population_digest: str,
    freeze_digest: str,
) -> tuple[AffectedNetworkV1, ...]:
    if (
        type(selection) is not OrdinarySelectionV1
        or type(resolver) is not RepositoryIdentityResolver
        or type(manifest) is not LabelBlindPopulationManifestV3
    ):
        raise SealedDiagnosticError(DiagnosticAccessReason.AFFECTED_AUTHORITY_MISMATCH)
    try:
        ordinary_selection_bytes(selection)
        label_blind_population_manifest_bytes(manifest)
        if (
            manifest.population_digest != population_digest
            or manifest.freeze_digest != freeze_digest
            or manifest.ordinary_selection_digest != selection.selection_digest
        ):
            raise ReservationError("population authority binding changed")
        network_digests = {item.network_identity_digest for item in selection.fix_exclusions}
        network_digests.update(item.network_identity_digest for item in selection.pushes)
        rows = tuple(
            sorted(
                AffectedNetworkV1(
                    resolver.by_digest(digest).canonical_repository,
                    digest,
                )
                for digest in network_digests
            )
        )
        if not rows:
            raise ReservationError("population authority has no affected networks")
        for push in selection.pushes:
            network = resolver.resolve(push.canonical_repository)
            if network.network_identity_digest != push.network_identity_digest:
                raise ReservationError("population repository authority changed")
        return rows
    except (LabelBlindManifestError, OrdinarySelectionError, ReservationError, TypeError, ValueError):
        raise SealedDiagnosticError(DiagnosticAccessReason.AFFECTED_AUTHORITY_MISMATCH) from None


def build_development_access_subject(
    population_digest: str,
    freeze_digest: str,
    predecessor_digest: str,
    checkpoint: ArmCheckpointResultV1,
    *,
    bundle: LabelBlindExecutionBundleV1,
    selection: OrdinarySelectionV1,
    resolver: RepositoryIdentityResolver,
    manifest: LabelBlindPopulationManifestV3,
    artifact_access_policy_digest: str,
    lifecycle_review_policy_digest: str,
) -> DevelopmentAccessSubjectV1:
    if type(checkpoint) is not ArmCheckpointResultV1:
        raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST)
    checkpoint.__post_init__()
    if checkpoint.status is not CheckpointStatus.COMPLETE or checkpoint.reference is None:
        raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST)
    selector = CheckpointSelectorV1(checkpoint.reference, checkpoint.checkpoint_digest)
    arm_digest = _arm_digest(checkpoint.arm_id)
    subject = DevelopmentAccessSubjectV1(
        population_digest,
        freeze_digest,
        predecessor_digest,
        manifest.manifest_digest,
        selection.selection_digest,
        _affected_networks(selection, resolver, manifest, population_digest, freeze_digest),
        checkpoint.plan_digest,
        arm_digest,
        selector,
        bundle,
        artifact_access_policy_digest,
        lifecycle_review_policy_digest,
        "",
    )
    subject.__post_init__()
    return subject


def build_development_access_request(
    subject: DevelopmentAccessSubjectV1,
    review: IndependenceAttestation,
    review_policy: ReviewIndependencePolicy,
    review_resolver: canonical.ContentResolver,
) -> DevelopmentAccessRequestV1:
    if type(subject) is not DevelopmentAccessSubjectV1:
        raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST)
    subject.__post_init__()
    if type(review) is not IndependenceAttestation or type(review_policy) is not ReviewIndependencePolicy:
        raise SealedDiagnosticError(DiagnosticAccessReason.REVIEW_REQUIRED)
    try:
        review.__post_init__()
        review_policy.__post_init__()
    except (FactPackValidationError, TypeError, ValueError):
        raise SealedDiagnosticError(DiagnosticAccessReason.REVIEW_REQUIRED) from None
    draft = object.__new__(DevelopmentAccessRequestV1)
    object.__setattr__(draft, "subject", subject)
    object.__setattr__(draft, "review", review)
    object.__setattr__(draft, "review_policy", review_policy)
    object.__setattr__(draft, "request_digest", "")
    request_digest = canonical.content_digest(_access_request_value(draft, include_digest=False))
    request = DevelopmentAccessRequestV1(subject, review, review_policy, request_digest)
    _validate_external_review(request, review_resolver)
    return request


def persist_private_authority_event(
    kind: ArtifactKind,
    content: bytes,
    event_digest: str,
    repository: S3ArtifactRepository,
    authority: ArtifactReadAuthority,
    access_policy_digest: str,
) -> ArtifactReference:
    if kind not in {ArtifactKind.RESERVATION, ArtifactKind.LIFECYCLE}:
        raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST)
    try:
        payload = json.loads(content)
        if type(payload) is not dict or canonical_json_bytes(payload) != content:
            raise ValueError
        envelope = canonical_artifact_bytes(
            kind,
            payload,
            access_class=ArtifactAccessClass.PRIVATE,
            provenance_digest=_digest(event_digest, "authority event"),
        )
        reference = artifact_reference(envelope)
        repository.put_if_absent(envelope, reference=reference)
        accepted = repository.get(
            reference,
            expected_kind=kind,
            authority=authority,
            expected_access_policy_digest=access_policy_digest,
        )
        if accepted.content != envelope or accepted.reference != reference:
            raise ValueError
        return reference
    except (ArtifactRepositoryError, TypeError, ValueError, json.JSONDecodeError):
        raise SealedDiagnosticError(DiagnosticAccessReason.AUTHORITY_PERSISTENCE_FAILED) from None


@dataclass(frozen=True)
class DevelopmentObservationAccessV1:
    artifact: AcceptedArtifact
    lifecycle_projection: PopulationLifecycleProjectionV1
    lifecycle_reference: ArtifactReference
    influence_references: tuple[ArtifactReference, ...]
    request_digest: str
    access_digest: str

    def __post_init__(self) -> None:
        if (
            type(self) is not DevelopmentObservationAccessV1
            or type(self.artifact) is not AcceptedArtifact
            or type(self.lifecycle_projection) is not PopulationLifecycleProjectionV1
            or type(self.lifecycle_reference) is not ArtifactReference
            or type(self.influence_references) is not tuple
        ):
            raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST)
        if (
            self.artifact.reference.artifact_kind is not ArtifactKind.OBSERVATION
            or self.artifact.reference.access_class is not ArtifactAccessClass.CUSTODIAN_SEALED
            or self.lifecycle_projection.state is not PopulationLifecycleState.DEVELOPMENT_OPENED
            or self.lifecycle_projection.admission_eligible
            or self.lifecycle_reference.artifact_kind is not ArtifactKind.LIFECYCLE
            or self.lifecycle_reference.access_class is not ArtifactAccessClass.PRIVATE
            or self.lifecycle_reference.provenance_digest != self.lifecycle_projection.head_event_digest
            or not self.influence_references
            or tuple(item.provenance_digest for item in self.influence_references) != self.lifecycle_projection.influence_event_digests
            or any(
                item.artifact_kind is not ArtifactKind.RESERVATION or item.access_class is not ArtifactAccessClass.PRIVATE
                for item in self.influence_references
            )
        ):
            raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST)
        _digest(self.request_digest, "access request")
        expected = canonical.content_digest(_opened_access_value(self))
        if not self.access_digest:
            object.__setattr__(self, "access_digest", expected)
        elif _digest(self.access_digest, "opened access") != expected:
            raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST)


def _opened_access_value(value: DevelopmentObservationAccessV1) -> dict[str, JsonValue]:
    return {
        "request_digest": value.request_digest,
        "lifecycle_projection_digest": value.lifecycle_projection.projection_digest,
        "lifecycle_reference": _reference_value(value.lifecycle_reference),
        "influence_references": tuple(_reference_value(item) for item in value.influence_references),
        "observation_reference": _reference_value(value.artifact.reference),
    }


def _read_requested_observation(
    request: DevelopmentAccessRequestV1,
    repository: S3ArtifactRepository,
    authority: ArtifactReadAuthority,
    policy_digest: str,
) -> AcceptedArtifact:
    try:
        accepted = repository.get(
            request.subject.checkpoint.reference,
            expected_kind=ArtifactKind.OBSERVATION,
            authority=authority,
            expected_access_policy_digest=policy_digest,
        )
        payload, _, _ = _decode_checkpoint(accepted.artifact.payload)
        if (
            accepted.reference != request.subject.checkpoint.reference
            or accepted.reference.provenance_digest != request.subject.checkpoint.checkpoint_digest
            or payload.get("checkpoint_digest") != request.subject.checkpoint.checkpoint_digest
            or payload.get("plan_digest") != request.subject.plan_digest
            or _arm_digest(str(payload.get("arm_id"))) != request.subject.arm_digest
            or payload.get("bundle_digest") != request.subject.bundle.bundle_digest
        ):
            raise ObservationCheckpointError("development access identity mismatch")
        return accepted
    except (ArtifactRepositoryError, ObservationCheckpointError, TypeError, ValueError):
        raise SealedDiagnosticError(DiagnosticAccessReason.OBSERVATION_UNAVAILABLE) from None


def _validate_artifact_read_authority(request: DevelopmentAccessRequestV1, authority: ArtifactReadAuthority) -> None:
    if (
        type(authority) is not ArtifactReadAuthority
        or type(authority.actor_role) is not ArtifactActorRole
        or type(authority.permissions) is not tuple
        or any(type(item) is not ArtifactReadPermission for item in authority.permissions)
    ):
        raise SealedDiagnosticError(DiagnosticAccessReason.OBSERVATION_UNAVAILABLE)
    permissions = tuple(sorted(set(authority.permissions), key=lambda item: item.value))
    required = {ArtifactReadPermission.CUSTODIAN_SEALED, ArtifactReadPermission.PRIVATE}
    value = {
        "actor_role": authority.actor_role.value,
        "permissions": tuple(item.value for item in authority.permissions),
        "policy_digest": authority.policy_digest,
    }
    if (
        authority.actor_role is not ArtifactActorRole.CUSTODIAN
        or authority.permissions != permissions
        or not required.issubset(authority.permissions)
        or authority.policy_digest != request.subject.artifact_access_policy_digest
        or authority.authority_digest != canonical.content_digest(value)
    ):
        raise SealedDiagnosticError(DiagnosticAccessReason.OBSERVATION_UNAVAILABLE)


def open_observation_for_development(
    request: DevelopmentAccessRequestV1,
    *,
    repository: S3ArtifactRepository,
    artifact_authority: ArtifactReadAuthority,
    lifecycle_authority: BaselineLifecycleAuthority,
    reservation_authority: ReservationAuthority,
    resolver: RepositoryIdentityResolver,
    selection: OrdinarySelectionV1,
    manifest: LabelBlindPopulationManifestV3,
    review_resolver: canonical.ContentResolver,
) -> DevelopmentObservationAccessV1:
    try:
        request.__post_init__()
    except (AttributeError, SealedDiagnosticError, TypeError, ValueError):
        raise SealedDiagnosticError(DiagnosticAccessReason.INVALID_REQUEST) from None
    _validate_external_review(request, review_resolver)
    _validate_artifact_read_authority(request, artifact_authority)
    try:
        active = lifecycle_authority.require_admission_eligible(request.subject.population_digest, request.subject.freeze_digest)
        if active.head_event_digest != request.subject.predecessor_digest:
            raise LifecycleError("development opening predecessor changed")
    except (AttributeError, LifecycleError, SealedDiagnosticError, TypeError, ValueError):
        raise SealedDiagnosticError(DiagnosticAccessReason.LIFECYCLE_INELIGIBLE) from None
    affected_networks = _affected_networks(
        selection,
        resolver,
        manifest,
        request.subject.population_digest,
        request.subject.freeze_digest,
    )
    if (
        manifest.manifest_digest != request.subject.population_manifest_digest
        or selection.selection_digest != request.subject.selection_digest
        or affected_networks != request.subject.affected_networks
    ):
        raise SealedDiagnosticError(DiagnosticAccessReason.AFFECTED_AUTHORITY_MISMATCH)
    try:
        opening = reviewed_development_opening(
            predecessor_digest=request.subject.predecessor_digest,
            population_digest=request.subject.population_digest,
            freeze_digest=request.subject.freeze_digest,
            access_evidence_digest=request.review.attestation_digest,
            resolver=resolver,
            repositories=tuple(item.canonical_repository for item in affected_networks),
            producer_identity=request.review.producer_identity,
            reviewer_identity=request.review.reviewer_identity,
            conflict_disclosed=True,
            policy_digest=request.review_policy.policy_digest,
        )
    except (LifecycleError, ReservationError, TypeError, ValueError):
        raise SealedDiagnosticError(DiagnosticAccessReason.REVIEW_REQUIRED) from None
    influence_events = tuple(decode_influence_event(content) for content in opening.influence_contents)
    lifecycle_event = decode_lifecycle_event(opening.event_content)
    influence_references = tuple(
        persist_private_authority_event(
            ArtifactKind.RESERVATION,
            content,
            event.event_digest,
            repository,
            artifact_authority,
            request.subject.artifact_access_policy_digest,
        )
        for content, event in zip(opening.influence_contents, influence_events, strict=True)
    )
    lifecycle_reference = persist_private_authority_event(
        ArtifactKind.LIFECYCLE,
        opening.event_content,
        lifecycle_event.event_digest,
        repository,
        artifact_authority,
        request.subject.artifact_access_policy_digest,
    )
    try:
        for content in opening.influence_contents:
            reservation_authority.append_influence(content)
        census = reservation_authority.current_census()
        projection = lifecycle_authority.append(opening.event_content)
        expected_influences = tuple(event.event_digest for event in influence_events)
        expected_networks = {event.network_identity_digest for event in influence_events}
        requested_networks = {item.network_identity_digest for item in affected_networks}
        if (
            not set(expected_influences).issubset(census.accepted_event_digests)
            or expected_networks != requested_networks
            or not requested_networks.issubset(census.reserved_network_digests)
            or projection.state is not PopulationLifecycleState.DEVELOPMENT_OPENED
            or projection.admission_eligible
            or projection.influence_event_digests != expected_influences
        ):
            raise LifecycleError("development authorities did not commit exact opening")
    except (LifecycleError, ReservationError, TypeError, ValueError):
        raise SealedDiagnosticError(DiagnosticAccessReason.AUTHORITY_COMMIT_FAILED) from None
    artifact = _read_requested_observation(
        request,
        repository,
        artifact_authority,
        request.subject.artifact_access_policy_digest,
    )
    return DevelopmentObservationAccessV1(
        artifact,
        projection,
        lifecycle_reference,
        influence_references,
        request.request_digest,
        "",
    )


__all__ = [
    "DEVELOPMENT_ACCESS_SCHEMA",
    "PRE_SPEND_DIAGNOSTIC_SCHEMA",
    "AffectedNetworkV1",
    "DevelopmentAccessRequestV1",
    "DevelopmentAccessSubjectV1",
    "DevelopmentObservationAccessV1",
    "DiagnosticAccessReason",
    "DiagnosticReason",
    "DiagnosticStatus",
    "PreSpendDiagnosticV1",
    "SealedDiagnosticError",
    "build_development_access_request",
    "build_development_access_subject",
    "open_observation_for_development",
    "pre_spend_diagnostic_bytes",
    "project_pre_spend_diagnostics",
]
