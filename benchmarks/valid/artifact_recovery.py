"""Exact recovery of ordered durable authority projections."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from benchmarks.valid.artifact_repository import (
    ArtifactReadAuthority,
    ArtifactRepositoryError,
    ArtifactRepositoryReason,
    S3ArtifactRepository,
)
from benchmarks.valid.replacement_artifact_contract import (
    AcceptedArtifact,
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
    artifact_reference,
    canonical_artifact_bytes,
)
from openultrasast.core.canonical import JsonValue, content_digest

PROJECTION_ROOT_SCHEMA = "openultrasast.valid-detection-benchmark.durable-projection-root.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_ROOT_KEYS = frozenset(
    {
        "schema_version",
        "family",
        "authority_digest",
        "expires_at_epoch",
        "member_count",
        "member_references",
        "ordered_member_digest",
    }
)


class ProjectionFamily(StrEnum):
    RESERVATION = "reservation"
    LIFECYCLE = "lifecycle"
    POPULATION = "population"
    OBSERVATION = "observation"
    WORKFLOW = "workflow"
    REPLAY = "replay"
    REPORT = "report"


class ArtifactRecoveryReason(StrEnum):
    INVALID_ROOT = "invalid_root"
    MISSING_ROOT = "missing_root"
    MISSING_MEMBER = "missing_member"
    INVALID_MEMBER = "invalid_member"
    WRONG_VERSION = "wrong_version"
    EXPIRED_AUTHORITY = "expired_authority"
    AUTHORITY_MISMATCH = "authority_mismatch"


class ArtifactRecoveryError(RuntimeError):
    def __init__(self, reason: ArtifactRecoveryReason) -> None:
        self.reason = reason
        super().__init__(f"artifact_recovery_{reason.value}")


@dataclass(frozen=True)
class DurableProjectionRootV1:
    schema_version: str
    family: ProjectionFamily
    authority_digest: str
    expires_at_epoch: int | None
    member_count: int
    member_references: tuple[ArtifactReference, ...]
    ordered_member_digest: str


@dataclass(frozen=True)
class RecoveredDurableProjectionV1:
    root: DurableProjectionRootV1
    root_reference: ArtifactReference
    members: tuple[AcceptedArtifact, ...]
    decision_digest: str


_KIND_BY_FAMILY = {
    ProjectionFamily.RESERVATION: ArtifactKind.RESERVATION,
    ProjectionFamily.LIFECYCLE: ArtifactKind.LIFECYCLE,
    ProjectionFamily.POPULATION: ArtifactKind.POPULATION,
    ProjectionFamily.OBSERVATION: ArtifactKind.OBSERVATION,
    ProjectionFamily.WORKFLOW: ArtifactKind.WORKFLOW,
    ProjectionFamily.REPLAY: ArtifactKind.REPLAY,
    ProjectionFamily.REPORT: ArtifactKind.REPORT,
}
_ACCESS_BY_FAMILY = {
    ProjectionFamily.RESERVATION: ArtifactAccessClass.PRIVATE,
    ProjectionFamily.LIFECYCLE: ArtifactAccessClass.PRIVATE,
    ProjectionFamily.POPULATION: ArtifactAccessClass.PRIVATE,
    ProjectionFamily.OBSERVATION: ArtifactAccessClass.CUSTODIAN_SEALED,
    ProjectionFamily.WORKFLOW: ArtifactAccessClass.OPERATOR_SAFE,
    ProjectionFamily.REPLAY: ArtifactAccessClass.OPERATOR_SAFE,
    ProjectionFamily.REPORT: ArtifactAccessClass.OPERATOR_SAFE,
}
_MEMBER_ACCESS_BY_FAMILY = {
    ProjectionFamily.RESERVATION: frozenset({ArtifactAccessClass.PRIVATE}),
    ProjectionFamily.LIFECYCLE: frozenset({ArtifactAccessClass.PRIVATE}),
    ProjectionFamily.POPULATION: frozenset(
        {
            ArtifactAccessClass.PUBLIC,
            ArtifactAccessClass.PRIVATE,
            ArtifactAccessClass.CUSTODIAN_SEALED,
        }
    ),
    ProjectionFamily.OBSERVATION: frozenset({ArtifactAccessClass.CUSTODIAN_SEALED}),
    ProjectionFamily.WORKFLOW: frozenset({ArtifactAccessClass.OPERATOR_SAFE}),
    ProjectionFamily.REPLAY: frozenset({ArtifactAccessClass.OPERATOR_SAFE}),
    ProjectionFamily.REPORT: frozenset({ArtifactAccessClass.OPERATOR_SAFE}),
}


def _digest(value: object) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT)
    return value


def _optional_expiry(value: object) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value <= 0:
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT)
    return value


def projection_kind(family: ProjectionFamily | str) -> ArtifactKind:
    try:
        return _KIND_BY_FAMILY[ProjectionFamily(family)]
    except (TypeError, ValueError, KeyError):
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT) from None


def projection_access(family: ProjectionFamily | str) -> ArtifactAccessClass:
    try:
        return _ACCESS_BY_FAMILY[ProjectionFamily(family)]
    except (TypeError, ValueError, KeyError):
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT) from None


def _reference_value(reference: ArtifactReference) -> dict[str, JsonValue]:
    if type(reference) is not ArtifactReference:
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT)
    return {
        "artifact_kind": reference.artifact_kind.value,
        "access_class": reference.access_class.value,
        "provenance_digest": reference.provenance_digest,
        "content_digest": reference.content_digest,
        "byte_length": reference.byte_length,
    }


def _ordered_digest(references: tuple[ArtifactReference, ...]) -> str:
    rows: tuple[JsonValue, ...] = tuple(
        {"sequence_index": index, "reference": _reference_value(reference)} for index, reference in enumerate(references)
    )
    return content_digest({"ordered_members": rows})


def _validate_root(root: DurableProjectionRootV1) -> None:
    if type(root) is not DurableProjectionRootV1:
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT)
    if root.schema_version != PROJECTION_ROOT_SCHEMA:
        raise ArtifactRecoveryError(ArtifactRecoveryReason.WRONG_VERSION)
    try:
        family = ProjectionFamily(root.family)
    except (TypeError, ValueError):
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT) from None
    _digest(root.authority_digest)
    _optional_expiry(root.expires_at_epoch)
    if type(root.member_count) is not int or root.member_count <= 0:
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT)
    if type(root.member_references) is not tuple or len(root.member_references) != root.member_count:
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT)
    if any(type(reference) is not ArtifactReference for reference in root.member_references):
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT)
    identities = tuple(reference.content_digest for reference in root.member_references)
    if len(set(identities)) != len(identities):
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT)
    expected_kind = projection_kind(family)
    allowed_access = _MEMBER_ACCESS_BY_FAMILY[family]
    if any(
        reference.artifact_kind is not expected_kind or reference.access_class not in allowed_access for reference in root.member_references
    ):
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT)
    if _digest(root.ordered_member_digest) != _ordered_digest(root.member_references):
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT)


def _root_payload(root: DurableProjectionRootV1) -> dict[str, JsonValue]:
    _validate_root(root)
    return {
        "schema_version": root.schema_version,
        "family": root.family.value,
        "authority_digest": root.authority_digest,
        "expires_at_epoch": root.expires_at_epoch,
        "member_count": root.member_count,
        "member_references": tuple(_reference_value(reference) for reference in root.member_references),
        "ordered_member_digest": root.ordered_member_digest,
    }


def canonical_projection_root_artifact(root: DurableProjectionRootV1) -> tuple[bytes, ArtifactReference]:
    payload = _root_payload(root)
    content = canonical_artifact_bytes(
        projection_kind(root.family),
        payload,
        access_class=projection_access(root.family),
        provenance_digest=root.authority_digest,
    )
    return content, artifact_reference(content)


def build_durable_projection_root(
    family: ProjectionFamily | str,
    member_references: tuple[ArtifactReference, ...],
    *,
    authority_digest: str,
    expires_at_epoch: int | None,
) -> tuple[DurableProjectionRootV1, bytes, ArtifactReference]:
    try:
        normalized = ProjectionFamily(family)
    except (TypeError, ValueError):
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT) from None
    root = DurableProjectionRootV1(
        PROJECTION_ROOT_SCHEMA,
        normalized,
        _digest(authority_digest),
        _optional_expiry(expires_at_epoch),
        len(member_references),
        member_references,
        _ordered_digest(member_references),
    )
    content, reference = canonical_projection_root_artifact(root)
    return root, content, reference


def _reference_from_value(value: object) -> ArtifactReference:
    if not isinstance(value, dict) or set(value) != {
        "artifact_kind",
        "access_class",
        "provenance_digest",
        "content_digest",
        "byte_length",
    }:
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT)
    try:
        return ArtifactReference(
            ArtifactKind(cast(str, value["artifact_kind"])),
            cast(str, value["content_digest"]),
            cast(int, value["byte_length"]),
            cast(str, value["provenance_digest"]),
            ArtifactAccessClass(cast(str, value["access_class"])),
        )
    except (TypeError, ValueError):
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT) from None


def _root_from_payload(payload: object) -> DurableProjectionRootV1:
    if not isinstance(payload, dict) or set(payload) != _ROOT_KEYS:
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT)
    members_value = payload["member_references"]
    if not isinstance(members_value, tuple):
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT)
    members = tuple(_reference_from_value(value) for value in members_value)
    try:
        family = ProjectionFamily(payload["family"])
    except (TypeError, ValueError):
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT) from None
    root = DurableProjectionRootV1(
        cast(str, payload["schema_version"]),
        family,
        cast(str, payload["authority_digest"]),
        cast(int | None, payload["expires_at_epoch"]),
        cast(int, payload["member_count"]),
        members,
        cast(str, payload["ordered_member_digest"]),
    )
    _validate_root(root)
    return root


def _read_root(
    repository: S3ArtifactRepository,
    reference: ArtifactReference,
    family: ProjectionFamily,
    authority: ArtifactReadAuthority,
    expected_policy: str,
) -> DurableProjectionRootV1:
    reason: ArtifactRecoveryReason | None = None
    try:
        accepted = repository.get(
            reference,
            expected_kind=projection_kind(family),
            authority=authority,
            expected_access_policy_digest=expected_policy,
        )
    except ArtifactRepositoryError as error:
        reason = (
            ArtifactRecoveryReason.MISSING_ROOT
            if error.reason is ArtifactRepositoryReason.NOT_FOUND
            else ArtifactRecoveryReason.INVALID_ROOT
        )
        accepted = None
    if reason is not None or accepted is None:
        raise ArtifactRecoveryError(reason or ArtifactRecoveryReason.INVALID_ROOT)
    root = _root_from_payload(dict(accepted.artifact.payload))
    canonical_content, canonical_reference = canonical_projection_root_artifact(root)
    if accepted.content != canonical_content or accepted.reference != canonical_reference or accepted.reference != reference:
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT)
    return root


def _read_members(
    repository: S3ArtifactRepository,
    root: DurableProjectionRootV1,
    authority: ArtifactReadAuthority,
    expected_policy: str,
) -> tuple[AcceptedArtifact, ...]:
    members: list[AcceptedArtifact] = []
    for reference in root.member_references:
        reason: ArtifactRecoveryReason | None = None
        try:
            accepted = repository.get(
                reference,
                expected_kind=projection_kind(root.family),
                authority=authority,
                expected_access_policy_digest=expected_policy,
            )
        except ArtifactRepositoryError as error:
            reason = (
                ArtifactRecoveryReason.MISSING_MEMBER
                if error.reason is ArtifactRepositoryReason.NOT_FOUND
                else ArtifactRecoveryReason.INVALID_MEMBER
            )
            accepted = None
        if reason is not None or accepted is None:
            raise ArtifactRecoveryError(reason or ArtifactRecoveryReason.INVALID_MEMBER)
        members.append(accepted)
    return tuple(members)


def projection_decision_digest(
    root: DurableProjectionRootV1,
    members: tuple[AcceptedArtifact, ...],
) -> str:
    _validate_root(root)
    if type(members) is not tuple or any(type(item) is not AcceptedArtifact for item in members):
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_MEMBER)
    if tuple(item.reference for item in members) != root.member_references:
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_MEMBER)
    return content_digest(
        {
            "root": _root_payload(root),
            "member_payload_digests": tuple(item.artifact.payload_digest for item in members),
        }
    )


def recover_durable_projection(
    repository: S3ArtifactRepository,
    *,
    expected_family: ProjectionFamily | str,
    root_reference: ArtifactReference,
    authority: ArtifactReadAuthority,
    expected_access_policy_digest: str,
    expected_authority_digest: str,
    current_epoch: int,
) -> RecoveredDurableProjectionV1:
    try:
        family = ProjectionFamily(expected_family)
    except (TypeError, ValueError):
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT) from None
    if type(root_reference) is not ArtifactReference:
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT)
    if root_reference.artifact_kind is not projection_kind(family) or root_reference.access_class is not projection_access(family):
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT)
    root = _read_root(repository, root_reference, family, authority, expected_access_policy_digest)
    if root.family is not family:
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT)
    if root.authority_digest != _digest(expected_authority_digest):
        raise ArtifactRecoveryError(ArtifactRecoveryReason.AUTHORITY_MISMATCH)
    if type(current_epoch) is not int or current_epoch < 0:
        raise ArtifactRecoveryError(ArtifactRecoveryReason.INVALID_ROOT)
    if root.expires_at_epoch is not None and current_epoch >= root.expires_at_epoch:
        raise ArtifactRecoveryError(ArtifactRecoveryReason.EXPIRED_AUTHORITY)
    members = _read_members(repository, root, authority, expected_access_policy_digest)
    return RecoveredDurableProjectionV1(root, root_reference, members, projection_decision_digest(root, members))


def list_durable_projection(
    repository: S3ArtifactRepository,
    *,
    expected_family: ProjectionFamily | str,
    root_reference: ArtifactReference,
    authority: ArtifactReadAuthority,
    expected_access_policy_digest: str,
    expected_authority_digest: str,
    current_epoch: int,
) -> tuple[ArtifactReference, ...]:
    """List only the members of one exact caller-selected durable root."""
    result = recover_durable_projection(
        repository,
        expected_family=expected_family,
        root_reference=root_reference,
        authority=authority,
        expected_access_policy_digest=expected_access_policy_digest,
        expected_authority_digest=expected_authority_digest,
        current_epoch=current_epoch,
    )
    return result.root.member_references


__all__ = [
    "ArtifactRecoveryError",
    "ArtifactRecoveryReason",
    "DurableProjectionRootV1",
    "PROJECTION_ROOT_SCHEMA",
    "ProjectionFamily",
    "RecoveredDurableProjectionV1",
    "build_durable_projection_root",
    "canonical_projection_root_artifact",
    "list_durable_projection",
    "projection_access",
    "projection_decision_digest",
    "projection_kind",
    "recover_durable_projection",
]
