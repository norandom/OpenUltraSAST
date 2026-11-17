"""Create-only S3 persistence for replacement benchmark artifacts."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Protocol, cast

from benchmarks.valid.replacement_artifact_contract import (
    AcceptedArtifact,
    ArtifactAccessClass,
    ArtifactContractError,
    ArtifactKind,
    ArtifactReference,
    accept_artifact,
)
from benchmarks.valid.store_configuration import StorePurpose, StoreSettings
from openultrasast.core.canonical import JsonValue, content_digest


class ArtifactRepositoryReason(StrEnum):
    INVALID_REQUEST = "invalid_request"
    NOT_AUTHORIZED = "not_authorized"
    POLICY_MISMATCH = "policy_mismatch"
    NOT_FOUND = "not_found"
    EMPTY_OBJECT = "empty_object"
    INVALID_OBJECT = "invalid_object"
    IDENTITY_CONFLICT = "identity_conflict"
    STORE_FAILURE = "store_failure"
    DEPENDENCY_MISSING = "dependency_missing"


class ArtifactRepositoryError(RuntimeError):
    """Closed repository failure that never includes provider or artifact bytes."""

    def __init__(self, reason: ArtifactRepositoryReason) -> None:
        self.reason = reason
        super().__init__(f"artifact_repository_{reason.value}")


class ArtifactRepositoryConflict(ArtifactRepositoryError):
    def __init__(self) -> None:
        super().__init__(ArtifactRepositoryReason.IDENTITY_CONFLICT)


class ArtifactActorRole(StrEnum):
    CUSTODIAN = "custodian"
    DETECTOR = "detector"
    PRESENTER = "presenter"
    OPERATOR = "operator"


class ArtifactReadPermission(StrEnum):
    PRIVATE = "private"
    CUSTODIAN_SEALED = "custodian_sealed"


@dataclass(frozen=True)
class ArtifactReadAuthority:
    actor_role: ArtifactActorRole
    permissions: tuple[ArtifactReadPermission, ...]
    policy_digest: str
    authority_digest: str


@dataclass(frozen=True)
class ArtifactObjectLocation:
    purpose: StorePurpose
    bucket: str
    key: str


class S3ObjectClient(Protocol):
    def put_object(self, **kwargs: object) -> Mapping[str, object]: ...

    def get_object(self, **kwargs: object) -> Mapping[str, object]: ...


_PREFIX_BY_KIND = {
    ArtifactKind.RESERVATION: "reservations",
    ArtifactKind.REVIEW: "reviews",
    ArtifactKind.LIFECYCLE: "lifecycles",
    ArtifactKind.POPULATION: "populations",
    ArtifactKind.OBSERVATION: "observations",
    ArtifactKind.WORKFLOW: "workflows",
    ArtifactKind.REPORT: "reports",
    ArtifactKind.REPLAY: "replays",
}
_PRECONDITION_CODES = frozenset({"409", "412", "ConditionalRequestConflict", "PreconditionFailed"})
_NOT_FOUND_CODES = frozenset({"404", "NoSuchKey", "NotFound"})
_DIGEST = re.compile(r"[0-9a-f]{64}")


def _digest(value: object) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ArtifactRepositoryError(ArtifactRepositoryReason.INVALID_REQUEST)
    return value


def _authority_value(authority: ArtifactReadAuthority) -> dict[str, JsonValue]:
    return {
        "actor_role": authority.actor_role.value,
        "permissions": tuple(item.value for item in authority.permissions),
        "policy_digest": authority.policy_digest,
    }


def artifact_read_authority(
    actor_role: ArtifactActorRole | str,
    permissions: Iterable[ArtifactReadPermission | str],
    policy_digest: str,
    *,
    expected_access_policy_digest: str,
) -> ArtifactReadAuthority:
    invalid = False
    try:
        role = ArtifactActorRole(actor_role)
        granted = tuple(sorted({ArtifactReadPermission(item) for item in permissions}, key=lambda item: item.value))
    except (TypeError, ValueError):
        invalid = True
    if invalid:
        raise ArtifactRepositoryError(ArtifactRepositoryReason.INVALID_REQUEST)
    policy = _digest(policy_digest)
    expected = _digest(expected_access_policy_digest)
    if policy != expected:
        raise ArtifactRepositoryError(ArtifactRepositoryReason.POLICY_MISMATCH)
    if role is not ArtifactActorRole.CUSTODIAN and granted:
        raise ArtifactRepositoryError(ArtifactRepositoryReason.NOT_AUTHORIZED)
    draft = ArtifactReadAuthority(role, granted, policy, "")
    return replace(draft, authority_digest=content_digest(_authority_value(draft)))


def _validate_authority(authority: ArtifactReadAuthority, expected_policy: str) -> None:
    if type(authority) is not ArtifactReadAuthority:
        raise ArtifactRepositoryError(ArtifactRepositoryReason.NOT_AUTHORIZED)
    if type(authority.actor_role) is not ArtifactActorRole or any(
        type(item) is not ArtifactReadPermission for item in authority.permissions
    ):
        raise ArtifactRepositoryError(ArtifactRepositoryReason.NOT_AUTHORIZED)
    expected_permissions = tuple(sorted(set(authority.permissions), key=lambda item: item.value))
    if authority.permissions != expected_permissions:
        raise ArtifactRepositoryError(ArtifactRepositoryReason.NOT_AUTHORIZED)
    expected = _digest(expected_policy)
    if authority.actor_role is not ArtifactActorRole.CUSTODIAN and authority.permissions:
        raise ArtifactRepositoryError(ArtifactRepositoryReason.NOT_AUTHORIZED)
    if authority.policy_digest != expected:
        raise ArtifactRepositoryError(ArtifactRepositoryReason.POLICY_MISMATCH)
    if authority.authority_digest != content_digest(_authority_value(authority)):
        raise ArtifactRepositoryError(ArtifactRepositoryReason.NOT_AUTHORIZED)


def _require_access(access: ArtifactAccessClass, authority: ArtifactReadAuthority) -> None:
    role = authority.actor_role
    permissions = authority.permissions
    is_allowed = access is ArtifactAccessClass.PUBLIC
    if access is ArtifactAccessClass.PRIVATE:
        is_allowed = role is ArtifactActorRole.CUSTODIAN and ArtifactReadPermission.PRIVATE in permissions
    elif access is ArtifactAccessClass.CUSTODIAN_SEALED:
        is_allowed = role is ArtifactActorRole.CUSTODIAN and ArtifactReadPermission.CUSTODIAN_SEALED in permissions
    elif access is ArtifactAccessClass.OPERATOR_SAFE:
        is_allowed = role in {ArtifactActorRole.OPERATOR, ArtifactActorRole.PRESENTER}
    if not is_allowed:
        raise ArtifactRepositoryError(ArtifactRepositoryReason.NOT_AUTHORIZED)


def artifact_object_location(settings: StoreSettings, reference: ArtifactReference) -> ArtifactObjectLocation:
    if type(settings) is not StoreSettings or settings.purpose is not StorePurpose.DURABLE:
        raise ArtifactRepositoryError(ArtifactRepositoryReason.INVALID_REQUEST)
    if type(reference) is not ArtifactReference:
        raise ArtifactRepositoryError(ArtifactRepositoryReason.INVALID_REQUEST)
    prefix = _PREFIX_BY_KIND[reference.artifact_kind]
    key = f"{prefix}/{reference.access_class.value}/{reference.content_digest}.json"
    return ArtifactObjectLocation(StorePurpose.DURABLE, settings.bucket, key)


def _provider_code(error: Exception) -> str:
    try:
        response = getattr(error, "response", None)
        if isinstance(response, Mapping):
            details = response.get("Error")
            code = details.get("Code", "") if isinstance(details, Mapping) else ""
        else:
            code = getattr(error, "code", "")
    except Exception:
        return ""
    if isinstance(code, str):
        return code
    return str(code) if type(code) is int else ""


def _body_bytes(response: Mapping[str, object]) -> bytes:
    body = response.get("Body")
    read_failed = False
    try:
        value = body.read() if hasattr(body, "read") else body
    except Exception:
        read_failed = True
        value = None
    if read_failed:
        raise ArtifactRepositoryError(ArtifactRepositoryReason.STORE_FAILURE)
    if not isinstance(value, bytes):
        raise ArtifactRepositoryError(ArtifactRepositoryReason.STORE_FAILURE)
    if not value:
        raise ArtifactRepositoryError(ArtifactRepositoryReason.EMPTY_OBJECT)
    length = response.get("ContentLength")
    if type(length) is not int or length != len(value):
        raise ArtifactRepositoryError(ArtifactRepositoryReason.STORE_FAILURE)
    return value


class S3ArtifactRepository:
    """Strict content-object repository over an injected S3-compatible client."""

    def __init__(self, settings: StoreSettings, client: S3ObjectClient) -> None:
        if type(settings) is not StoreSettings or settings.purpose is not StorePurpose.DURABLE:
            raise ArtifactRepositoryError(ArtifactRepositoryReason.INVALID_REQUEST)
        self._settings = settings
        self._client = client

    def _read_raw(self, reference: ArtifactReference) -> bytes:
        location = artifact_object_location(self._settings, reference)
        failure: ArtifactRepositoryReason | None = None
        try:
            response = self._client.get_object(Bucket=location.bucket, Key=location.key)
        except Exception as error:
            failure = (
                ArtifactRepositoryReason.NOT_FOUND if _provider_code(error) in _NOT_FOUND_CODES else ArtifactRepositoryReason.STORE_FAILURE
            )
            response = None
        if failure is not None:
            raise ArtifactRepositoryError(failure)
        if not isinstance(response, Mapping):
            raise ArtifactRepositoryError(ArtifactRepositoryReason.STORE_FAILURE)
        return _body_bytes(response)

    def _read_accepted(self, reference: ArtifactReference) -> AcceptedArtifact:
        content = self._read_raw(reference)
        invalid = False
        try:
            accepted = accept_artifact(content, reference=reference)
        except ArtifactContractError:
            invalid = True
            accepted = None
        if invalid or accepted is None:
            raise ArtifactRepositoryError(ArtifactRepositoryReason.INVALID_OBJECT)
        return accepted

    def _existing_after_precondition(self, content: bytes, reference: ArtifactReference) -> ArtifactReference:
        read_failed = False
        try:
            existing = self._read_raw(reference)
        except ArtifactRepositoryError:
            read_failed = True
            existing = b""
        if read_failed:
            raise ArtifactRepositoryConflict()
        if existing != content:
            raise ArtifactRepositoryConflict()
        invalid = False
        try:
            accept_artifact(existing, reference=reference)
        except ArtifactContractError:
            invalid = True
        if invalid:
            raise ArtifactRepositoryConflict()
        return reference

    def put_if_absent(self, content: bytes, *, reference: ArtifactReference) -> ArtifactReference:
        invalid = False
        try:
            accepted = accept_artifact(content, reference=reference)
        except (ArtifactContractError, TypeError):
            invalid = True
            accepted = None
        if invalid or accepted is None:
            raise ArtifactRepositoryError(ArtifactRepositoryReason.INVALID_OBJECT)
        location = artifact_object_location(self._settings, accepted.reference)
        precondition = False
        put_failed = False
        try:
            response = self._client.put_object(
                Bucket=location.bucket,
                Key=location.key,
                Body=content,
                ContentType="application/json",
                IfNoneMatch="*",
            )
        except Exception as error:
            precondition = _provider_code(error) in _PRECONDITION_CODES
            put_failed = not precondition
            response = None
        if precondition:
            return self._existing_after_precondition(content, reference)
        if put_failed:
            raise ArtifactRepositoryError(ArtifactRepositoryReason.STORE_FAILURE)
        if not isinstance(response, Mapping) or not isinstance(response.get("ETag"), str) or not response["ETag"]:
            raise ArtifactRepositoryError(ArtifactRepositoryReason.STORE_FAILURE)
        self._read_accepted(reference)
        return reference

    def get(
        self,
        reference: ArtifactReference,
        *,
        expected_kind: ArtifactKind | str,
        authority: ArtifactReadAuthority,
        expected_access_policy_digest: str,
    ) -> AcceptedArtifact:
        if type(reference) is not ArtifactReference:
            raise ArtifactRepositoryError(ArtifactRepositoryReason.INVALID_REQUEST)
        invalid = False
        try:
            kind = ArtifactKind(expected_kind)
        except (TypeError, ValueError):
            invalid = True
            kind = None
        if invalid or kind is None:
            raise ArtifactRepositoryError(ArtifactRepositoryReason.INVALID_REQUEST)
        if reference.artifact_kind is not kind:
            raise ArtifactRepositoryError(ArtifactRepositoryReason.INVALID_REQUEST)
        _validate_authority(authority, expected_access_policy_digest)
        _require_access(reference.access_class, authority)
        return self._read_accepted(reference)


def open_s3_artifact_repository(settings: StoreSettings) -> S3ArtifactRepository:
    """Build the application client without any bucket-administration authority."""
    if type(settings) is not StoreSettings or settings.purpose is not StorePurpose.DURABLE:
        raise ArtifactRepositoryError(ArtifactRepositoryReason.INVALID_REQUEST)
    dependency_missing = False
    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        dependency_missing = True
    if dependency_missing:
        raise ArtifactRepositoryError(ArtifactRepositoryReason.DEPENDENCY_MISSING)
    store_failed = False
    try:
        config = Config(signature_version="s3v4", s3={"addressing_style": "path"})
        client = boto3.client(
            "s3",
            endpoint_url=settings.endpoint,
            aws_access_key_id=settings.access_key_id,
            aws_secret_access_key=settings.secret_access_key,
            aws_session_token=settings.session_token,
            region_name=settings.region,
            config=config,
        )
    except Exception:
        store_failed = True
        client = None
    if store_failed or client is None:
        raise ArtifactRepositoryError(ArtifactRepositoryReason.STORE_FAILURE)
    return S3ArtifactRepository(settings, cast(S3ObjectClient, client))


__all__ = [
    "ArtifactActorRole",
    "ArtifactObjectLocation",
    "ArtifactReadAuthority",
    "ArtifactReadPermission",
    "ArtifactRepositoryConflict",
    "ArtifactRepositoryError",
    "ArtifactRepositoryReason",
    "S3ArtifactRepository",
    "artifact_object_location",
    "artifact_read_authority",
    "open_s3_artifact_repository",
]
