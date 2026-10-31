"""Strict canonical serialization and read-only artifact validation for core v2."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, TypeAlias

DETECTION_CORE_SCHEMA = "openultrasast.detection-core.v2"
STORAGE_RECEIPT_SCHEMA = "openultrasast.detection-core.storage-receipt.v2"

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | tuple["JsonValue", ...] | Mapping[str, "JsonValue"]
_NormalizedJson: TypeAlias = JsonScalar | list["_NormalizedJson"] | dict[str, "_NormalizedJson"]
_DIGEST = re.compile(r"[0-9a-f]{64}")


class CanonicalizationError(ValueError):
    """A value is outside the canonical JSON profile."""


class SchemaVersionError(CanonicalizationError):
    """A digestible record lacks a recognized schema version."""


class DuplicateIdentityError(CanonicalizationError):
    """A logical identity occurs more than once in an aggregate."""


class DigestFormatError(ValueError):
    """A v2 digest is not a full lowercase SHA-256 identity."""


class ArtifactResolutionError(LookupError):
    """A referenced artifact could not be read."""


class ArtifactValidationError(ValueError):
    """Resolved artifact bytes or their storage receipt are untrusted."""


def _normalize(value: object) -> _NormalizedJson:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError("numbers must be finite")
        return value
    if isinstance(value, tuple):
        return [_normalize(item) for item in value]
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise CanonicalizationError("mapping keys must be strings")
        return {key: _normalize(item) for key, item in value.items()}
    raise CanonicalizationError(f"unsupported canonical value: {type(value).__name__}")


def canonical_bytes(value: JsonValue) -> bytes:
    """Return deterministic compact UTF-8 JSON for the closed canonical profile."""
    normalized = _normalize(value)
    text = json.dumps(normalized, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError("strings must be valid UTF-8") from exc


def canonical_record_bytes(
    value: Mapping[str, JsonValue],
    *,
    known_schema_versions: Collection[str] = (DETECTION_CORE_SCHEMA,),
) -> bytes:
    """Canonicalize a record only when its top-level schema is explicitly known."""
    schema = value.get("schema_version")
    if not isinstance(schema, str):
        raise SchemaVersionError("schema_version must be present as text")
    if schema not in known_schema_versions:
        raise SchemaVersionError(f"unknown schema_version: {schema}")
    return canonical_bytes(value)


def bytes_digest(content: bytes) -> str:
    """Return the full lowercase SHA-256 identity of exact bytes."""
    if not isinstance(content, bytes):
        raise TypeError("content must be bytes")
    return hashlib.sha256(content).hexdigest()


def content_digest(value: JsonValue) -> str:
    """Return the full lowercase SHA-256 identity of a canonical value."""
    return bytes_digest(canonical_bytes(value))


def require_unique_identities(identities: Sequence[str], *, kind: str) -> None:
    """Refuse duplicate logical identities before an aggregate is hashed."""
    seen: set[str] = set()
    for identity in identities:
        if identity in seen:
            raise DuplicateIdentityError(f"duplicate {kind} identity: {identity}")
        seen.add(identity)


def _require_digest(value: object, field_name: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise DigestFormatError(f"{field_name} must be a full lowercase SHA-256 digest")


def _require_nonempty(value: object, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be nonempty text")


def _require_length(value: int, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")


@dataclass(frozen=True)
class ContentRef:
    """Opaque artifact identity plus the identities needed to validate its bytes."""

    artifact_id: str
    content_digest: str
    media_type: str
    byte_length: int
    retention_policy_digest: str
    storage_receipt_digest: str

    def __post_init__(self) -> None:
        _require_nonempty(self.artifact_id, "artifact_id")
        _require_nonempty(self.media_type, "media_type")
        _require_length(self.byte_length, "byte_length")
        _require_digest(self.content_digest, "content_digest")
        _require_digest(self.retention_policy_digest, "retention_policy_digest")
        _require_digest(self.storage_receipt_digest, "storage_receipt_digest")


@dataclass(frozen=True)
class StorageReceipt:
    """Store attestation over content, length, and retention identity."""

    store_identity: str
    content_digest: str
    byte_length: int
    retention_policy_digest: str
    receipt_digest: str

    def __post_init__(self) -> None:
        _require_nonempty(self.store_identity, "store_identity")
        _require_length(self.byte_length, "byte_length")
        _require_digest(self.content_digest, "content_digest")
        _require_digest(self.retention_policy_digest, "retention_policy_digest")
        _require_digest(self.receipt_digest, "receipt_digest")


@dataclass(frozen=True)
class ResolvedContent:
    """Bytes and the immutable store receipt returned by a resolver."""

    content: bytes
    receipt: StorageReceipt

    def __post_init__(self) -> None:
        if not isinstance(self.content, bytes):
            raise TypeError("resolved content must be bytes")


class ContentResolver(Protocol):
    """Injected read-only artifact resolver; core never writes through this port."""

    def resolve(self, reference: ContentRef) -> ResolvedContent: ...


def derive_storage_receipt_digest(
    *,
    store_identity: str,
    content_digest: str,
    byte_length: int,
    retention_policy_digest: str,
) -> str:
    """Derive a receipt identity from every attested storage property."""
    _require_nonempty(store_identity, "store_identity")
    _require_digest(content_digest, "content_digest")
    _require_length(byte_length, "byte_length")
    _require_digest(retention_policy_digest, "retention_policy_digest")
    payload: JsonValue = {
        "schema_version": STORAGE_RECEIPT_SCHEMA,
        "store_identity": store_identity,
        "content_digest": content_digest,
        "byte_length": byte_length,
        "retention_policy_digest": retention_policy_digest,
    }
    return bytes_digest(canonical_bytes(payload))


def _validate_receipt(reference: ContentRef, receipt: StorageReceipt, trusted_stores: Collection[str]) -> None:
    if receipt.content_digest != reference.content_digest:
        raise ArtifactValidationError("receipt content digest does not match reference")
    if receipt.byte_length != reference.byte_length:
        raise ArtifactValidationError("receipt byte length does not match reference")
    if receipt.retention_policy_digest != reference.retention_policy_digest:
        raise ArtifactValidationError("receipt retention policy does not match reference")
    if receipt.store_identity not in trusted_stores:
        raise ArtifactValidationError(f"store is not trusted: {receipt.store_identity}")
    if receipt.receipt_digest != reference.storage_receipt_digest:
        raise ArtifactValidationError("receipt digest does not match reference")
    expected = derive_storage_receipt_digest(
        store_identity=receipt.store_identity,
        content_digest=receipt.content_digest,
        byte_length=receipt.byte_length,
        retention_policy_digest=receipt.retention_policy_digest,
    )
    if receipt.receipt_digest != expected:
        raise ArtifactValidationError("receipt digest cannot be re-derived")


def resolve_content(
    reference: ContentRef,
    resolver: ContentResolver,
    *,
    trusted_store_identities: Collection[str],
    maximum_bytes: int,
) -> bytes:
    """Resolve and validate exact bytes and receipt identities before parsing."""
    _require_length(maximum_bytes, "maximum_bytes")
    if reference.byte_length > maximum_bytes:
        raise ArtifactValidationError("reference byte length exceeds configured maximum")
    resolved = resolver.resolve(reference)
    if len(resolved.content) != reference.byte_length:
        raise ArtifactValidationError("resolved byte length does not match reference")
    if bytes_digest(resolved.content) != reference.content_digest:
        raise ArtifactValidationError("resolved content digest does not match reference")
    _validate_receipt(reference, resolved.receipt, trusted_store_identities)
    return resolved.content


__all__ = [
    "ArtifactResolutionError",
    "ArtifactValidationError",
    "CanonicalizationError",
    "ContentRef",
    "ContentResolver",
    "DETECTION_CORE_SCHEMA",
    "DigestFormatError",
    "DuplicateIdentityError",
    "JsonScalar",
    "JsonValue",
    "ResolvedContent",
    "STORAGE_RECEIPT_SCHEMA",
    "SchemaVersionError",
    "StorageReceipt",
    "bytes_digest",
    "canonical_bytes",
    "canonical_record_bytes",
    "content_digest",
    "derive_storage_receipt_digest",
    "require_unique_identities",
    "resolve_content",
]
