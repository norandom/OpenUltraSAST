"""Canonical identities for replacement valid-benchmark artifacts.

The legacy ``artifact_contract`` module remains the read-only compatibility
boundary for V2 bytes. Only envelopes accepted here may authorize the
replacement benchmark.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from openultrasast.core.canonical import JsonValue, bytes_digest, canonical_bytes

BENCHMARK_ARTIFACT_SCHEMA = "openultrasast.valid-detection-benchmark.artifact.v1"
BENCHMARK_REFERENCE_SCHEMA = "openultrasast.valid-detection-benchmark.artifact-reference.v1"

_DIGEST = re.compile(r"[0-9a-f]{64}")
_ENVELOPE_KEYS = frozenset(
    {
        "schema_version",
        "artifact_kind",
        "access_class",
        "provenance_digest",
        "payload_digest",
        "payload",
    }
)
_REFERENCE_KEYS = frozenset(
    {
        "schema_version",
        "artifact_kind",
        "access_class",
        "provenance_digest",
        "content_digest",
        "byte_length",
    }
)


class ArtifactContractError(ValueError):
    """The replacement artifact does not satisfy its closed contract."""


class ArtifactIdentityConflict(ArtifactContractError):
    """One content identity was presented with different bytes."""


class ArtifactKind(StrEnum):
    """Closed replacement-benchmark artifact families."""

    RESERVATION = "reservation"
    REVIEW = "review"
    LIFECYCLE = "lifecycle"
    POPULATION = "population"
    OBSERVATION = "observation"
    WORKFLOW = "workflow"
    REPORT = "report"
    REPLAY = "replay"


class ArtifactAccessClass(StrEnum):
    """Access class recorded in every authoritative envelope."""

    PUBLIC = "public"
    PRIVATE = "private"
    CUSTODIAN_SEALED = "custodian_sealed"
    OPERATOR_SAFE = "operator_safe"


@dataclass(frozen=True)
class ArtifactReference:
    """Exact kind, access, provenance, digest, and byte-length identity."""

    artifact_kind: ArtifactKind
    content_digest: str
    byte_length: int
    provenance_digest: str
    access_class: ArtifactAccessClass

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifact_kind", _kind(self.artifact_kind))
        object.__setattr__(self, "access_class", _access(self.access_class))
        _require_digest(self.content_digest, "content digest")
        _require_digest(self.provenance_digest, "provenance digest")
        _require_length(self.byte_length)


@dataclass(frozen=True)
class BenchmarkArtifact:
    """Validated authoritative envelope and its domain payload."""

    artifact_kind: ArtifactKind
    access_class: ArtifactAccessClass
    provenance_digest: str
    payload_digest: str
    payload: Mapping[str, JsonValue]


@dataclass(frozen=True)
class AcceptedArtifact:
    """Artifact admitted only after exact reference validation."""

    reference: ArtifactReference
    artifact: BenchmarkArtifact
    content: bytes


def _require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ArtifactContractError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _require_length(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ArtifactContractError("artifact byte length must be a positive integer")
    return value


def _kind(value: object) -> ArtifactKind:
    if not isinstance(value, str):
        raise ArtifactContractError(f"unsupported artifact kind: {value!r}")
    try:
        return ArtifactKind(value)
    except ValueError as error:
        raise ArtifactContractError(f"unsupported artifact kind: {value!r}") from error


def _access(value: object) -> ArtifactAccessClass:
    if not isinstance(value, str):
        raise ArtifactContractError(f"unsupported artifact access class: {value!r}")
    try:
        return ArtifactAccessClass(value)
    except ValueError as error:
        raise ArtifactContractError(f"unsupported artifact access class: {value!r}") from error


def _canonical_value(value: object) -> JsonValue:
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise ArtifactContractError("canonical artifact mapping keys must be strings")
        return {key: _canonical_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(_canonical_value(item) for item in value)
    raise ArtifactContractError(f"unsupported canonical artifact value: {type(value).__name__}")


def canonical_json_bytes(value: object) -> bytes:
    """Encode the benchmark's compact, sorted, finite JSON profile."""
    try:
        return canonical_bytes(_canonical_value(value))
    except (TypeError, ValueError, UnicodeError) as error:
        if isinstance(error, ArtifactContractError):
            raise
        raise ArtifactContractError(f"unsupported canonical artifact value: {error}") from error


def _payload(value: object) -> dict[str, JsonValue]:
    canonical = _canonical_value(value)
    if not isinstance(canonical, Mapping) or not canonical:
        raise ArtifactContractError("artifact payload must be a nonempty mapping")
    return dict(canonical)


def canonical_artifact_bytes(
    kind: ArtifactKind | str,
    payload: Mapping[str, JsonValue],
    *,
    access_class: ArtifactAccessClass | str,
    provenance_digest: str,
) -> bytes:
    """Build deterministic bytes for one authoritative replacement artifact."""
    artifact_kind = _kind(kind)
    access = _access(access_class)
    provenance = _require_digest(provenance_digest, "provenance digest")
    canonical_payload = _payload(payload)
    envelope: JsonValue = {
        "schema_version": BENCHMARK_ARTIFACT_SCHEMA,
        "artifact_kind": artifact_kind.value,
        "access_class": access.value,
        "provenance_digest": provenance,
        "payload_digest": bytes_digest(canonical_json_bytes(canonical_payload)),
        "payload": canonical_payload,
    }
    return canonical_json_bytes(envelope)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ArtifactContractError(f"duplicate canonical JSON key: {key}")
        value[key] = item
    return value


def _decode_canonical(content: bytes, label: str) -> dict[str, object]:
    if not isinstance(content, bytes) or not content:
        raise ArtifactContractError(f"{label} bytes must be nonempty")
    try:
        decoded = json.loads(content, object_pairs_hook=_unique_object)
    except ArtifactContractError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ArtifactContractError(f"{label} bytes are unreadable") from error
    if not isinstance(decoded, dict):
        raise ArtifactContractError(f"{label} must be a canonical JSON object")
    if canonical_json_bytes(decoded) != content:
        raise ArtifactContractError(f"{label} bytes are not canonical")
    return decoded


def _validate_envelope(value: Mapping[str, object]) -> BenchmarkArtifact:
    if set(value) != _ENVELOPE_KEYS:
        raise ArtifactContractError("artifact envelope fields do not match schema")
    if value.get("schema_version") != BENCHMARK_ARTIFACT_SCHEMA:
        raise ArtifactContractError("artifact schema is not replacement-authorizing")
    kind = _kind(value.get("artifact_kind"))
    access = _access(value.get("access_class"))
    provenance = _require_digest(value.get("provenance_digest"), "provenance digest")
    payload = _payload(value.get("payload"))
    payload_digest = _require_digest(value.get("payload_digest"), "payload digest")
    if bytes_digest(canonical_json_bytes(payload)) != payload_digest:
        raise ArtifactContractError("payload digest does not match canonical payload")
    return BenchmarkArtifact(kind, access, provenance, payload_digest, payload)


def _check_reference(artifact: BenchmarkArtifact, content: bytes, reference: ArtifactReference) -> None:
    if bytes_digest(content) != reference.content_digest:
        raise ArtifactContractError("artifact content digest does not match reference")
    if len(content) != reference.byte_length:
        raise ArtifactContractError("artifact byte length does not match reference")
    if artifact.artifact_kind is not reference.artifact_kind:
        raise ArtifactContractError("artifact kind does not match reference")
    if artifact.access_class is not reference.access_class:
        raise ArtifactContractError("artifact access class does not match reference")
    if artifact.provenance_digest != reference.provenance_digest:
        raise ArtifactContractError("artifact provenance does not match reference")


def validate_artifact(content: bytes, *, reference: ArtifactReference | None = None) -> BenchmarkArtifact:
    """Validate schema, canonical bytes, metadata, payload, and optional identity."""
    artifact = _validate_envelope(_decode_canonical(content, "artifact"))
    if reference is not None:
        _check_reference(artifact, content, reference)
    return artifact


def artifact_reference(content: bytes) -> ArtifactReference:
    """Derive an exact reference only after the artifact bytes validate."""
    artifact = validate_artifact(content)
    return ArtifactReference(
        artifact.artifact_kind,
        bytes_digest(content),
        len(content),
        artifact.provenance_digest,
        artifact.access_class,
    )


def _reference_value(reference: ArtifactReference) -> dict[str, JsonValue]:
    return {
        "schema_version": BENCHMARK_REFERENCE_SCHEMA,
        "artifact_kind": reference.artifact_kind.value,
        "access_class": reference.access_class.value,
        "provenance_digest": reference.provenance_digest,
        "content_digest": reference.content_digest,
        "byte_length": reference.byte_length,
    }


def canonical_reference_bytes(reference: ArtifactReference) -> bytes:
    """Encode a validated exact artifact reference canonically."""
    if not isinstance(reference, ArtifactReference):
        raise ArtifactContractError("artifact reference has the wrong type")
    return canonical_json_bytes(_reference_value(reference))


def decode_reference(content: bytes) -> ArtifactReference:
    """Decode only the replacement reference schema and closed values."""
    value = _decode_canonical(content, "artifact reference")
    if set(value) != _REFERENCE_KEYS:
        raise ArtifactContractError("artifact reference fields do not match schema")
    if value.get("schema_version") != BENCHMARK_REFERENCE_SCHEMA:
        raise ArtifactContractError("artifact reference schema is unsupported")
    return ArtifactReference(
        _kind(value.get("artifact_kind")),
        _require_digest(value.get("content_digest"), "content digest"),
        _require_length(value.get("byte_length")),
        _require_digest(value.get("provenance_digest"), "provenance digest"),
        _access(value.get("access_class")),
    )


def accept_artifact(
    content: bytes,
    *,
    reference: ArtifactReference,
    existing: bytes | None = None,
) -> AcceptedArtifact:
    """Admit exact bytes idempotently and reject identity collisions."""
    if existing is not None:
        validate_artifact(existing, reference=reference)
        if existing != content:
            raise ArtifactIdentityConflict("same artifact identity resolves to different bytes")
    artifact = validate_artifact(content, reference=reference)
    return AcceptedArtifact(reference, artifact, content)


__all__ = [
    "BENCHMARK_ARTIFACT_SCHEMA",
    "BENCHMARK_REFERENCE_SCHEMA",
    "AcceptedArtifact",
    "ArtifactAccessClass",
    "ArtifactContractError",
    "ArtifactIdentityConflict",
    "ArtifactKind",
    "ArtifactReference",
    "BenchmarkArtifact",
    "accept_artifact",
    "artifact_reference",
    "canonical_artifact_bytes",
    "canonical_json_bytes",
    "canonical_reference_bytes",
    "decode_reference",
    "validate_artifact",
]
