"""Durable persistence, hostile decode, and replay for positive-set closure decisions."""

from __future__ import annotations

import json
import math
from typing import Any

from benchmarks.valid.artifact_repository import ArtifactReadAuthority, S3ArtifactRepository
from benchmarks.valid.positive_set_closure import (
    POSITIVE_SET_CLOSURE_SCHEMA,
    PositiveSetClosureReason,
    PositiveSetClosureStateError,
    PositiveSetClosureStateReason,
    PositiveSetClosureStatus,
    PositiveSetClosureV1,
    positive_set_closure,
    positive_set_closure_bytes,
    positive_set_closure_value,
)
from benchmarks.valid.replacement_artifact_contract import (
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
    artifact_reference,
    canonical_artifact_bytes,
)
from openultrasast.core.canonical import canonical_bytes

_CLOSURE_KEYS = frozenset(
    {
        "schema_version",
        "batch_digests",
        "accepted_batch_digests",
        "total_accepted_positives",
        "positives_by_ecosystem",
        "accepted_families",
        "status",
        "reason",
        "closure_digest",
    }
)


def _reject_constant(name: str) -> None:
    raise ValueError(name)


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError(text)
    return value


def _converted(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(_converted(item) for item in value)
    if isinstance(value, dict):
        return {str(key): _converted(item) for key, item in value.items()}
    return value


def _decoded_value(content: bytes) -> dict[str, Any]:
    """Hostile decode: no constants, finite floats, bounded recursion, canonical bytes."""
    if not isinstance(content, bytes) or not content:
        raise PositiveSetClosureStateError(PositiveSetClosureStateReason.STATE_UNREADABLE)
    try:
        parsed = json.loads(content, parse_constant=_reject_constant, parse_float=_finite_float)
        value = _converted(parsed)
        canonical = canonical_bytes(value)
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise PositiveSetClosureStateError(PositiveSetClosureStateReason.STATE_UNREADABLE) from None
    if not isinstance(value, dict) or canonical != content:
        raise PositiveSetClosureStateError(PositiveSetClosureStateReason.STATE_UNREADABLE)
    return value


def decode_positive_set_closure(content: bytes) -> PositiveSetClosureV1:
    """Rebuild one closure decision only from canonical, digest-consistent bytes."""
    value = _decoded_value(content)
    if set(value) != _CLOSURE_KEYS or value["schema_version"] != POSITIVE_SET_CLOSURE_SCHEMA:
        raise PositiveSetClosureStateError(PositiveSetClosureStateReason.STATE_MISMATCH)
    try:
        closure = positive_set_closure(
            batch_digests=tuple(value["batch_digests"]),
            accepted_batch_digests=tuple(value["accepted_batch_digests"]),
            total_accepted_positives=value["total_accepted_positives"],
            positives_by_ecosystem={item["ecosystem"]: item["accepted_positives"] for item in value["positives_by_ecosystem"]},
            accepted_families=tuple(value["accepted_families"]),
            status=PositiveSetClosureStatus(value["status"]),
            reason=PositiveSetClosureReason(value["reason"]),
        )
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise PositiveSetClosureStateError(PositiveSetClosureStateReason.STATE_MISMATCH) from error
    if positive_set_closure_bytes(closure) != content:
        raise PositiveSetClosureStateError(PositiveSetClosureStateReason.STATE_MISMATCH)
    return closure


def persist_positive_set_closure(store: S3ArtifactRepository, closure: PositiveSetClosureV1) -> ArtifactReference:
    """Persist one durable closure decision bound to the ledger facts it examined."""
    content = canonical_artifact_bytes(
        ArtifactKind.POPULATION,
        positive_set_closure_value(closure),
        access_class=ArtifactAccessClass.OPERATOR_SAFE,
        provenance_digest=closure.closure_digest,
    )
    return store.put_if_absent(content, reference=artifact_reference(content))


def resume_positive_set_closure(
    store: S3ArtifactRepository,
    reference: ArtifactReference,
    *,
    authority: ArtifactReadAuthority,
    expected_access_policy_digest: str,
) -> PositiveSetClosureV1:
    """Resume one closure decision from the durable store after restart."""
    accepted = store.get(
        reference,
        expected_kind=ArtifactKind.POPULATION,
        authority=authority,
        expected_access_policy_digest=expected_access_policy_digest,
    )
    try:
        content = canonical_bytes(_converted(accepted.artifact.payload))
    except (TypeError, ValueError, RecursionError):
        raise PositiveSetClosureStateError(PositiveSetClosureStateReason.STATE_UNREADABLE) from None
    return decode_positive_set_closure(content)


__all__ = [
    "decode_positive_set_closure",
    "persist_positive_set_closure",
    "resume_positive_set_closure",
]
