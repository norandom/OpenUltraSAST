"""Durable persistence, hostile decode, and replay for cohort selection decisions."""

from __future__ import annotations

import json
import math
from typing import Any

from benchmarks.valid.artifact_repository import ArtifactReadAuthority, S3ArtifactRepository
from benchmarks.valid.cohort_selection import (
    COHORT_SELECTION_SCHEMA,
    CohortSelectionReason,
    CohortSelectionStateError,
    CohortSelectionStateReason,
    CohortSelectionStatus,
    CohortSelectionV1,
    cohort_selection,
    cohort_selection_bytes,
    cohort_selection_value,
)
from benchmarks.valid.replacement_artifact_contract import (
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
    artifact_reference,
    canonical_artifact_bytes,
)
from openultrasast.core.canonical import canonical_bytes

_SELECTION_KEYS = frozenset(
    {
        "schema_version",
        "ecosystem",
        "selected_entries",
        "targeted_families",
        "queue_digest",
        "census_digest",
        "ecosystem_policy_digest",
        "ground_truth_policy_digest",
        "prior_batch_digests",
        "accepted_families",
        "accepted_by_ecosystem",
        "status",
        "reason",
        "selection_digest",
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
        raise CohortSelectionStateError(CohortSelectionStateReason.STATE_UNREADABLE)
    try:
        parsed = json.loads(content, parse_constant=_reject_constant, parse_float=_finite_float)
        value = _converted(parsed)
        canonical = canonical_bytes(value)
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise CohortSelectionStateError(CohortSelectionStateReason.STATE_UNREADABLE) from None
    if not isinstance(value, dict) or canonical != content:
        raise CohortSelectionStateError(CohortSelectionStateReason.STATE_UNREADABLE)
    return value


def decode_cohort_selection(content: bytes) -> CohortSelectionV1:
    """Rebuild one selection decision only from canonical, digest-consistent bytes."""
    value = _decoded_value(content)
    if set(value) != _SELECTION_KEYS or value["schema_version"] != COHORT_SELECTION_SCHEMA:
        raise CohortSelectionStateError(CohortSelectionStateReason.STATE_MISMATCH)
    try:
        selection = cohort_selection(
            ecosystem=value["ecosystem"],
            selected_entries=tuple(value["selected_entries"]),
            targeted_families=tuple(value["targeted_families"]),
            queue_digest=value["queue_digest"],
            census_digest=value["census_digest"],
            ecosystem_policy_digest=value["ecosystem_policy_digest"],
            ground_truth_policy_digest=value["ground_truth_policy_digest"],
            prior_batch_digests=tuple(value["prior_batch_digests"]),
            accepted_families=tuple(value["accepted_families"]),
            accepted_by_ecosystem={item["ecosystem"]: item["accepted_positives"] for item in value["accepted_by_ecosystem"]},
            status=CohortSelectionStatus(value["status"]),
            reason=CohortSelectionReason(value["reason"]),
        )
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise CohortSelectionStateError(CohortSelectionStateReason.STATE_MISMATCH) from error
    if cohort_selection_bytes(selection) != content:
        raise CohortSelectionStateError(CohortSelectionStateReason.STATE_MISMATCH)
    return selection


def persist_cohort_selection(store: S3ArtifactRepository, selection: CohortSelectionV1) -> ArtifactReference:
    """Persist one durable selection decision bound to the reservation snapshot."""
    content = canonical_artifact_bytes(
        ArtifactKind.POPULATION,
        cohort_selection_value(selection),
        access_class=ArtifactAccessClass.OPERATOR_SAFE,
        provenance_digest=selection.census_digest,
    )
    return store.put_if_absent(content, reference=artifact_reference(content))


def resume_cohort_selection(
    store: S3ArtifactRepository,
    reference: ArtifactReference,
    *,
    authority: ArtifactReadAuthority,
    expected_access_policy_digest: str,
) -> CohortSelectionV1:
    """Resume one selection decision from the durable store after restart."""
    accepted = store.get(
        reference,
        expected_kind=ArtifactKind.POPULATION,
        authority=authority,
        expected_access_policy_digest=expected_access_policy_digest,
    )
    try:
        content = canonical_bytes(_converted(accepted.artifact.payload))
    except (TypeError, ValueError, RecursionError):
        raise CohortSelectionStateError(CohortSelectionStateReason.STATE_UNREADABLE) from None
    return decode_cohort_selection(content)


__all__ = [
    "decode_cohort_selection",
    "persist_cohort_selection",
    "resume_cohort_selection",
]
