"""Durable persistence, hostile decode, and replay for ordinary population draws."""

from __future__ import annotations

import json
import math
from typing import Any

from benchmarks.valid.artifact_repository import ArtifactReadAuthority, S3ArtifactRepository
from benchmarks.valid.ecosystem_review import CanonicalEcosystem
from benchmarks.valid.ordinary_change_contract import (
    OrdinaryDrawAssignmentV1,
    OrdinaryExclusionReason,
    OrdinaryExclusionV1,
    OrdinaryFixExclusionV1,
    OrdinaryPushV1,
)
from benchmarks.valid.ordinary_draw_contract import (
    ORDINARY_POPULATION_DRAW_SCHEMA,
    OrdinaryDrawProvenanceV1,
    OrdinaryDrawRule,
    OrdinaryDrawStateError,
    OrdinaryDrawStateReason,
    OrdinaryPopulationDrawV1,
    OrdinaryRepositoryReceiptV1,
    ordinary_population_draw,
    ordinary_population_draw_bytes,
    ordinary_population_draw_value,
)
from benchmarks.valid.replacement_artifact_contract import (
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
    artifact_reference,
    canonical_artifact_bytes,
)
from openultrasast.core.canonical import canonical_bytes

_DRAW_KEYS = frozenset(
    {
        "schema_version",
        "required_per_positive",
        "policy_digest",
        "closure_digest",
        "reservation_census_digest",
        "positive_change_digests",
        "per_positive_counts",
        "repository_receipts",
        "fix_exclusions",
        "pushes",
        "assignments",
        "exclusions",
        "provenance",
        "provenance_digest",
        "draw_digest",
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
        raise OrdinaryDrawStateError(OrdinaryDrawStateReason.STATE_UNREADABLE)
    try:
        parsed = json.loads(content, parse_constant=_reject_constant, parse_float=_finite_float)
        value = _converted(parsed)
        canonical = canonical_bytes(value)
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise OrdinaryDrawStateError(OrdinaryDrawStateReason.STATE_UNREADABLE) from None
    if not isinstance(value, dict) or canonical != content:
        raise OrdinaryDrawStateError(OrdinaryDrawStateReason.STATE_UNREADABLE)
    return value


def _push(item: Any) -> OrdinaryPushV1:
    return OrdinaryPushV1(
        item["canonical_repository"],
        item["network_identity_digest"],
        CanonicalEcosystem(item["ecosystem"]),
        item["base_revision"],
        item["tip_revision"],
        item["change_byte_length"],
        item["change_content_digest"],
        item["history_source_digest"],
        item["push_digest"],
    )


def _decoded_draw(value: dict[str, Any]) -> OrdinaryPopulationDrawV1:
    return ordinary_population_draw(
        required_per_positive=value["required_per_positive"],
        policy_digest=value["policy_digest"],
        closure_digest=value["closure_digest"],
        reservation_census_digest=value["reservation_census_digest"],
        positive_change_digests=tuple(value["positive_change_digests"]),
        per_positive_counts=tuple((item["change_identity_digest"], item["eligible_pushes"]) for item in value["per_positive_counts"]),
        repository_receipts=tuple(
            OrdinaryRepositoryReceiptV1(
                item["canonical_repository"],
                item["network_identity_digest"],
                item["byte_length"],
                item["repository_content_digest"],
            )
            for item in value["repository_receipts"]
        ),
        fix_exclusions=tuple(
            OrdinaryFixExclusionV1(
                item["network_identity_digest"],
                item["fixed_revision"],
                item["positive_change_digest"],
                item["ground_truth_review_digest"],
            )
            for item in value["fix_exclusions"]
        ),
        pushes=tuple(_push(item) for item in value["pushes"]),
        assignments=tuple(
            OrdinaryDrawAssignmentV1(
                item["positive_change_digest"],
                item["network_identity_digest"],
                CanonicalEcosystem(item["ecosystem"]),
                item["push_digest"],
            )
            for item in value["assignments"]
        ),
        exclusions=tuple(
            OrdinaryExclusionV1(
                item["network_identity_digest"],
                item["tip_revision"],
                OrdinaryExclusionReason(item["reason"]),
                item["contamination_review_digest"],
            )
            for item in value["exclusions"]
        ),
        provenance=tuple(
            OrdinaryDrawProvenanceV1(
                item["network_identity_digest"],
                item["tip_revision"],
                OrdinaryDrawRule(item["rule"]),
                item["evidence_digest"],
            )
            for item in value["provenance"]
        ),
    )


def decode_ordinary_population_draw(content: bytes) -> OrdinaryPopulationDrawV1:
    """Rebuild one ordinary population draw only from canonical, digest-consistent bytes."""
    value = _decoded_value(content)
    if set(value) != _DRAW_KEYS or value["schema_version"] != ORDINARY_POPULATION_DRAW_SCHEMA:
        raise OrdinaryDrawStateError(OrdinaryDrawStateReason.STATE_MISMATCH)
    try:
        draw = _decoded_draw(value)
    except OrdinaryDrawStateError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise OrdinaryDrawStateError(OrdinaryDrawStateReason.STATE_MISMATCH) from error
    if ordinary_population_draw_bytes(draw) != content:
        raise OrdinaryDrawStateError(OrdinaryDrawStateReason.STATE_MISMATCH)
    return draw


def persist_ordinary_population_draw(store: S3ArtifactRepository, draw: OrdinaryPopulationDrawV1) -> ArtifactReference:
    """Persist one durable ordinary population draw bound to the evidence it examined."""
    content = canonical_artifact_bytes(
        ArtifactKind.POPULATION,
        ordinary_population_draw_value(draw),
        access_class=ArtifactAccessClass.OPERATOR_SAFE,
        provenance_digest=draw.draw_digest,
    )
    return store.put_if_absent(content, reference=artifact_reference(content))


def resume_ordinary_population_draw(
    store: S3ArtifactRepository,
    reference: ArtifactReference,
    *,
    authority: ArtifactReadAuthority,
    expected_access_policy_digest: str,
) -> OrdinaryPopulationDrawV1:
    """Resume one ordinary population draw from the durable store after restart."""
    accepted = store.get(
        reference,
        expected_kind=ArtifactKind.POPULATION,
        authority=authority,
        expected_access_policy_digest=expected_access_policy_digest,
    )
    try:
        content = canonical_bytes(_converted(accepted.artifact.payload))
    except (TypeError, ValueError, RecursionError):
        raise OrdinaryDrawStateError(OrdinaryDrawStateReason.STATE_UNREADABLE) from None
    return decode_ordinary_population_draw(content)


__all__ = [
    "decode_ordinary_population_draw",
    "persist_ordinary_population_draw",
    "resume_ordinary_population_draw",
]
