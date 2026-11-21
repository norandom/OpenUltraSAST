"""Durable persistence, hostile decode, and reviewer package publication."""

from __future__ import annotations

import json
import math
from typing import Any

from benchmarks.valid.artifact_repository import ArtifactReadAuthority, S3ArtifactRepository
from benchmarks.valid.replacement_artifact_contract import (
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
    artifact_reference,
    canonical_artifact_bytes,
)
from benchmarks.valid.sourcing_queue import (
    SOURCING_QUEUE_SCHEMA,
    EcosystemReviewQueueV1,
    FamilyEvidence,
    FixSiteEvidence,
    QueueEntryStatus,
    QueueExclusionV1,
    ReachabilityEvidence,
    ReviewQueueEntryV1,
    SourcingQueueError,
    SourcingQueueReason,
    SourcingQueueStateV1,
    ecosystem_review_queue,
    queue_state_bytes,
    queue_state_value,
    reviewer_evidence_payload,
    sourcing_queue_state,
)
from openultrasast.core.canonical import canonical_bytes

_STATE_KEYS = frozenset(
    {"schema_version", "python_queue", "javascript_queue", "exclusions", "census_digest", "policy_digest", "state_digest"}
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
        raise SourcingQueueError(SourcingQueueReason.STATE_UNREADABLE)
    try:
        parsed = json.loads(content, parse_constant=_reject_constant, parse_float=_finite_float)
        value = _converted(parsed)
        canonical = canonical_bytes(value)
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise SourcingQueueError(SourcingQueueReason.STATE_UNREADABLE) from None
    if not isinstance(value, dict) or canonical != content:
        raise SourcingQueueError(SourcingQueueReason.STATE_UNREADABLE)
    return value


def _entry_from_value(item: Any) -> ReviewQueueEntryV1:
    family_value = item["family"]
    family = FamilyEvidence(
        family_value["vulnerability_family"],
        family_value["cwe"],
        family_value["advisory_locator"],
        family_value["advisory_digest"],
    )
    reachability = ReachabilityEvidence(item["reachability"]["entry_point"], item["reachability"]["evidence_digest"])
    site = FixSiteEvidence(
        item["fix_site"]["path"],
        item["fix_site"]["function"],
        item["fix_site"]["vulnerable_revision"],
        item["fix_site"]["fixed_revision"],
        item["fix_site"]["vulnerable_snapshot_digest"],
        item["fix_site"]["fixed_snapshot_digest"],
        item["fix_site"]["vulnerable_byte_length"],
        item["fix_site"]["fixed_byte_length"],
    )
    status = QueueEntryStatus(item["entry_status"])
    entry = ReviewQueueEntryV1(
        item["canonical_ecosystem"],
        item["observed_language"],
        item["candidate_digest"],
        item["canonical_repository"],
        item["network_identity_digest"],
        family,
        reachability,
        site,
        item["model_assistance_digest"],
        status,
        item["entry_digest"],
    )
    return entry


def _rebuilt_queue(value: Any) -> EcosystemReviewQueueV1:
    """Rebuild one queue through its public constructor so digests rederive exactly."""
    entries = tuple(_entry_from_value(item) for item in value["entries"])
    return ecosystem_review_queue(value["ecosystem"], cap=value["cap"], policy_digest=value["policy_digest"], entries=entries)


def _exclusion_from_value(item: Any) -> QueueExclusionV1:
    return QueueExclusionV1(
        item["advisory_locator"],
        item["repository"],
        item["candidate_digest"],
        SourcingQueueReason(item["reason"]),
        item["exclusion_digest"],
    )


def decode_queue_state(content: bytes) -> SourcingQueueStateV1:
    """Rebuild queue state only from canonical, digest-consistent bytes."""
    value = _decoded_value(content)
    if set(value) != _STATE_KEYS or value["schema_version"] != SOURCING_QUEUE_SCHEMA:
        raise SourcingQueueError(SourcingQueueReason.STATE_MISMATCH)
    try:
        state = sourcing_queue_state(
            python_queue=_rebuilt_queue(value["python_queue"]),
            javascript_queue=_rebuilt_queue(value["javascript_queue"]),
            exclusions=tuple(_exclusion_from_value(item) for item in value["exclusions"]),
            census_digest=value["census_digest"],
            policy_digest=value["policy_digest"],
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        raise SourcingQueueError(SourcingQueueReason.STATE_MISMATCH) from None
    if queue_state_bytes(state) != content:
        raise SourcingQueueError(SourcingQueueReason.STATE_MISMATCH)
    return state


def persist_sourcing_queue(store: S3ArtifactRepository, state: SourcingQueueStateV1) -> ArtifactReference:
    """Persist resumable queue state and exclusions as one durable population artifact."""
    content = canonical_artifact_bytes(
        ArtifactKind.POPULATION,
        queue_state_value(state),
        access_class=ArtifactAccessClass.PUBLIC,
        provenance_digest=state.policy_digest,
    )
    return store.put_if_absent(content, reference=artifact_reference(content))


def resume_sourcing_queue(
    store: S3ArtifactRepository,
    reference: ArtifactReference,
    *,
    authority: ArtifactReadAuthority,
    expected_access_policy_digest: str,
) -> SourcingQueueStateV1:
    """Resume queue state from the durable store after restart or scratch loss."""
    accepted = store.get(
        reference,
        expected_kind=ArtifactKind.POPULATION,
        authority=authority,
        expected_access_policy_digest=expected_access_policy_digest,
    )
    try:
        content = canonical_bytes(_converted(accepted.artifact.payload))
    except (TypeError, ValueError, RecursionError):
        raise SourcingQueueError(SourcingQueueReason.STATE_MISMATCH) from None
    return decode_queue_state(content)


def publish_reviewer_evidence_packages(store: S3ArtifactRepository, state: SourcingQueueStateV1) -> tuple[ArtifactReference, ...]:
    """Publish canonical reviewer evidence packages with no verdict as authority."""
    references = []
    for entry in (*state.python_queue.entries, *state.javascript_queue.entries):
        content = canonical_artifact_bytes(
            ArtifactKind.REVIEW,
            reviewer_evidence_payload(entry),
            access_class=ArtifactAccessClass.PUBLIC,
            provenance_digest=entry.entry_digest,
        )
        references.append(store.put_if_absent(content, reference=artifact_reference(content)))
    return tuple(references)


__all__ = [
    "decode_queue_state",
    "persist_sourcing_queue",
    "publish_reviewer_evidence_packages",
    "resume_sourcing_queue",
]
