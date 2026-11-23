"""Durable persistence, hostile decode, and replay for cohort batch ingestion."""

from __future__ import annotations

import json
import math
from collections.abc import Sequence
from typing import Any

from benchmarks.valid.artifact_repository import ArtifactReadAuthority, S3ArtifactRepository
from benchmarks.valid.cohort_ingestion import (
    CohortBatchOutcomeV1,
    CohortBatchStatus,
    CohortInsufficientReason,
    CohortRecordOutcomeV1,
    CohortRecordStatus,
    CohortStateError,
    CohortStateReason,
    cohort_batch,
    cohort_batch_bytes,
    cohort_batch_ecosystem,
    cohort_batch_value,
    decode_external_record,
)
from benchmarks.valid.ground_truth_review import AcceptedGroundTruthV1, VerifiedScope
from benchmarks.valid.replacement_artifact_contract import (
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
    artifact_reference,
    canonical_artifact_bytes,
)
from benchmarks.valid.sourcing_queue import QueueExclusionV1, SourcingQueueReason
from openultrasast.core.canonical import JsonValue, bytes_digest, canonical_bytes

REFUSED_QUEUE_EXCLUSIONS_SCHEMA = "openultrasast.valid-detection-benchmark.refused-queue-exclusions.v1"
_BATCH_KEYS = frozenset(
    {
        "schema_version",
        "ecosystem",
        "queue_digest",
        "census_digest",
        "ecosystem_policy_digest",
        "ground_truth_policy_digest",
        "record_outcomes",
        "pending_entries",
        "accepted_positives",
        "minimum_accepted_positives",
        "status",
        "insufficient_reason",
        "batch_digest",
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
        raise CohortStateError(CohortStateReason.STATE_UNREADABLE)
    try:
        parsed = json.loads(content, parse_constant=_reject_constant, parse_float=_finite_float)
        value = _converted(parsed)
        canonical = canonical_bytes(value)
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise CohortStateError(CohortStateReason.STATE_UNREADABLE) from None
    if not isinstance(value, dict) or canonical != content:
        raise CohortStateError(CohortStateReason.STATE_UNREADABLE)
    return value


def _record_outcome_from_value(item: Any) -> CohortRecordOutcomeV1:
    return CohortRecordOutcomeV1(
        item["record_digest"],
        item["queue_entry_digest"],
        item["ground_truth_review_digest"],
        CohortRecordStatus(item["status"]),
        item["reason"],
    )


def _accepted_from_value(item: Any) -> AcceptedGroundTruthV1:
    return AcceptedGroundTruthV1(
        item["change_identity_digest"],
        item["candidate_digest"],
        item["ecosystem_review_digest"],
        item["ground_truth_review_digest"],
        tuple(VerifiedScope(scope["vulnerability_family"], scope["ecosystem"]) for scope in item["verified_scopes"]),
    )


def decode_cohort_batch(content: bytes) -> CohortBatchOutcomeV1:
    """Rebuild one batch outcome only from canonical, digest-consistent bytes."""
    value = _decoded_value(content)
    if set(value) != _BATCH_KEYS:
        raise CohortStateError(CohortStateReason.STATE_MISMATCH)
    ecosystem = cohort_batch_ecosystem(value["schema_version"])
    if ecosystem is None or value["ecosystem"] != ecosystem:
        raise CohortStateError(CohortStateReason.STATE_MISMATCH)
    try:
        reason = None if value["insufficient_reason"] is None else CohortInsufficientReason(value["insufficient_reason"])
        outcome = cohort_batch(
            ecosystem=ecosystem,
            queue_digest=value["queue_digest"],
            census_digest=value["census_digest"],
            ecosystem_policy_digest=value["ecosystem_policy_digest"],
            ground_truth_policy_digest=value["ground_truth_policy_digest"],
            record_outcomes=tuple(_record_outcome_from_value(item) for item in value["record_outcomes"]),
            pending_entries=tuple(value["pending_entries"]),
            accepted_positives=tuple(_accepted_from_value(item) for item in value["accepted_positives"]),
            status=CohortBatchStatus(value["status"]),
            insufficient_reason=reason,
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        raise CohortStateError(CohortStateReason.STATE_MISMATCH) from None
    if cohort_batch_bytes(outcome) != content:
        raise CohortStateError(CohortStateReason.STATE_MISMATCH)
    return outcome


def persist_cohort_batch(store: S3ArtifactRepository, outcome: CohortBatchOutcomeV1) -> ArtifactReference:
    """Persist one accepted or refused batch outcome as a durable review artifact."""
    content = canonical_artifact_bytes(
        ArtifactKind.REVIEW,
        cohort_batch_value(outcome),
        access_class=ArtifactAccessClass.OPERATOR_SAFE,
        provenance_digest=outcome.queue_digest,
    )
    return store.put_if_absent(content, reference=artifact_reference(content))


def resume_cohort_batch(
    store: S3ArtifactRepository,
    reference: ArtifactReference,
    *,
    authority: ArtifactReadAuthority,
    expected_access_policy_digest: str,
) -> CohortBatchOutcomeV1:
    """Resume one batch outcome from the durable store after restart or scratch loss."""
    accepted = store.get(
        reference,
        expected_kind=ArtifactKind.REVIEW,
        authority=authority,
        expected_access_policy_digest=expected_access_policy_digest,
    )
    try:
        content = canonical_bytes(_converted(accepted.artifact.payload))
    except (TypeError, ValueError, RecursionError):
        raise CohortStateError(CohortStateReason.STATE_UNREADABLE) from None
    return decode_cohort_batch(content)


def publish_external_review_records(store: S3ArtifactRepository, records: Sequence[bytes]) -> tuple[ArtifactReference, ...]:
    """Persist canonical external review record bytes as durable governed evidence.

    Records that fail hostile decode are not publishable as payloads; they stay
    ledgered by digest and closed reason inside the persisted batch outcome.
    """
    references = []
    for content in records:
        payload = decode_external_record(content)
        artifact = canonical_artifact_bytes(
            ArtifactKind.REVIEW,
            payload,
            access_class=ArtifactAccessClass.OPERATOR_SAFE,
            provenance_digest=bytes_digest(content),
        )
        references.append(store.put_if_absent(artifact, reference=artifact_reference(artifact)))
    return tuple(references)


def read_external_review_records(
    store: S3ArtifactRepository,
    references: Sequence[ArtifactReference],
    *,
    authority: ArtifactReadAuthority,
    expected_access_policy_digest: str,
) -> tuple[bytes, ...]:
    """Read canonical external review record bytes back from the durable store."""
    contents = []
    for reference in references:
        accepted = store.get(
            reference,
            expected_kind=ArtifactKind.REVIEW,
            authority=authority,
            expected_access_policy_digest=expected_access_policy_digest,
        )
        try:
            contents.append(canonical_bytes(_converted(accepted.artifact.payload)))
        except (TypeError, ValueError, RecursionError):
            raise CohortStateError(CohortStateReason.STATE_UNREADABLE) from None
    return tuple(contents)


def _queue_exclusion_value(item: QueueExclusionV1) -> dict[str, JsonValue]:
    if not isinstance(item.reason, SourcingQueueReason):
        raise CohortStateError(CohortStateReason.STATE_MISMATCH)
    return {
        "advisory_locator": item.advisory_locator,
        "repository": item.repository,
        "candidate_digest": item.candidate_digest,
        "reason": item.reason.value,
        "exclusion_digest": item.exclusion_digest,
    }


def persist_refused_queue_exclusions(
    store: S3ArtifactRepository,
    exclusions: Sequence[QueueExclusionV1],
    *,
    policy_digest: str,
) -> ArtifactReference:
    """Durably record a refused sourcing attempt's exclusions with closed reasons."""
    payload: dict[str, JsonValue] = {
        "schema_version": REFUSED_QUEUE_EXCLUSIONS_SCHEMA,
        "exclusions": tuple(_queue_exclusion_value(item) for item in exclusions),
        "policy_digest": policy_digest,
    }
    content = canonical_artifact_bytes(
        ArtifactKind.POPULATION,
        payload,
        access_class=ArtifactAccessClass.PUBLIC,
        provenance_digest=policy_digest,
    )
    return store.put_if_absent(content, reference=artifact_reference(content))


__all__ = [
    "REFUSED_QUEUE_EXCLUSIONS_SCHEMA",
    "decode_cohort_batch",
    "persist_cohort_batch",
    "persist_refused_queue_exclusions",
    "publish_external_review_records",
    "read_external_review_records",
    "resume_cohort_batch",
]
