"""Bounded ingestion of externally reviewed cohort batches.

One ingestion unit consumes a single supplied batch of at most twenty external
review records against one pending canonical-ecosystem review queue (Python or
JavaScript; TypeScript arrives as observed language evidence under javascript).
Every acceptance comes only from the committed review authorities revalidating
the external attestations; missing, partial, or refused reviews are recorded as
closed per-record exclusions or pending entries and are never self-approved.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any

from benchmarks.valid.ecosystem_review import (
    EcosystemReviewAttestationV1,
    EcosystemReviewDecision,
    EcosystemReviewError,
    RepositoryEcosystemReviewV1,
    review_repository_ecosystem,
)
from benchmarks.valid.fix_site_catalog import FixSiteCandidateV1
from benchmarks.valid.ground_truth_review import (
    AcceptedGroundTruthV1,
    GroundTruthAttestationV1,
    GroundTruthExclusionReason,
    GroundTruthReviewError,
    GroundTruthReviewV1,
    GroundTruthStatus,
    VerifiedScope,
    project_accepted_ground_truth,
    review_ground_truth,
)
from benchmarks.valid.sourcing_queue import EcosystemReviewQueueV1, ReviewQueueEntryV1, SourcingQueueStateV1
from openultrasast.core.canonical import JsonValue, bytes_digest, canonical_bytes, content_digest

EXTERNAL_REVIEW_RECORD_SCHEMA = "openultrasast.valid-detection-benchmark.external-review-record.v1"
COHORT_BATCH_SCHEMA = "openultrasast.valid-detection-benchmark.python-cohort-batch.v1"
JAVASCRIPT_COHORT_BATCH_SCHEMA = "openultrasast.valid-detection-benchmark.javascript-cohort-batch.v1"
_BATCH_SCHEMA_BY_ECOSYSTEM = {"python": COHORT_BATCH_SCHEMA, "javascript": JAVASCRIPT_COHORT_BATCH_SCHEMA}
_ECOSYSTEM_BY_BATCH_SCHEMA = {schema: ecosystem for ecosystem, schema in _BATCH_SCHEMA_BY_ECOSYSTEM.items()}
COHORT_BATCH_CAP = 20
MINIMUM_ACCEPTED_POSITIVES = 10
_DIGEST = re.compile(r"[0-9a-f]{64}")
_RECORD_KEYS = frozenset({"schema_version", "queue_entry_digest", "ecosystem_attestation", "ground_truth_attestation"})
_ECOSYSTEM_ATTESTATION_KEYS = frozenset(
    {"candidate_digest", "source_evidence_digest", "producer_identity", "reviewer_identity", "conflict_disclosed",
     "policy_digest", "policy_satisfied", "decision"}
)
_GROUND_TRUTH_ATTESTATION_KEYS = frozenset(
    {"candidate_digest", "ecosystem_review_digest", "producer_identity", "reviewer_identity", "conflict_disclosed",
     "policy_digest", "policy_satisfied", "defect_present", "fix_addresses", "in_repository_reachable",
     "verified_scopes", "model_assistance_digest"}
)
_CLOSED_RECORD_REASONS = frozenset(item.value for item in GroundTruthExclusionReason)


class CohortRecordExclusionReason(StrEnum):
    """Closed per-record exclusion causes inside one bounded ingestion unit."""

    RECORD_UNREADABLE = "record_unreadable"
    RECORD_SCHEMA_MISMATCH = "record_schema_mismatch"
    QUEUE_ENTRY_UNKNOWN = "queue_entry_unknown"
    CANDIDATE_EVIDENCE_MISSING = "candidate_evidence_missing"
    REVIEW_EVIDENCE_INVALID = "review_evidence_invalid"
    DUPLICATE_RECORD = "duplicate_record"
    CONFLICTING_ACCEPTED_REVIEW = "conflicting_accepted_review"
    BATCH_UNIT_REFUSED = "batch_unit_refused"


class CohortRecordStatus(StrEnum):
    ACCEPTED = "accepted"
    EXCLUDED = "excluded"


class CohortInsufficientReason(StrEnum):
    """Closed whole-batch insufficiency causes; none of these is a clean pass."""

    BATCH_EMPTY = "batch_empty"
    BATCH_CAP_EXCEEDED = "batch_cap_exceeded"
    PYTHON_QUEUE_EMPTY = "python_queue_empty"
    JAVASCRIPT_QUEUE_EMPTY = "javascript_queue_empty"
    INSUFFICIENT_ACCEPTED_POSITIVES = "insufficient_accepted_positives"


class CohortBatchStatus(StrEnum):
    ACCEPTED = "accepted"
    INSUFFICIENT = "insufficient"


class CohortStateReason(StrEnum):
    STATE_UNREADABLE = "state_unreadable"
    STATE_MISMATCH = "state_mismatch"


_CLOSED_OUTCOME_REASONS = _CLOSED_RECORD_REASONS | frozenset(item.value for item in CohortRecordExclusionReason)


_REASON_TEXT = {
    CohortRecordExclusionReason.RECORD_UNREADABLE: "external review record bytes are unreadable",
    CohortRecordExclusionReason.RECORD_SCHEMA_MISMATCH: "external review record does not match its closed schema",
    CohortRecordExclusionReason.QUEUE_ENTRY_UNKNOWN: "record does not answer a pending cohort review queue entry",
    CohortRecordExclusionReason.CANDIDATE_EVIDENCE_MISSING: "reviewed candidate evidence is absent from the exact input set",
    CohortRecordExclusionReason.REVIEW_EVIDENCE_INVALID: "external review attestations fail authority validation",
    CohortRecordExclusionReason.DUPLICATE_RECORD: "queue entry is already answered by another record in this batch",
    CohortRecordExclusionReason.CONFLICTING_ACCEPTED_REVIEW: "change identity has conflicting accepted reviews",
    CohortRecordExclusionReason.BATCH_UNIT_REFUSED: "ingestion unit refused the whole over-cap batch",
    CohortStateReason.STATE_UNREADABLE: "cohort batch state bytes are unreadable",
    CohortStateReason.STATE_MISMATCH: "cohort batch state does not match its canonical schema",
}


class CohortIngestionError(ValueError):
    """Closed per-record refusal carrying one exclusion reason."""

    def __init__(self, reason: CohortRecordExclusionReason) -> None:
        self.reason = reason
        super().__init__(_REASON_TEXT[reason])


class CohortStateError(ValueError):
    """Closed batch-state refusal carrying one reason."""

    def __init__(self, reason: CohortStateReason) -> None:
        self.reason = reason
        super().__init__(_REASON_TEXT[reason])


@dataclass(frozen=True)
class CohortRecordOutcomeV1:
    record_digest: str
    queue_entry_digest: str | None
    ground_truth_review_digest: str | None
    status: CohortRecordStatus
    reason: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.record_digest, str) or _DIGEST.fullmatch(self.record_digest) is None:
            raise CohortStateError(CohortStateReason.STATE_MISMATCH)
        for digest_value in (self.queue_entry_digest, self.ground_truth_review_digest):
            if digest_value is not None and (not isinstance(digest_value, str) or _DIGEST.fullmatch(digest_value) is None):
                raise CohortStateError(CohortStateReason.STATE_MISMATCH)
        if not isinstance(self.status, CohortRecordStatus):
            raise CohortStateError(CohortStateReason.STATE_MISMATCH)
        if self.status is CohortRecordStatus.ACCEPTED:
            if self.reason is not None:
                raise CohortStateError(CohortStateReason.STATE_MISMATCH)
        elif self.reason not in _CLOSED_OUTCOME_REASONS:
            raise CohortStateError(CohortStateReason.STATE_MISMATCH)


@dataclass(frozen=True)
class CohortBatchOutcomeV1:
    ecosystem: str
    queue_digest: str
    census_digest: str
    ecosystem_policy_digest: str
    ground_truth_policy_digest: str
    record_outcomes: tuple[CohortRecordOutcomeV1, ...]
    pending_entries: tuple[str, ...]
    accepted_positives: tuple[AcceptedGroundTruthV1, ...]
    minimum_accepted_positives: int
    status: CohortBatchStatus
    insufficient_reason: CohortInsufficientReason | None
    batch_digest: str


@dataclass(frozen=True)
class _Reviewed:
    outcome: CohortRecordOutcomeV1
    entry_digest: str | None
    review: GroundTruthReviewV1 | None
    ecosystem: RepositoryEcosystemReviewV1 | None


@dataclass
class _BatchState:
    entries: dict[str, ReviewQueueEntryV1]
    candidates_by_digest: Mapping[str, FixSiteCandidateV1]
    ecosystem_policy_digest: str
    ground_truth_policy_digest: str
    outcomes: list[CohortRecordOutcomeV1] = field(default_factory=list)
    accepted_reviews: list[GroundTruthReviewV1] = field(default_factory=list)
    accepted_by_change: dict[str, AcceptedGroundTruthV1] = field(default_factory=dict)
    ecosystem_reviews: dict[str, RepositoryEcosystemReviewV1] = field(default_factory=dict)
    answered: set[str] = field(default_factory=set)


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


def _decoded_record(content: bytes) -> dict[str, Any]:
    """Hostile decode: no constants, finite floats, bounded recursion, canonical bytes."""
    if not isinstance(content, bytes) or not content:
        raise CohortIngestionError(CohortRecordExclusionReason.RECORD_UNREADABLE)
    try:
        parsed = json.loads(content, parse_constant=_reject_constant, parse_float=_finite_float)
        value = _converted(parsed)
        canonical = canonical_bytes(value)
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise CohortIngestionError(CohortRecordExclusionReason.RECORD_UNREADABLE) from None
    if not isinstance(value, dict) or canonical != content:
        raise CohortIngestionError(CohortRecordExclusionReason.RECORD_UNREADABLE)
    return value


def _record_payload(content: bytes) -> dict[str, Any]:
    value = _decoded_record(content)
    if set(value) != _RECORD_KEYS or value["schema_version"] != EXTERNAL_REVIEW_RECORD_SCHEMA:
        raise CohortIngestionError(CohortRecordExclusionReason.RECORD_SCHEMA_MISMATCH)
    return value


def _entry_digest(payload: Mapping[str, Any]) -> str:
    digest = payload["queue_entry_digest"]
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        raise CohortIngestionError(CohortRecordExclusionReason.RECORD_SCHEMA_MISMATCH)
    return digest


def _mapping_with_keys(value: Any, keys: frozenset[str]) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise CohortIngestionError(CohortRecordExclusionReason.RECORD_SCHEMA_MISMATCH)
    return value


def _ecosystem_attestation(value: Any) -> EcosystemReviewAttestationV1:
    item = _mapping_with_keys(value, _ECOSYSTEM_ATTESTATION_KEYS)
    try:
        return EcosystemReviewAttestationV1(
            item["candidate_digest"],
            item["source_evidence_digest"],
            item["producer_identity"],
            item["reviewer_identity"],
            item["conflict_disclosed"],
            item["policy_digest"],
            item["policy_satisfied"],
            EcosystemReviewDecision(item["decision"]),
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        raise CohortIngestionError(CohortRecordExclusionReason.RECORD_SCHEMA_MISMATCH) from None


def _verified_scopes(value: Any) -> tuple[VerifiedScope, ...]:
    if not isinstance(value, tuple):
        raise CohortIngestionError(CohortRecordExclusionReason.RECORD_SCHEMA_MISMATCH)
    try:
        return tuple(VerifiedScope(item["vulnerability_family"], item["ecosystem"]) for item in value)
    except (AttributeError, KeyError, TypeError, ValueError):
        raise CohortIngestionError(CohortRecordExclusionReason.RECORD_SCHEMA_MISMATCH) from None


def _ground_truth_attestation(value: Any) -> GroundTruthAttestationV1:
    item = _mapping_with_keys(value, _GROUND_TRUTH_ATTESTATION_KEYS)
    try:
        return GroundTruthAttestationV1(
            candidate_digest=item["candidate_digest"],
            ecosystem_review_digest=item["ecosystem_review_digest"],
            producer_identity=item["producer_identity"],
            reviewer_identity=item["reviewer_identity"],
            conflict_disclosed=item["conflict_disclosed"],
            policy_digest=item["policy_digest"],
            policy_satisfied=item["policy_satisfied"],
            defect_present=item["defect_present"],
            fix_addresses=item["fix_addresses"],
            in_repository_reachable=item["in_repository_reachable"],
            verified_scopes=_verified_scopes(item["verified_scopes"]),
            model_assistance_digest=item["model_assistance_digest"],
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        raise CohortIngestionError(CohortRecordExclusionReason.RECORD_SCHEMA_MISMATCH) from None


def decode_external_record(content: bytes) -> dict[str, Any]:
    """Decode one external review record after hostile-byte validation."""
    return _record_payload(content)


def _review_pair(
    payload: Mapping[str, Any],
    candidate: FixSiteCandidateV1,
    batch: _BatchState,
) -> tuple[RepositoryEcosystemReviewV1, GroundTruthReviewV1]:
    try:
        ecosystem = review_repository_ecosystem(
            candidate,
            _ecosystem_attestation(payload["ecosystem_attestation"]),
            expected_policy_digest=batch.ecosystem_policy_digest,
        )
        review = review_ground_truth(
            candidate,
            ecosystem,
            _ground_truth_attestation(payload["ground_truth_attestation"]),
            expected_ecosystem_policy_digest=batch.ecosystem_policy_digest,
            expected_ground_truth_policy_digest=batch.ground_truth_policy_digest,
        )
    except (EcosystemReviewError, GroundTruthReviewError):
        raise CohortIngestionError(CohortRecordExclusionReason.REVIEW_EVIDENCE_INVALID) from None
    return ecosystem, review


def _excluded(record_digest: str, entry_digest: str | None, reason: str) -> _Reviewed:
    outcome = CohortRecordOutcomeV1(record_digest, entry_digest, None, CohortRecordStatus.EXCLUDED, reason)
    return _Reviewed(outcome, entry_digest, None, None)


def _accepted_outcome(
    record_digest: str,
    entry_digest: str,
    review: GroundTruthReviewV1,
    ecosystem: RepositoryEcosystemReviewV1,
    batch: _BatchState,
) -> _Reviewed:
    projected = AcceptedGroundTruthV1(
        review.change_identity_digest,
        review.candidate_digest,
        review.ecosystem_review_digest,
        review.review_digest,
        review.verified_scopes,
    )
    existing = batch.accepted_by_change.get(review.change_identity_digest)
    if existing is not None and existing != projected:
        return _excluded(record_digest, entry_digest, CohortRecordExclusionReason.CONFLICTING_ACCEPTED_REVIEW.value)
    batch.accepted_by_change[review.change_identity_digest] = projected
    batch.accepted_reviews.append(review)
    outcome = CohortRecordOutcomeV1(record_digest, entry_digest, review.review_digest, CohortRecordStatus.ACCEPTED, None)
    return _Reviewed(outcome, entry_digest, review, ecosystem)


def _review_record(content: bytes, batch: _BatchState) -> _Reviewed:
    record_digest = bytes_digest(content)
    entry_digest: str | None = None
    try:
        payload = _record_payload(content)
        entry_digest = _entry_digest(payload)
        entry = batch.entries.get(entry_digest)
        if entry is None:
            raise CohortIngestionError(CohortRecordExclusionReason.QUEUE_ENTRY_UNKNOWN)
        if entry_digest in batch.answered:
            raise CohortIngestionError(CohortRecordExclusionReason.DUPLICATE_RECORD)
        candidate = batch.candidates_by_digest.get(entry.candidate_digest)
        if candidate is None:
            raise CohortIngestionError(CohortRecordExclusionReason.CANDIDATE_EVIDENCE_MISSING)
        ecosystem, review = _review_pair(payload, candidate, batch)
    except CohortIngestionError as error:
        return _excluded(record_digest, entry_digest, error.reason.value)
    batch.answered.add(entry_digest)
    batch.ecosystem_reviews[ecosystem.review_digest] = ecosystem
    if review.status is GroundTruthStatus.EXCLUDED:
        assert review.exclusion_reason is not None
        outcome = CohortRecordOutcomeV1(
            record_digest, entry_digest, review.review_digest, CohortRecordStatus.EXCLUDED, review.exclusion_reason.value
        )
        return _Reviewed(outcome, entry_digest, review, ecosystem)
    return _accepted_outcome(record_digest, entry_digest, review, ecosystem, batch)


def _batch_status(
    record_count: int,
    accepted_count: int,
    queue_entry_count: int,
    queue_empty_reason: CohortInsufficientReason,
) -> tuple[CohortBatchStatus, CohortInsufficientReason | None]:
    if queue_entry_count == 0:
        return CohortBatchStatus.INSUFFICIENT, queue_empty_reason
    if record_count == 0:
        return CohortBatchStatus.INSUFFICIENT, CohortInsufficientReason.BATCH_EMPTY
    if accepted_count < MINIMUM_ACCEPTED_POSITIVES:
        return CohortBatchStatus.INSUFFICIENT, CohortInsufficientReason.INSUFFICIENT_ACCEPTED_POSITIVES
    return CohortBatchStatus.ACCEPTED, None


def _closed_digest(value: object) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise CohortStateError(CohortStateReason.STATE_MISMATCH)
    return value


def _batch_schema(ecosystem: object) -> str:
    schema = _BATCH_SCHEMA_BY_ECOSYSTEM.get(ecosystem) if isinstance(ecosystem, str) else None
    if schema is None:
        raise CohortStateError(CohortStateReason.STATE_MISMATCH)
    return schema


def cohort_batch_ecosystem(schema_version: object) -> str | None:
    """Map one committed cohort batch schema onto its canonical ecosystem, else None."""
    return _ECOSYSTEM_BY_BATCH_SCHEMA.get(schema_version) if isinstance(schema_version, str) else None


def cohort_batch(
    *,
    ecosystem: str = "python",
    queue_digest: str,
    census_digest: str,
    ecosystem_policy_digest: str,
    ground_truth_policy_digest: str,
    record_outcomes: Iterable[CohortRecordOutcomeV1],
    pending_entries: Iterable[str],
    accepted_positives: Iterable[AcceptedGroundTruthV1],
    status: CohortBatchStatus,
    insufficient_reason: CohortInsufficientReason | None,
) -> CohortBatchOutcomeV1:
    """Assemble one bounded cohort batch bound to its exact queue and census.

    The ecosystem must be one of the canonical cohort ecosystems; a batch for
    an observed language such as TypeScript is a javascript-ecosystem batch.
    """
    if not isinstance(ecosystem, str) or ecosystem not in _BATCH_SCHEMA_BY_ECOSYSTEM:
        raise CohortStateError(CohortStateReason.STATE_MISMATCH)
    if not isinstance(status, CohortBatchStatus):
        raise CohortStateError(CohortStateReason.STATE_MISMATCH)
    accepted_tuple = tuple(accepted_positives)
    if status is CohortBatchStatus.ACCEPTED and (insufficient_reason is not None or len(accepted_tuple) < MINIMUM_ACCEPTED_POSITIVES):
        raise CohortStateError(CohortStateReason.STATE_MISMATCH)
    if status is CohortBatchStatus.INSUFFICIENT and insufficient_reason is None:
        raise CohortStateError(CohortStateReason.STATE_MISMATCH)
    accepted = tuple(sorted(accepted_tuple, key=lambda item: item.change_identity_digest))
    draft = CohortBatchOutcomeV1(
        ecosystem,
        _closed_digest(queue_digest),
        _closed_digest(census_digest),
        _closed_digest(ecosystem_policy_digest),
        _closed_digest(ground_truth_policy_digest),
        tuple(sorted(record_outcomes, key=lambda item: item.record_digest)),
        tuple(sorted({_closed_digest(item) for item in pending_entries})),
        accepted,
        MINIMUM_ACCEPTED_POSITIVES,
        status,
        insufficient_reason,
        "",
    )
    return replace(draft, batch_digest=content_digest(_batch_value(draft, include_digest=False)))


def _record_outcome_value(item: CohortRecordOutcomeV1) -> dict[str, JsonValue]:
    return {
        "record_digest": item.record_digest,
        "queue_entry_digest": item.queue_entry_digest,
        "ground_truth_review_digest": item.ground_truth_review_digest,
        "status": item.status.value,
        "reason": item.reason,
    }


def _scope_values(scopes: tuple[VerifiedScope, ...]) -> tuple[dict[str, JsonValue], ...]:
    return tuple(
        {"vulnerability_family": scope.vulnerability_family, "ecosystem": scope.ecosystem.value} for scope in scopes
    )


def _accepted_value(item: AcceptedGroundTruthV1) -> dict[str, JsonValue]:
    return {
        "change_identity_digest": item.change_identity_digest,
        "candidate_digest": item.candidate_digest,
        "ecosystem_review_digest": item.ecosystem_review_digest,
        "ground_truth_review_digest": item.ground_truth_review_digest,
        "verified_scopes": _scope_values(item.verified_scopes),
    }


def cohort_batch_value(outcome: CohortBatchOutcomeV1) -> dict[str, JsonValue]:
    """Canonical batch payload used for durable persistence and exact rereads."""
    return {
        "schema_version": _batch_schema(outcome.ecosystem),
        "ecosystem": outcome.ecosystem,
        "queue_digest": outcome.queue_digest,
        "census_digest": outcome.census_digest,
        "ecosystem_policy_digest": outcome.ecosystem_policy_digest,
        "ground_truth_policy_digest": outcome.ground_truth_policy_digest,
        "record_outcomes": tuple(_record_outcome_value(item) for item in outcome.record_outcomes),
        "pending_entries": outcome.pending_entries,
        "accepted_positives": tuple(_accepted_value(item) for item in outcome.accepted_positives),
        "minimum_accepted_positives": outcome.minimum_accepted_positives,
        "status": outcome.status.value,
        "insufficient_reason": outcome.insufficient_reason.value if outcome.insufficient_reason is not None else None,
        "batch_digest": outcome.batch_digest,
    }


def _batch_value(outcome: CohortBatchOutcomeV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value = cohort_batch_value(outcome)
    if not include_digest:
        value.pop("batch_digest")
    return value


def cohort_batch_bytes(outcome: CohortBatchOutcomeV1) -> bytes:
    """Encode a digest-consistent batch outcome as canonical bytes."""
    if outcome.batch_digest != content_digest(_batch_value(outcome, include_digest=False)):
        raise CohortStateError(CohortStateReason.STATE_MISMATCH)
    return canonical_bytes(cohort_batch_value(outcome))


def _refused_batch(
    queue: EcosystemReviewQueueV1,
    census_digest: str,
    ecosystem: str,
    ordered: Sequence[bytes],
    batch: _BatchState,
) -> CohortBatchOutcomeV1:
    outcomes = [
        CohortRecordOutcomeV1(
            bytes_digest(content), None, None, CohortRecordStatus.EXCLUDED, CohortRecordExclusionReason.BATCH_UNIT_REFUSED.value
        )
        for content in ordered
    ]
    return cohort_batch(
        ecosystem=ecosystem,
        queue_digest=queue.queue_digest,
        census_digest=census_digest,
        ecosystem_policy_digest=batch.ecosystem_policy_digest,
        ground_truth_policy_digest=batch.ground_truth_policy_digest,
        record_outcomes=outcomes,
        pending_entries=tuple(batch.entries),
        accepted_positives=(),
        status=CohortBatchStatus.INSUFFICIENT,
        insufficient_reason=CohortInsufficientReason.BATCH_CAP_EXCEEDED,
    )


def _ingest_cohort_batch(
    records: Sequence[bytes],
    *,
    queue: EcosystemReviewQueueV1,
    census_digest: str,
    ecosystem: str,
    queue_empty_reason: CohortInsufficientReason,
    candidates_by_digest: Mapping[str, FixSiteCandidateV1],
    expected_ecosystem_policy_digest: str,
    expected_ground_truth_policy_digest: str,
) -> CohortBatchOutcomeV1:
    """Ingest one supplied batch of at most twenty external review records."""
    for content in records:
        if not isinstance(content, bytes):
            raise ValueError("external review records must be supplied as bytes")
    batch = _BatchState(
        {entry.entry_digest: entry for entry in queue.entries},
        candidates_by_digest,
        expected_ecosystem_policy_digest,
        expected_ground_truth_policy_digest,
    )
    ordered = tuple(sorted(records, key=bytes_digest))
    if len(ordered) > COHORT_BATCH_CAP:
        return _refused_batch(queue, census_digest, ecosystem, ordered, batch)
    for content in ordered:
        batch.outcomes.append(_review_record(content, batch).outcome)
    try:
        accepted_positives = project_accepted_ground_truth(
            batch.accepted_reviews,
            candidates_by_digest=candidates_by_digest,
            ecosystem_reviews_by_digest=dict(batch.ecosystem_reviews),
            expected_ecosystem_policy_digest=expected_ecosystem_policy_digest,
            expected_ground_truth_policy_digest=expected_ground_truth_policy_digest,
        )
    except GroundTruthReviewError:
        raise CohortStateError(CohortStateReason.STATE_MISMATCH) from None
    status, reason = _batch_status(len(ordered), len(accepted_positives), len(batch.entries), queue_empty_reason)
    return cohort_batch(
        ecosystem=ecosystem,
        queue_digest=queue.queue_digest,
        census_digest=census_digest,
        ecosystem_policy_digest=expected_ecosystem_policy_digest,
        ground_truth_policy_digest=expected_ground_truth_policy_digest,
        record_outcomes=batch.outcomes,
        pending_entries=sorted(batch.entries.keys() - batch.answered),
        accepted_positives=accepted_positives,
        status=status,
        insufficient_reason=reason,
    )


def ingest_python_cohort_batch(
    records: Sequence[bytes],
    *,
    state: SourcingQueueStateV1,
    candidates_by_digest: Mapping[str, FixSiteCandidateV1],
    expected_ecosystem_policy_digest: str,
    expected_ground_truth_policy_digest: str,
) -> CohortBatchOutcomeV1:
    """Ingest one supplied batch of at most twenty external Python review records."""
    return _ingest_cohort_batch(
        records,
        queue=state.python_queue,
        census_digest=state.census_digest,
        ecosystem="python",
        queue_empty_reason=CohortInsufficientReason.PYTHON_QUEUE_EMPTY,
        candidates_by_digest=candidates_by_digest,
        expected_ecosystem_policy_digest=expected_ecosystem_policy_digest,
        expected_ground_truth_policy_digest=expected_ground_truth_policy_digest,
    )


def ingest_javascript_cohort_batch(
    records: Sequence[bytes],
    *,
    state: SourcingQueueStateV1,
    candidates_by_digest: Mapping[str, FixSiteCandidateV1],
    expected_ecosystem_policy_digest: str,
    expected_ground_truth_policy_digest: str,
) -> CohortBatchOutcomeV1:
    """Ingest one supplied JavaScript/TypeScript review batch under the canonical javascript ecosystem.

    TypeScript arrives only as observed language evidence on queue entries; the
    cohort itself stays bound to the javascript ecosystem and its batch schema.
    """
    return _ingest_cohort_batch(
        records,
        queue=state.javascript_queue,
        census_digest=state.census_digest,
        ecosystem="javascript",
        queue_empty_reason=CohortInsufficientReason.JAVASCRIPT_QUEUE_EMPTY,
        candidates_by_digest=candidates_by_digest,
        expected_ecosystem_policy_digest=expected_ecosystem_policy_digest,
        expected_ground_truth_policy_digest=expected_ground_truth_policy_digest,
    )


__all__ = [
    "COHORT_BATCH_CAP",
    "COHORT_BATCH_SCHEMA",
    "CohortBatchOutcomeV1",
    "CohortBatchStatus",
    "CohortIngestionError",
    "CohortInsufficientReason",
    "CohortRecordExclusionReason",
    "CohortRecordOutcomeV1",
    "CohortRecordStatus",
    "CohortStateError",
    "CohortStateReason",
    "EXTERNAL_REVIEW_RECORD_SCHEMA",
    "JAVASCRIPT_COHORT_BATCH_SCHEMA",
    "MINIMUM_ACCEPTED_POSITIVES",
    "cohort_batch",
    "cohort_batch_bytes",
    "cohort_batch_ecosystem",
    "cohort_batch_value",
    "decode_external_record",
    "ingest_javascript_cohort_batch",
    "ingest_python_cohort_batch",
]
