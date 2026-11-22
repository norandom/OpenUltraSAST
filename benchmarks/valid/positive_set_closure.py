"""Combined closure of the replacement positive set over durable cohort ledgers.

The closure projection reads only accepted review evidence already recorded on
cohort batch outcomes: families, ecosystems, and positive counts are facts of
recorded human reviews. Every accepted positive is reachable by construction
because acceptance exists only through the committed review machinery, which
requires the in-repository reachability judgment; no scope is granted here and
an unverified family or ecosystem stays impossible without a new external
review record.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum

from benchmarks.valid.cohort_ingestion import (
    CohortBatchOutcomeV1,
    CohortBatchStatus,
    CohortStateError,
    cohort_batch_bytes,
)
from benchmarks.valid.cohort_selection import COHORT_SELECTION_ECOSYSTEMS, REQUIRED_DISTINCT_FAMILIES
from benchmarks.valid.ground_truth_review import AcceptedGroundTruthV1
from openultrasast.core.canonical import JsonValue, canonical_bytes, content_digest

POSITIVE_SET_CLOSURE_SCHEMA = "openultrasast.valid-detection-benchmark.positive-set-closure.v1"
COMBINED_POSITIVE_FLOOR = 40
_DIGEST = re.compile(r"[0-9a-f]{64}")
_FAMILY = re.compile(r"[a-z0-9][a-z0-9_]{0,127}")


class PositiveSetClosureStatus(StrEnum):
    CLOSED = "closed"
    INSUFFICIENT = "insufficient"


class PositiveSetClosureReason(StrEnum):
    """Closed decision vocabulary naming which closure gate closed or failed."""

    ALL_GAPS_CLOSED = "all_gaps_closed"
    NO_ACCEPTED_BATCHES = "no_accepted_batches"
    INSUFFICIENT_TOTAL_POSITIVES = "insufficient_total_positives"
    MISSING_ECOSYSTEM = "missing_ecosystem"
    INSUFFICIENT_FAMILIES = "insufficient_families"


_INSUFFICIENCY_REASONS = frozenset(
    {
        PositiveSetClosureReason.NO_ACCEPTED_BATCHES,
        PositiveSetClosureReason.INSUFFICIENT_TOTAL_POSITIVES,
        PositiveSetClosureReason.MISSING_ECOSYSTEM,
        PositiveSetClosureReason.INSUFFICIENT_FAMILIES,
    }
)


class PositiveSetClosureStateReason(StrEnum):
    STATE_UNREADABLE = "state_unreadable"
    STATE_MISMATCH = "state_mismatch"


_STATE_REASON_TEXT = {
    PositiveSetClosureStateReason.STATE_UNREADABLE: "positive set closure bytes are unreadable",
    PositiveSetClosureStateReason.STATE_MISMATCH: "positive set closure state does not match its canonical schema",
}


class PositiveSetClosureStateError(ValueError):
    """Closed closure refusal carrying one structural reason."""

    def __init__(self, reason: PositiveSetClosureStateReason) -> None:
        self.reason = reason
        super().__init__(_STATE_REASON_TEXT[reason])


def _mismatch() -> PositiveSetClosureStateError:
    return PositiveSetClosureStateError(PositiveSetClosureStateReason.STATE_MISMATCH)


@dataclass(frozen=True)
class PositiveSetClosureV1:
    batch_digests: tuple[str, ...]
    accepted_batch_digests: tuple[str, ...]
    total_accepted_positives: int
    positives_by_ecosystem: tuple[tuple[str, int], ...]
    accepted_families: tuple[str, ...]
    status: PositiveSetClosureStatus
    reason: PositiveSetClosureReason
    closure_digest: str

    def __post_init__(self) -> None:
        _validate_closure(self)


@dataclass(frozen=True)
class _ClosureFacts:
    batch_digests: tuple[str, ...]
    accepted_batch_digests: tuple[str, ...]
    families: tuple[str, ...]
    counts: tuple[tuple[str, int], ...]
    total: int


def _closed_digest(value: object) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise _mismatch()
    return value


def _closed_vocabulary(values: object, pattern: re.Pattern[str]) -> tuple[str, ...]:
    if not isinstance(values, tuple) or not all(isinstance(item, str) for item in values):
        raise _mismatch()
    ordered = tuple(sorted(set(values)))
    if ordered != values or any(pattern.fullmatch(item) is None for item in ordered):
        raise _mismatch()
    return values


def _closed_counts(pairs: object) -> tuple[tuple[str, int], ...]:
    if not isinstance(pairs, tuple) or tuple(ecosystem for ecosystem, _ in pairs) != COHORT_SELECTION_ECOSYSTEMS:
        raise _mismatch()
    for _, count in pairs:
        if type(count) is not int or count < 0:
            raise _mismatch()
    return pairs


def _gates(item: PositiveSetClosureV1) -> tuple[bool, bool, bool]:
    total_ok = item.total_accepted_positives >= COMBINED_POSITIVE_FLOOR
    ecosystems_ok = all(count > 0 for _, count in item.positives_by_ecosystem)
    families_ok = len(item.accepted_families) >= REQUIRED_DISTINCT_FAMILIES
    return total_ok, ecosystems_ok, families_ok


def _validate_closure(item: PositiveSetClosureV1) -> None:
    if not isinstance(item.status, PositiveSetClosureStatus) or not isinstance(item.reason, PositiveSetClosureReason):
        raise _mismatch()
    if item.closure_digest:
        _closed_digest(item.closure_digest)
    _closed_vocabulary(item.batch_digests, _DIGEST)
    _closed_vocabulary(item.accepted_batch_digests, _DIGEST)
    if not set(item.accepted_batch_digests) <= set(item.batch_digests):
        raise _mismatch()
    _closed_vocabulary(item.accepted_families, _FAMILY)
    _closed_counts(item.positives_by_ecosystem)
    if item.total_accepted_positives < 0 or item.total_accepted_positives != sum(
        count for _, count in item.positives_by_ecosystem
    ):
        raise _mismatch()
    if bool(item.accepted_batch_digests) != (item.total_accepted_positives > 0):
        raise _mismatch()
    total_ok, ecosystems_ok, families_ok = _gates(item)
    if item.status is PositiveSetClosureStatus.CLOSED:
        if item.reason is not PositiveSetClosureReason.ALL_GAPS_CLOSED or not (total_ok and ecosystems_ok and families_ok):
            raise _mismatch()
    else:
        if item.reason not in _INSUFFICIENCY_REASONS or (total_ok and ecosystems_ok and families_ok):
            raise _mismatch()
        if item.reason is PositiveSetClosureReason.NO_ACCEPTED_BATCHES and item.total_accepted_positives != 0:
            raise _mismatch()


def _count_value(pairs: tuple[tuple[str, int], ...]) -> tuple[dict[str, JsonValue], ...]:
    return tuple({"ecosystem": ecosystem, "accepted_positives": count} for ecosystem, count in pairs)


def _closure_value(item: PositiveSetClosureV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": POSITIVE_SET_CLOSURE_SCHEMA,
        "batch_digests": item.batch_digests,
        "accepted_batch_digests": item.accepted_batch_digests,
        "total_accepted_positives": item.total_accepted_positives,
        "positives_by_ecosystem": _count_value(item.positives_by_ecosystem),
        "accepted_families": item.accepted_families,
        "status": item.status.value,
        "reason": item.reason.value,
    }
    if include_digest:
        value["closure_digest"] = item.closure_digest
    return value


def positive_set_closure_value(item: PositiveSetClosureV1) -> dict[str, JsonValue]:
    """Canonical closure payload used for durable persistence and exact rereads."""
    return _closure_value(item, include_digest=True)


def positive_set_closure_bytes(item: PositiveSetClosureV1) -> bytes:
    """Encode a digest-consistent closure decision as canonical bytes."""
    if item.closure_digest != content_digest(_closure_value(item, include_digest=False)):
        raise _mismatch()
    return canonical_bytes(positive_set_closure_value(item))


def positive_set_closure(
    *,
    batch_digests: Iterable[str],
    accepted_batch_digests: Iterable[str],
    total_accepted_positives: int,
    positives_by_ecosystem: Mapping[str, int],
    accepted_families: Iterable[str],
    status: PositiveSetClosureStatus,
    reason: PositiveSetClosureReason,
) -> PositiveSetClosureV1:
    """Assemble one durable closure decision bound to its exact ledger facts."""
    try:
        counts = tuple((ecosystem, positives_by_ecosystem[ecosystem]) for ecosystem in COHORT_SELECTION_ECOSYSTEMS)
        draft = PositiveSetClosureV1(
            tuple(sorted(set(batch_digests))),
            tuple(sorted(set(accepted_batch_digests))),
            total_accepted_positives,
            counts,
            tuple(sorted(set(accepted_families))),
            status,
            reason,
            "",
        )
    except PositiveSetClosureStateError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise PositiveSetClosureStateError(PositiveSetClosureStateReason.STATE_MISMATCH) from error
    return replace(draft, closure_digest=content_digest(_closure_value(draft, include_digest=False)))


def _require_replayable(batch: CohortBatchOutcomeV1) -> None:
    """Prove one ledger batch re-encodes to its recorded digest before use."""
    try:
        cohort_batch_bytes(batch)
        for positive in batch.accepted_positives:
            if not positive.verified_scopes:
                raise _mismatch()
            for scope in positive.verified_scopes:
                if scope.ecosystem.value != batch.ecosystem:
                    raise _mismatch()
    except PositiveSetClosureStateError:
        raise
    except (CohortStateError, AttributeError, KeyError, TypeError, ValueError) as error:
        raise PositiveSetClosureStateError(PositiveSetClosureStateReason.STATE_MISMATCH) from error


def _closure_facts(batches: Sequence[CohortBatchOutcomeV1]) -> _ClosureFacts:
    """Derive combined facts from replay-verified accepted cohort evidence."""
    digests: set[str] = set()
    accepted_digests: set[str] = set()
    families: set[str] = set()
    counts = {ecosystem: 0 for ecosystem in COHORT_SELECTION_ECOSYSTEMS}
    by_change: dict[str, AcceptedGroundTruthV1] = {}
    for batch in batches:
        _require_replayable(batch)
        digests.add(_closed_digest(batch.batch_digest))
        if batch.status is not CohortBatchStatus.ACCEPTED:
            continue
        accepted_digests.add(batch.batch_digest)
        for positive in batch.accepted_positives:
            existing = by_change.get(positive.change_identity_digest)
            if existing is not None and existing != positive:
                raise _mismatch()
            if existing is None:
                by_change[positive.change_identity_digest] = positive
                counts[batch.ecosystem] += 1
            for scope in positive.verified_scopes:
                families.add(scope.vulnerability_family)
    return _ClosureFacts(
        tuple(sorted(digests)),
        tuple(sorted(accepted_digests)),
        tuple(sorted(families)),
        tuple((ecosystem, counts[ecosystem]) for ecosystem in COHORT_SELECTION_ECOSYSTEMS),
        len(by_change),
    )


def _closure_reason(facts: _ClosureFacts) -> PositiveSetClosureReason:
    if not facts.accepted_batch_digests:
        return PositiveSetClosureReason.NO_ACCEPTED_BATCHES
    if facts.total < COMBINED_POSITIVE_FLOOR:
        return PositiveSetClosureReason.INSUFFICIENT_TOTAL_POSITIVES
    if any(count == 0 for _, count in facts.counts):
        return PositiveSetClosureReason.MISSING_ECOSYSTEM
    if len(facts.families) < REQUIRED_DISTINCT_FAMILIES:
        return PositiveSetClosureReason.INSUFFICIENT_FAMILIES
    return PositiveSetClosureReason.ALL_GAPS_CLOSED


def project_positive_set_closure(batches: Sequence[CohortBatchOutcomeV1]) -> PositiveSetClosureV1:
    """Close the combined positive set over durable accepted cohort ledgers.

    Only accepted ingestion units contribute positives: an insufficient batch
    is a refused unit whose partial records never lower the closure bar. A
    gap-remaining set stays insufficient with a closed reason instead of being
    reported closed.
    """
    try:
        facts = _closure_facts(batches)
    except PositiveSetClosureStateError:
        raise
    except (AttributeError, TypeError, ValueError) as error:
        raise PositiveSetClosureStateError(PositiveSetClosureStateReason.STATE_MISMATCH) from error
    reason = _closure_reason(facts)
    if reason is PositiveSetClosureReason.ALL_GAPS_CLOSED:
        status = PositiveSetClosureStatus.CLOSED
    else:
        status = PositiveSetClosureStatus.INSUFFICIENT
    return positive_set_closure(
        batch_digests=facts.batch_digests,
        accepted_batch_digests=facts.accepted_batch_digests,
        total_accepted_positives=facts.total,
        positives_by_ecosystem=dict(facts.counts),
        accepted_families=facts.families,
        status=status,
        reason=reason,
    )


__all__ = [
    "COMBINED_POSITIVE_FLOOR",
    "POSITIVE_SET_CLOSURE_SCHEMA",
    "PositiveSetClosureReason",
    "PositiveSetClosureStateError",
    "PositiveSetClosureStateReason",
    "PositiveSetClosureStatus",
    "PositiveSetClosureV1",
    "positive_set_closure",
    "positive_set_closure_bytes",
    "positive_set_closure_value",
    "project_positive_set_closure",
]
