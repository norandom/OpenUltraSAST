"""Deterministic first-parent ordinary-change draws for the closed positive set.

The draw consumes only the durable accepted cohort ledgers whose combined
closure is closed, the reviewed reservation census, and committed exclusion
evidence. Each accepted positive receives its own first-parent ordinary walk
below the exact vulnerable parent, with the fixes and every reviewed
contaminated or excluded change refused by a closed rule before any count is
accepted. No detector observation or admission label is ever opened here.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from benchmarks.valid.cohort_ingestion import CohortBatchOutcomeV1, CohortBatchStatus
from benchmarks.valid.ecosystem_review import CanonicalEcosystem
from benchmarks.valid.fix_site_catalog import FixSiteCandidateV1
from benchmarks.valid.ground_truth_review import GroundTruthReviewV1, GroundTruthStatus
from benchmarks.valid.ordinary_change_contract import (
    ContaminationTiming,
    OrdinaryContaminationReviewV1,
    OrdinaryDrawAssignmentV1,
    OrdinaryExclusionReason,
    OrdinaryExclusionV1,
    OrdinaryFixExclusionV1,
    OrdinaryPushV1,
    _digest,
    _push_value,
    _revision,
    contamination_review_bytes,
)
from benchmarks.valid.ordinary_draw_contract import (
    MINIMUM_ORDINARY_PER_POSITIVE,
    OrdinaryDrawError,
    OrdinaryDrawProvenanceV1,
    OrdinaryDrawReason,
    OrdinaryDrawRule,
    OrdinaryPopulationDrawV1,
    OrdinaryPopulationHistorySource,
    OrdinaryRepositoryReceiptV1,
    ordinary_population_draw,
)
from benchmarks.valid.positive_set_closure import (
    PositiveSetClosureStateError,
    PositiveSetClosureStatus,
    project_positive_set_closure,
)
from benchmarks.valid.reservation import ReservationCensusV1, ReservationError, census_bytes
from openultrasast.core.canonical import bytes_digest, content_digest


def _refused(reason: OrdinaryDrawReason, detail: str = "") -> OrdinaryDrawError:
    return OrdinaryDrawError(reason, detail)


@dataclass(frozen=True)
class _PositiveFacts:
    change_identity_digest: str
    candidate_digest: str
    ground_truth_review_digest: str
    canonical_repository: str
    network_identity_digest: str
    vulnerable_revision: str
    fixed_revision: str
    ecosystem: CanonicalEcosystem


def _positive_facts(
    batches: Sequence[CohortBatchOutcomeV1],
    candidates_by_digest: Mapping[str, FixSiteCandidateV1],
) -> tuple[_PositiveFacts, ...]:
    """Derive per-positive repository facts only from accepted ledger evidence."""
    by_change: dict[str, _PositiveFacts] = {}
    try:
        for batch in batches:
            if batch.status is not CohortBatchStatus.ACCEPTED:
                continue
            ecosystem = CanonicalEcosystem(batch.ecosystem)
            for positive in batch.accepted_positives:
                candidate = candidates_by_digest.get(positive.candidate_digest)
                if candidate is None:
                    raise _refused(OrdinaryDrawReason.CANDIDATE_MISSING)
                fact = _PositiveFacts(
                    positive.change_identity_digest,
                    positive.candidate_digest,
                    positive.ground_truth_review_digest,
                    candidate.canonical_repository,
                    candidate.network_identity_digest,
                    candidate.vulnerable.revision,
                    candidate.fixed.revision,
                    ecosystem,
                )
                existing = by_change.setdefault(fact.change_identity_digest, fact)
                if existing != fact:
                    raise _refused(OrdinaryDrawReason.INVALID_REQUEST)
    except OrdinaryDrawError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise _refused(OrdinaryDrawReason.INVALID_REQUEST) from error
    return tuple(sorted(by_change.values(), key=lambda fact: fact.change_identity_digest))


def _require_single_ecosystem(facts: Sequence[_PositiveFacts]) -> None:
    seen: dict[str, CanonicalEcosystem] = {}
    for fact in facts:
        existing = seen.setdefault(fact.network_identity_digest, fact.ecosystem)
        if existing != fact.ecosystem:
            raise _refused(OrdinaryDrawReason.ECOSYSTEM_SPLIT)


def _require_unreserved(facts: Sequence[_PositiveFacts], census: ReservationCensusV1) -> None:
    reserved = set(census.reserved_network_digests)
    for fact in facts:
        if fact.network_identity_digest in reserved:
            raise _refused(OrdinaryDrawReason.RESERVED_REPOSITORY)


def _contamination_index(reviews: Iterable[OrdinaryContaminationReviewV1]) -> dict[tuple[str, str], OrdinaryContaminationReviewV1]:
    index: dict[tuple[str, str], OrdinaryContaminationReviewV1] = {}
    for review in reviews:
        try:
            contamination_review_bytes(review)
        except (AttributeError, KeyError, TypeError, ValueError) as error:
            raise _refused(OrdinaryDrawReason.INVALID_REQUEST) from error
        if review.timing is not ContaminationTiming.PRE_FREEZE:
            raise _refused(OrdinaryDrawReason.POST_FREEZE_CONTAMINATION)
        key = (review.network_identity_digest, review.tip_revision)
        existing = index.get(key)
        if existing is not None and existing != review:
            raise _refused(OrdinaryDrawReason.CONFLICTING_EXCLUSION_EVIDENCE)
        index[key] = review
    return index


def _excluded_review_index(reviews: Iterable[GroundTruthReviewV1]) -> dict[tuple[str, str], str]:
    index: dict[tuple[str, str], str] = {}
    for review in reviews:
        try:
            if review.status is not GroundTruthStatus.EXCLUDED or review.exclusion_reason is None:
                raise TypeError("excluded review required")
            _digest(review.network_identity_digest, "review network identity digest")
            _digest(review.review_digest, "review digest")
            for revision in (review.vulnerable_revision, review.fixed_revision):
                _revision(revision, "reviewed revision")
        except (AttributeError, KeyError, TypeError, ValueError) as error:
            raise _refused(OrdinaryDrawReason.INVALID_REQUEST) from error
        for revision in (review.vulnerable_revision, review.fixed_revision):
            key = (review.network_identity_digest, revision)
            existing = index.get(key)
            if existing is not None and existing != review.review_digest:
                raise _refused(OrdinaryDrawReason.CONFLICTING_EXCLUSION_EVIDENCE)
            index[key] = review.review_digest
    return index


def _fix_ledger(facts: Sequence[_PositiveFacts]) -> tuple[tuple[OrdinaryFixExclusionV1, ...], dict[tuple[str, str], str]]:
    exclusions: set[OrdinaryFixExclusionV1] = set()
    keys: dict[tuple[str, str], str] = {}
    for fact in facts:
        exclusion = OrdinaryFixExclusionV1(
            fact.network_identity_digest,
            fact.fixed_revision,
            fact.change_identity_digest,
            fact.ground_truth_review_digest,
        )
        exclusions.add(exclusion)
        keys[(fact.network_identity_digest, fact.fixed_revision)] = fact.ground_truth_review_digest
    ordered = tuple(sorted(exclusions))
    if len(ordered) != len(facts):
        raise _refused(OrdinaryDrawReason.INVALID_REQUEST)
    return ordered, keys


def _sources_and_receipts(
    facts: Sequence[_PositiveFacts],
    history_by_network: Mapping[str, OrdinaryPopulationHistorySource],
) -> tuple[dict[str, OrdinaryPopulationHistorySource], tuple[OrdinaryRepositoryReceiptV1, ...]]:
    sources: dict[str, OrdinaryPopulationHistorySource] = {}
    receipts: dict[str, OrdinaryRepositoryReceiptV1] = {}
    for fact in facts:
        source = history_by_network.get(fact.network_identity_digest)
        if source is None:
            raise _refused(OrdinaryDrawReason.INVALID_REQUEST)
        if (source.canonical_repository, source.network_identity_digest) != (
            fact.canonical_repository,
            fact.network_identity_digest,
        ):
            raise _refused(OrdinaryDrawReason.INVALID_REQUEST)
        try:
            _digest(source.source_digest, "history source digest")
        except (AttributeError, TypeError, ValueError) as error:
            raise _refused(OrdinaryDrawReason.INVALID_REQUEST) from error
        sources[fact.network_identity_digest] = source
        if fact.network_identity_digest not in receipts:
            manifest = source.reader.repository_bytes(fact.canonical_repository)
            if not isinstance(manifest, bytes) or not manifest:
                raise _refused(OrdinaryDrawReason.REPOSITORY_UNREADABLE)
            receipts[fact.network_identity_digest] = OrdinaryRepositoryReceiptV1(
                fact.canonical_repository,
                fact.network_identity_digest,
                len(manifest),
                bytes_digest(manifest),
            )
    return sources, tuple(sorted(receipts.values()))


def _ordinary_push(
    fact: _PositiveFacts,
    source: OrdinaryPopulationHistorySource,
    base: str,
    tip: str,
    content: bytes,
) -> OrdinaryPushV1:
    try:
        draft = OrdinaryPushV1(
            fact.canonical_repository,
            fact.network_identity_digest,
            fact.ecosystem,
            base,
            tip,
            len(content),
            bytes_digest(content),
            source.source_digest,
            "",
        )
        return OrdinaryPushV1(**{**vars(draft), "push_digest": content_digest(_push_value(draft, include_digest=False))})
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise _refused(OrdinaryDrawReason.INVALID_REQUEST) from error


def _row(network: str, tip: str, rule: OrdinaryDrawRule, evidence: str) -> OrdinaryDrawProvenanceV1:
    return OrdinaryDrawProvenanceV1(network, tip, rule, evidence)


def _first_parent(value: object) -> str:
    try:
        return _revision(value, "ordinary first parent")
    except (AttributeError, TypeError, ValueError) as error:
        raise _refused(OrdinaryDrawReason.HISTORY_UNREADABLE) from error


def _consider_tip(
    fact: _PositiveFacts,
    source: OrdinaryPopulationHistorySource,
    base: str,
    tip: str,
    *,
    fix_keys: Mapping[tuple[str, str], str],
    contamination: Mapping[tuple[str, str], OrdinaryContaminationReviewV1],
    excluded_reviews: Mapping[tuple[str, str], str],
) -> tuple[OrdinaryPushV1 | None, OrdinaryDrawProvenanceV1, OrdinaryExclusionV1 | None]:
    network = fact.network_identity_digest
    key = (network, tip)
    if key in fix_keys:
        return None, _row(network, tip, OrdinaryDrawRule.EXCLUDED_ACCEPTED_FIX, fix_keys[key]), None
    content = source.reader.change_bytes(tip)
    if not isinstance(content, bytes) or not content:
        raise _refused(OrdinaryDrawReason.HISTORY_UNREADABLE)
    review = contamination.get(key)
    excluded = excluded_reviews.get(key)
    if review is not None and excluded is not None:
        raise _refused(OrdinaryDrawReason.CONFLICTING_EXCLUSION_EVIDENCE)
    if review is not None:
        exclusion = OrdinaryExclusionV1(network, tip, OrdinaryExclusionReason.REVIEWED_SECURITY_DEFECT, review.review_digest)
        return None, _row(network, tip, OrdinaryDrawRule.EXCLUDED_REVIEWED_CONTAMINATION, review.review_digest), exclusion
    if excluded is not None:
        return None, _row(network, tip, OrdinaryDrawRule.EXCLUDED_REVIEWED_CHANGE, excluded), None
    push = _ordinary_push(fact, source, base, tip, content)
    return push, _row(network, tip, OrdinaryDrawRule.ELIGIBLE_FIRST_PARENT_ORDINARY, push.push_digest), None


def _walk_positive(
    fact: _PositiveFacts,
    source: OrdinaryPopulationHistorySource,
    *,
    fix_keys: Mapping[tuple[str, str], str],
    contamination: Mapping[tuple[str, str], OrdinaryContaminationReviewV1],
    excluded_reviews: Mapping[tuple[str, str], str],
    required: int,
) -> tuple[list[OrdinaryPushV1], set[OrdinaryDrawProvenanceV1], set[OrdinaryExclusionV1]]:
    parents = tuple(source.reader.parents(fact.fixed_revision))
    if not parents or parents[0] != fact.vulnerable_revision:
        raise _refused(OrdinaryDrawReason.HISTORY_UNBOUND)
    pushes: list[OrdinaryPushV1] = []
    provenance: set[OrdinaryDrawProvenanceV1] = set()
    exclusions: set[OrdinaryExclusionV1] = set()
    tip = fact.vulnerable_revision
    seen = {fact.fixed_revision}
    while len(pushes) < required:
        if tip in seen:
            raise _refused(OrdinaryDrawReason.INVALID_REQUEST)
        seen.add(tip)
        ancestors = tuple(source.reader.parents(tip))
        if not ancestors:
            break
        base = _first_parent(ancestors[0])
        push, row, exclusion = _consider_tip(
            fact,
            source,
            base,
            tip,
            fix_keys=fix_keys,
            contamination=contamination,
            excluded_reviews=excluded_reviews,
        )
        if push is not None:
            pushes.append(push)
        if exclusion is not None:
            exclusions.add(exclusion)
        provenance.add(row)
        tip = base
    if len(pushes) < required:
        raise _refused(OrdinaryDrawReason.INSUFFICIENT_HISTORY, f" supplies {len(pushes)} of {required}")
    return pushes, provenance, exclusions


def _collect_draws(
    facts: Sequence[_PositiveFacts],
    sources: Mapping[str, OrdinaryPopulationHistorySource],
    *,
    fix_keys: Mapping[tuple[str, str], str],
    contamination: Mapping[tuple[str, str], OrdinaryContaminationReviewV1],
    excluded_reviews: Mapping[tuple[str, str], str],
    required: int,
) -> tuple[dict[str, OrdinaryPushV1], set[OrdinaryDrawAssignmentV1], set[OrdinaryDrawProvenanceV1], set[OrdinaryExclusionV1]]:
    pushes_by_digest: dict[str, OrdinaryPushV1] = {}
    assignments: set[OrdinaryDrawAssignmentV1] = set()
    provenance: set[OrdinaryDrawProvenanceV1] = set()
    exclusions: set[OrdinaryExclusionV1] = set()
    for fact in facts:
        drawn, rows, excluded = _walk_positive(
            fact,
            sources[fact.network_identity_digest],
            fix_keys=fix_keys,
            contamination=contamination,
            excluded_reviews=excluded_reviews,
            required=required,
        )
        for push in drawn:
            existing = pushes_by_digest.get(push.push_digest)
            if existing is not None and existing != push:
                raise _refused(OrdinaryDrawReason.INVALID_REQUEST)
            pushes_by_digest[push.push_digest] = push
            assignments.add(
                OrdinaryDrawAssignmentV1(fact.change_identity_digest, fact.network_identity_digest, fact.ecosystem, push.push_digest)
            )
        provenance.update(rows)
        exclusions.update(excluded)
    supplied = {review.review_digest for review in contamination.values()}
    applied = {row.contamination_review_digest for row in exclusions}
    if supplied != applied:
        raise _refused(OrdinaryDrawReason.CONFLICTING_EXCLUSION_EVIDENCE)
    return pushes_by_digest, assignments, provenance, exclusions


def draw_ordinary_population(
    batches: Sequence[CohortBatchOutcomeV1],
    *,
    candidates_by_digest: Mapping[str, FixSiteCandidateV1],
    history_by_network: Mapping[str, OrdinaryPopulationHistorySource],
    contamination_reviews: Iterable[OrdinaryContaminationReviewV1] = (),
    excluded_reviews: Iterable[GroundTruthReviewV1] = (),
    reservation_census: ReservationCensusV1,
    required_per_positive: int = MINIMUM_ORDINARY_PER_POSITIVE,
    policy_digest: str,
) -> OrdinaryPopulationDrawV1:
    """Draw the ordinary population for every accepted positive of a closed set.

    The draw is label-blind and detector-blind by construction: only durable
    accepted ledger facts, reviewed exclusion evidence, the reservation census,
    and readable nonzero first-parent histories enter the walk.
    """
    if type(required_per_positive) is not int or required_per_positive < MINIMUM_ORDINARY_PER_POSITIVE:
        raise _refused(OrdinaryDrawReason.INVALID_REQUEST)
    try:
        census_bytes(reservation_census)
        policy = _digest(policy_digest, "ordinary population draw policy digest")
    except (AttributeError, ReservationError, TypeError, ValueError) as error:
        raise _refused(OrdinaryDrawReason.INVALID_REQUEST) from error
    try:
        closure = project_positive_set_closure(batches)
    except PositiveSetClosureStateError as error:
        raise _refused(OrdinaryDrawReason.INVALID_REQUEST) from error
    if closure.status is not PositiveSetClosureStatus.CLOSED:
        raise _refused(OrdinaryDrawReason.POSITIVE_SET_NOT_CLOSED)
    facts = _positive_facts(batches, candidates_by_digest)
    _require_single_ecosystem(facts)
    _require_unreserved(facts, reservation_census)
    contamination = _contamination_index(contamination_reviews)
    excluded_index = _excluded_review_index(excluded_reviews)
    fix_exclusions, fix_keys = _fix_ledger(facts)
    sources, receipts = _sources_and_receipts(facts, history_by_network)
    pushes, assignments, provenance, exclusions = _collect_draws(
        facts,
        sources,
        fix_keys=fix_keys,
        contamination=contamination,
        excluded_reviews=excluded_index,
        required=required_per_positive,
    )
    counts = Counter(row.positive_change_digest for row in assignments)
    return ordinary_population_draw(
        required_per_positive=required_per_positive,
        policy_digest=policy,
        closure_digest=closure.closure_digest,
        reservation_census_digest=reservation_census.census_digest,
        positive_change_digests=tuple(sorted(counts)),
        per_positive_counts=tuple((digest, counts[digest]) for digest in sorted(counts)),
        repository_receipts=receipts,
        fix_exclusions=fix_exclusions,
        pushes=tuple(pushes[key] for key in sorted(pushes)),
        assignments=tuple(sorted(assignments)),
        exclusions=tuple(sorted(exclusions)),
        provenance=tuple(sorted(provenance)),
    )


__all__ = ["OrdinaryPopulationHistorySource", "draw_ordinary_population"]
