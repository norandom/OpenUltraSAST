"""Outcome-blind selection of the next bounded cohort batch over pending queues.

Selection may read pending queue state, the accepted-cohort ledger, and the
frozen review-policy digests already recorded on that ledger. Families
represented in the accepted ledger are facts of recorded human reviews: they
drive ecosystem and family-gap coverage only, never a change of review
policy, and no machine result enters this module or its durable bytes.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum

from benchmarks.valid.cohort_ingestion import (
    COHORT_BATCH_CAP,
    MINIMUM_ACCEPTED_POSITIVES,
    CohortBatchOutcomeV1,
    CohortRecordOutcomeV1,
    CohortRecordStatus,
    ingest_javascript_cohort_batch,
    ingest_python_cohort_batch,
)
from benchmarks.valid.fix_site_catalog import FixSiteCandidateV1
from benchmarks.valid.ground_truth_review import GroundTruthExclusionReason
from benchmarks.valid.sourcing_queue import (
    EcosystemReviewQueueV1,
    ReviewQueueEntryV1,
    SourcingQueueStateV1,
    ecosystem_review_queue,
    sourcing_queue_state,
)
from openultrasast.core.canonical import JsonValue, canonical_bytes, content_digest

COHORT_SELECTION_SCHEMA = "openultrasast.valid-detection-benchmark.cohort-selection.v1"
REQUIRED_DISTINCT_FAMILIES = 2
COHORT_SELECTION_ECOSYSTEMS = ("javascript", "python")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_FAMILY = re.compile(r"[a-z0-9][a-z0-9_]{0,127}")


class CohortSelectionStatus(StrEnum):
    SELECTED = "selected"
    REFUSED = "refused"


class CohortSelectionReason(StrEnum):
    """Closed decision vocabulary naming the ecosystem or family gap served."""

    MISSING_ECOSYSTEM_SELECTED = "missing_ecosystem_selected"
    FAMILY_GAP_SELECTED = "family_gap_selected"
    BALANCED_PROGRESS_SELECTED = "balanced_progress_selected"
    CLOSURE_GAP_SELECTED = "closure_gap_selected"
    NO_PENDING_ENTRIES = "no_pending_entries"
    CENSUS_MISMATCH = "census_mismatch"
    POLICY_MISMATCH = "policy_mismatch"
    GAP_UNCLOSABLE = "gap_unclosable"


class CohortSelectionStateReason(StrEnum):
    STATE_UNREADABLE = "state_unreadable"
    STATE_MISMATCH = "state_mismatch"


_REFUSAL_REASONS = frozenset(
    {
        CohortSelectionReason.NO_PENDING_ENTRIES,
        CohortSelectionReason.CENSUS_MISMATCH,
        CohortSelectionReason.POLICY_MISMATCH,
        CohortSelectionReason.GAP_UNCLOSABLE,
    }
)

_STATE_REASON_TEXT = {
    CohortSelectionStateReason.STATE_UNREADABLE: "cohort selection bytes are unreadable",
    CohortSelectionStateReason.STATE_MISMATCH: "cohort selection state does not match its canonical schema",
}


class CohortSelectionStateError(ValueError):
    """Closed selection refusal carrying one structural reason."""

    def __init__(self, reason: CohortSelectionStateReason) -> None:
        self.reason = reason
        super().__init__(_STATE_REASON_TEXT[reason])


def _mismatch() -> CohortSelectionStateError:
    return CohortSelectionStateError(CohortSelectionStateReason.STATE_MISMATCH)


@dataclass(frozen=True)
class CohortSelectionV1:
    ecosystem: str | None
    selected_entries: tuple[str, ...]
    targeted_families: tuple[str, ...]
    queue_digest: str | None
    census_digest: str
    ecosystem_policy_digest: str
    ground_truth_policy_digest: str
    prior_batch_digests: tuple[str, ...]
    accepted_families: tuple[str, ...]
    accepted_by_ecosystem: tuple[tuple[str, int], ...]
    status: CohortSelectionStatus
    reason: CohortSelectionReason
    selection_digest: str

    def __post_init__(self) -> None:
        _validate_selection(self)


@dataclass(frozen=True)
class _LedgerFacts:
    batch_digests: tuple[str, ...]
    families: tuple[str, ...]
    families_by_ecosystem: Mapping[str, frozenset[str]]
    accepted_by_ecosystem: Mapping[str, int]
    census_digests: tuple[str, ...]
    policy_pairs: tuple[tuple[str, str], ...]


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
    if not isinstance(pairs, tuple):
        raise _mismatch()
    ecosystems = []
    for pair in pairs:
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise _mismatch()
        ecosystem, count = pair
        if ecosystem not in COHORT_SELECTION_ECOSYSTEMS or type(count) is not int or count < 0:
            raise _mismatch()
        ecosystems.append(ecosystem)
    if ecosystems != sorted(ecosystems) or len(set(ecosystems)) != len(ecosystems):
        raise _mismatch()
    return pairs


def _validate_selection(item: CohortSelectionV1) -> None:
    if not isinstance(item.status, CohortSelectionStatus) or not isinstance(item.reason, CohortSelectionReason):
        raise _mismatch()
    if item.selection_digest:
        _closed_digest(item.selection_digest)
    for digest_value in (item.census_digest, item.ecosystem_policy_digest, item.ground_truth_policy_digest):
        _closed_digest(digest_value)
    _closed_vocabulary(item.prior_batch_digests, _DIGEST)
    _closed_vocabulary(item.accepted_families, _FAMILY)
    _closed_vocabulary(item.targeted_families, _FAMILY)
    _closed_counts(item.accepted_by_ecosystem)
    if item.status is CohortSelectionStatus.SELECTED:
        _validate_selected(item)
    else:
        _validate_refused(item)


def _validate_selected(item: CohortSelectionV1) -> None:
    if item.ecosystem not in COHORT_SELECTION_ECOSYSTEMS or item.reason in _REFUSAL_REASONS:
        raise _mismatch()
    _closed_digest(item.queue_digest)
    _closed_vocabulary(item.selected_entries, _DIGEST)
    if not 1 <= len(item.selected_entries) <= COHORT_BATCH_CAP:
        raise _mismatch()


def _validate_refused(item: CohortSelectionV1) -> None:
    if item.reason not in _REFUSAL_REASONS:
        raise _mismatch()
    if item.ecosystem is not None or item.queue_digest is not None or item.selected_entries or item.targeted_families:
        raise _mismatch()


def _count_value(pairs: tuple[tuple[str, int], ...]) -> tuple[dict[str, JsonValue], ...]:
    return tuple({"ecosystem": ecosystem, "accepted_positives": count} for ecosystem, count in pairs)


def _selection_value(item: CohortSelectionV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": COHORT_SELECTION_SCHEMA,
        "ecosystem": item.ecosystem,
        "selected_entries": item.selected_entries,
        "targeted_families": item.targeted_families,
        "queue_digest": item.queue_digest,
        "census_digest": item.census_digest,
        "ecosystem_policy_digest": item.ecosystem_policy_digest,
        "ground_truth_policy_digest": item.ground_truth_policy_digest,
        "prior_batch_digests": item.prior_batch_digests,
        "accepted_families": item.accepted_families,
        "accepted_by_ecosystem": _count_value(item.accepted_by_ecosystem),
        "status": item.status.value,
        "reason": item.reason.value,
    }
    if include_digest:
        value["selection_digest"] = item.selection_digest
    return value


def cohort_selection_value(item: CohortSelectionV1) -> dict[str, JsonValue]:
    """Canonical selection payload used for durable persistence and exact rereads."""
    return _selection_value(item, include_digest=True)


def cohort_selection_bytes(item: CohortSelectionV1) -> bytes:
    """Encode a digest-consistent selection decision as canonical bytes."""
    if item.selection_digest != content_digest(_selection_value(item, include_digest=False)):
        raise _mismatch()
    return canonical_bytes(cohort_selection_value(item))


def cohort_selection(
    *,
    ecosystem: str | None,
    selected_entries: Iterable[str],
    targeted_families: Iterable[str],
    queue_digest: str | None,
    census_digest: str,
    ecosystem_policy_digest: str,
    ground_truth_policy_digest: str,
    prior_batch_digests: Iterable[str],
    accepted_families: Iterable[str],
    accepted_by_ecosystem: Mapping[str, int],
    status: CohortSelectionStatus,
    reason: CohortSelectionReason,
) -> CohortSelectionV1:
    """Assemble one durable selection decision bound to its exact inputs."""
    draft = CohortSelectionV1(
        ecosystem,
        tuple(sorted(set(selected_entries))),
        tuple(sorted(set(targeted_families))),
        queue_digest,
        census_digest,
        ecosystem_policy_digest,
        ground_truth_policy_digest,
        tuple(sorted(set(prior_batch_digests))),
        tuple(sorted(set(accepted_families))),
        tuple((ecosystem, accepted_by_ecosystem[ecosystem]) for ecosystem in sorted(accepted_by_ecosystem)),
        status,
        reason,
        "",
    )
    return replace(draft, selection_digest=content_digest(_selection_value(draft, include_digest=False)))


def _ledger_facts(batches: Sequence[CohortBatchOutcomeV1]) -> _LedgerFacts:
    """Derive family and ecosystem facts from recorded review evidence only."""
    digests: set[str] = set()
    families: set[str] = set()
    by_ecosystem: dict[str, frozenset[str]] = {}
    counts: dict[str, int] = {}
    censuses: set[str] = set()
    policies: set[tuple[str, str]] = set()
    for batch in batches:
        try:
            ecosystem = batch.ecosystem
            if ecosystem not in COHORT_SELECTION_ECOSYSTEMS:
                raise _mismatch()
            census = _closed_digest(batch.census_digest)
            eco_policy = _closed_digest(batch.ecosystem_policy_digest)
            gt_policy = _closed_digest(batch.ground_truth_policy_digest)
            digests.add(_closed_digest(batch.batch_digest))
            batch_families: set[str] = set()
            for positive in batch.accepted_positives:
                for scope in positive.verified_scopes:
                    if scope.ecosystem.value != ecosystem:
                        raise _mismatch()
                    batch_families.add(scope.vulnerability_family)
        except (AttributeError, TypeError, ValueError) as error:
            raise CohortSelectionStateError(CohortSelectionStateReason.STATE_MISMATCH) from error
        censuses.add(census)
        policies.add((eco_policy, gt_policy))
        families.update(batch_families)
        by_ecosystem[ecosystem] = frozenset(batch_families | by_ecosystem.get(ecosystem, frozenset()))
        counts[ecosystem] = counts.get(ecosystem, 0) + len(batch.accepted_positives)
    return _LedgerFacts(
        tuple(sorted(digests)),
        tuple(sorted(families)),
        by_ecosystem,
        counts,
        tuple(sorted(censuses)),
        tuple(sorted(policies)),
    )


def _queue_for(state: SourcingQueueStateV1, ecosystem: str) -> EcosystemReviewQueueV1:
    """Fetch one ecosystem queue, failing closed on a malformed state."""
    try:
        queue = state.python_queue if ecosystem == "python" else state.javascript_queue
        if queue.ecosystem != ecosystem:
            raise _mismatch()
    except (AttributeError, TypeError, ValueError) as error:
        raise CohortSelectionStateError(CohortSelectionStateReason.STATE_MISMATCH) from error
    return queue


def _answered_entries(
    state: SourcingQueueStateV1,
    batches: Sequence[CohortBatchOutcomeV1],
) -> dict[str, frozenset[str]]:
    """Entry digests each ecosystem queue has already surrendered to a ledger batch."""
    queued = {
        ecosystem: {entry.entry_digest for entry in _queue_for(state, ecosystem).entries}
        for ecosystem in COHORT_SELECTION_ECOSYSTEMS
    }
    answered: dict[str, set[str]] = {ecosystem: set() for ecosystem in COHORT_SELECTION_ECOSYSTEMS}
    for batch in batches:
        try:
            ecosystem = batch.ecosystem
            pending = set(batch.pending_entries)
        except (AttributeError, TypeError, ValueError) as error:
            raise CohortSelectionStateError(CohortSelectionStateReason.STATE_MISMATCH) from error
        if ecosystem in answered:
            answered[ecosystem] |= queued[ecosystem] - pending
    return {ecosystem: frozenset(digests) for ecosystem, digests in answered.items()}


def _pending_for(
    state: SourcingQueueStateV1,
    answered: Mapping[str, frozenset[str]],
    ecosystem: str,
) -> tuple[ReviewQueueEntryV1, ...]:
    """Pending entries of one ecosystem queue in canonical digest order."""
    entries = _queue_for(state, ecosystem).entries
    consumed = answered.get(ecosystem, frozenset())
    return tuple(entry for entry in entries if entry.entry_digest not in consumed)


def _ecosystem_rank(
    pending: Sequence[ReviewQueueEntryV1],
    ecosystem: str,
    facts: _LedgerFacts,
) -> tuple[int, int, int, int, str]:
    """Rank one ecosystem by gap facts of record, never by how reviews resolved."""
    missing_ecosystem = facts.accepted_by_ecosystem.get(ecosystem, 0) == 0
    new_family_pending = any(entry.family.vulnerability_family not in facts.families for entry in pending)
    gap_class = 0 if (len(facts.families) < REQUIRED_DISTINCT_FAMILIES and new_family_pending) else 1
    feasible = 0 if len(pending) >= MINIMUM_ACCEPTED_POSITIVES else 1
    coverage = len(facts.families_by_ecosystem.get(ecosystem, frozenset()))
    return (0 if missing_ecosystem else 1, gap_class, feasible, coverage, ecosystem)


def _selected_entries(
    pending: Sequence[ReviewQueueEntryV1],
    represented: frozenset[str],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Pending entries with family-gap priority, bounded by the cohort cap."""
    prioritized = sorted(
        pending,
        key=lambda entry: (entry.family.vulnerability_family in represented, entry.entry_digest),
    )
    chosen = prioritized[:COHORT_BATCH_CAP]
    return (
        tuple(entry.entry_digest for entry in chosen),
        tuple(sorted({entry.family.vulnerability_family for entry in chosen} - represented)),
    )


def _decision_reason(ecosystem: str, facts: _LedgerFacts, targeted: tuple[str, ...]) -> CohortSelectionReason:
    if facts.accepted_by_ecosystem.get(ecosystem, 0) == 0:
        return CohortSelectionReason.MISSING_ECOSYSTEM_SELECTED
    if len(facts.families) < REQUIRED_DISTINCT_FAMILIES and targeted:
        return CohortSelectionReason.FAMILY_GAP_SELECTED
    return CohortSelectionReason.BALANCED_PROGRESS_SELECTED


def _census_refused(facts: _LedgerFacts, state_census: str) -> bool:
    return len(facts.census_digests) > 1 or (bool(facts.census_digests) and facts.census_digests[0] != state_census)


def _policy_refused(facts: _LedgerFacts, expected: tuple[str, str]) -> bool:
    return any(pair != expected for pair in facts.policy_pairs)


def _refused(
    reason: CohortSelectionReason,
    facts: _LedgerFacts,
    *,
    census_digest: str,
    ecosystem_policy_digest: str,
    ground_truth_policy_digest: str,
) -> CohortSelectionV1:
    """Bind one closed refusal to the exact ledger facts it examined."""
    return cohort_selection(
        ecosystem=None,
        selected_entries=(),
        targeted_families=(),
        queue_digest=None,
        census_digest=census_digest,
        ecosystem_policy_digest=ecosystem_policy_digest,
        ground_truth_policy_digest=ground_truth_policy_digest,
        prior_batch_digests=facts.batch_digests,
        accepted_families=facts.families,
        accepted_by_ecosystem=facts.accepted_by_ecosystem,
        status=CohortSelectionStatus.REFUSED,
        reason=reason,
    )


def select_third_cohort_batch(
    *,
    state: SourcingQueueStateV1,
    accepted_batches: Sequence[CohortBatchOutcomeV1],
    expected_ecosystem_policy_digest: str,
    expected_ground_truth_policy_digest: str,
) -> CohortSelectionV1:
    """Select the next bounded cohort batch from one shared reservation snapshot.

    The durable decision is a function of pending queue state, the accepted
    ledger's recorded family facts, and the frozen policy digests; how many
    reviews passed or failed cannot re-weight it.
    """
    facts = _ledger_facts(accepted_batches)
    try:
        census = _closed_digest(state.census_digest)
        eco_policy = _closed_digest(expected_ecosystem_policy_digest)
        gt_policy = _closed_digest(expected_ground_truth_policy_digest)
    except (AttributeError, TypeError, ValueError) as error:
        raise CohortSelectionStateError(CohortSelectionStateReason.STATE_MISMATCH) from error
    if _census_refused(facts, census):
        return _refused(
            CohortSelectionReason.CENSUS_MISMATCH,
            facts,
            census_digest=census,
            ecosystem_policy_digest=eco_policy,
            ground_truth_policy_digest=gt_policy,
        )
    if _policy_refused(facts, (eco_policy, gt_policy)):
        return _refused(
            CohortSelectionReason.POLICY_MISMATCH,
            facts,
            census_digest=census,
            ecosystem_policy_digest=eco_policy,
            ground_truth_policy_digest=gt_policy,
        )
    try:
        answered = _answered_entries(state, accepted_batches)
        ranked = sorted(
            _ecosystem_rank(_pending_for(state, answered, ecosystem), ecosystem, facts)
            for ecosystem in COHORT_SELECTION_ECOSYSTEMS
        )
        for rank in ranked:
            ecosystem = rank[4]
            pending = _pending_for(state, answered, ecosystem)
            if not pending:
                continue
            chosen, targeted = _selected_entries(pending, facts.families_by_ecosystem.get(ecosystem, frozenset()))
            return cohort_selection(
                ecosystem=ecosystem,
                selected_entries=chosen,
                targeted_families=targeted,
                queue_digest=_queue_for(state, ecosystem).queue_digest,
                census_digest=census,
                ecosystem_policy_digest=eco_policy,
                ground_truth_policy_digest=gt_policy,
                prior_batch_digests=facts.batch_digests,
                accepted_families=facts.families,
                accepted_by_ecosystem=facts.accepted_by_ecosystem,
                status=CohortSelectionStatus.SELECTED,
                reason=_decision_reason(ecosystem, facts, targeted),
            )
    except CohortSelectionStateError:
        raise
    except (AttributeError, TypeError, ValueError) as error:
        raise CohortSelectionStateError(CohortSelectionStateReason.STATE_MISMATCH) from error
    return _refused(
        CohortSelectionReason.NO_PENDING_ENTRIES,
        facts,
        census_digest=census,
        ecosystem_policy_digest=eco_policy,
        ground_truth_policy_digest=gt_policy,
    )


_REVIEW_RESOLVED_REASONS = frozenset(item.value for item in GroundTruthExclusionReason)


def _review_resolved(outcome: CohortRecordOutcomeV1) -> bool:
    """True when one external record resolved its queue entry through review."""
    if outcome.queue_entry_digest is None:
        return False
    if outcome.status is CohortRecordStatus.ACCEPTED:
        return True
    return outcome.reason in _REVIEW_RESOLVED_REASONS


def _pending_by_ecosystem(
    state: SourcingQueueStateV1,
    batches: Sequence[CohortBatchOutcomeV1],
) -> dict[str, tuple[ReviewQueueEntryV1, ...]]:
    """Pending entries per ecosystem from every batch's resolved records.

    A record resolves its entry only through the committed review machinery:
    accepted positives and review-level exclusions answer the entry, while
    unreadable or evidence-invalid records leave it pending. A narrowed
    selection batch therefore surrenders exactly the entries its records
    resolved, never the whole shared queue.
    """
    queued = {
        ecosystem: {entry.entry_digest for entry in _queue_for(state, ecosystem).entries}
        for ecosystem in COHORT_SELECTION_ECOSYSTEMS
    }
    answered: dict[str, set[str]] = {ecosystem: set() for ecosystem in COHORT_SELECTION_ECOSYSTEMS}
    for batch in batches:
        ecosystem = batch.ecosystem
        if ecosystem not in answered:
            continue
        for outcome in batch.record_outcomes:
            if _review_resolved(outcome) and outcome.queue_entry_digest in queued[ecosystem]:
                answered[ecosystem].add(outcome.queue_entry_digest)
    return {
        ecosystem: tuple(
            entry for entry in _queue_for(state, ecosystem).entries if entry.entry_digest not in answered[ecosystem]
        )
        for ecosystem in COHORT_SELECTION_ECOSYSTEMS
    }


def _ecosystem_gap(facts: _LedgerFacts) -> tuple[str, ...]:
    """Canonical ecosystems with no accepted positive recorded yet."""
    return tuple(
        ecosystem for ecosystem in COHORT_SELECTION_ECOSYSTEMS if facts.accepted_by_ecosystem.get(ecosystem, 0) == 0
    )


def _fourth_ecosystem(
    pending_by: Mapping[str, Sequence[ReviewQueueEntryV1]],
    facts: _LedgerFacts,
    ecosystem_gap: Sequence[str],
) -> str | None:
    """One ecosystem whose pending batch can close the remaining gap, else None.

    A gap-closing batch must be able to contribute the per-batch minimum of
    accepted positives; a family gap additionally needs a pending entry from a
    family no accepted review has recorded yet.
    """
    for ecosystem in ecosystem_gap or COHORT_SELECTION_ECOSYSTEMS:
        pending = pending_by[ecosystem]
        if len(pending) < MINIMUM_ACCEPTED_POSITIVES:
            continue
        if not ecosystem_gap and all(entry.family.vulnerability_family in facts.families for entry in pending):
            continue
        return ecosystem
    return None


def _fourth_selected(
    state: SourcingQueueStateV1,
    ecosystem: str,
    reason: CohortSelectionReason,
    pending: Sequence[ReviewQueueEntryV1],
    facts: _LedgerFacts,
    *,
    family_gap: bool,
    census: str,
    eco_policy: str,
    gt_policy: str,
) -> CohortSelectionV1:
    """Bind one selected fourth-round batch to the gap facts it serves."""
    base = facts.families_by_ecosystem.get(ecosystem, frozenset())
    represented = frozenset(facts.families) if family_gap else frozenset(base)
    chosen, targeted = _selected_entries(pending, represented)
    return cohort_selection(
        ecosystem=ecosystem,
        selected_entries=chosen,
        targeted_families=targeted,
        queue_digest=_queue_for(state, ecosystem).queue_digest,
        census_digest=census,
        ecosystem_policy_digest=eco_policy,
        ground_truth_policy_digest=gt_policy,
        prior_batch_digests=facts.batch_digests,
        accepted_families=facts.families,
        accepted_by_ecosystem=facts.accepted_by_ecosystem,
        status=CohortSelectionStatus.SELECTED,
        reason=reason,
    )


def _gap_closing_selection(
    state: SourcingQueueStateV1,
    pending_by: Mapping[str, Sequence[ReviewQueueEntryV1]],
    facts: _LedgerFacts,
    *,
    census: str,
    eco_policy: str,
    gt_policy: str,
) -> CohortSelectionV1 | None:
    """Selection closing a remaining ecosystem or family gap, or a closed refusal."""
    ecosystem_gap = _ecosystem_gap(facts)
    family_gap = len(facts.families) < REQUIRED_DISTINCT_FAMILIES
    if not (ecosystem_gap or family_gap):
        return None
    ecosystem = _fourth_ecosystem(pending_by, facts, ecosystem_gap)
    if ecosystem is None:
        return _refused(
            CohortSelectionReason.GAP_UNCLOSABLE,
            facts,
            census_digest=census,
            ecosystem_policy_digest=eco_policy,
            ground_truth_policy_digest=gt_policy,
        )
    reason = (
        CohortSelectionReason.MISSING_ECOSYSTEM_SELECTED if ecosystem_gap else CohortSelectionReason.CLOSURE_GAP_SELECTED
    )
    return _fourth_selected(
        state,
        ecosystem,
        reason,
        pending_by[ecosystem],
        facts,
        family_gap=family_gap,
        census=census,
        eco_policy=eco_policy,
        gt_policy=gt_policy,
    )


def _fourth_decision(
    state: SourcingQueueStateV1,
    accepted_batches: Sequence[CohortBatchOutcomeV1],
    facts: _LedgerFacts,
    *,
    census: str,
    eco_policy: str,
    gt_policy: str,
) -> CohortSelectionV1:
    try:
        pending_by = _pending_by_ecosystem(state, accepted_batches)
        if not any(pending_by.values()):
            return _refused(
                CohortSelectionReason.NO_PENDING_ENTRIES,
                facts,
                census_digest=census,
                ecosystem_policy_digest=eco_policy,
                ground_truth_policy_digest=gt_policy,
            )
        closing = _gap_closing_selection(state, pending_by, facts, census=census, eco_policy=eco_policy, gt_policy=gt_policy)
        if closing is not None:
            return closing
        ranked = sorted(
            _ecosystem_rank(pending_by[ecosystem], ecosystem, facts) for ecosystem in COHORT_SELECTION_ECOSYSTEMS
        )
        for rank in ranked:
            ecosystem = rank[4]
            if pending_by[ecosystem]:
                return _fourth_selected(
                    state,
                    ecosystem,
                    CohortSelectionReason.BALANCED_PROGRESS_SELECTED,
                    pending_by[ecosystem],
                    facts,
                    family_gap=False,
                    census=census,
                    eco_policy=eco_policy,
                    gt_policy=gt_policy,
                )
    except CohortSelectionStateError:
        raise
    except (AttributeError, TypeError, ValueError) as error:
        raise CohortSelectionStateError(CohortSelectionStateReason.STATE_MISMATCH) from error
    return _refused(
        CohortSelectionReason.NO_PENDING_ENTRIES,
        facts,
        census_digest=census,
        ecosystem_policy_digest=eco_policy,
        ground_truth_policy_digest=gt_policy,
    )


def select_fourth_cohort_batch(
    *,
    state: SourcingQueueStateV1,
    accepted_batches: Sequence[CohortBatchOutcomeV1],
    expected_ecosystem_policy_digest: str,
    expected_ground_truth_policy_digest: str,
) -> CohortSelectionV1:
    """Select the gap-closing fourth cohort batch from one shared reservation snapshot.

    The fourth round must close any remaining ecosystem or family gap: it
    targets the gap when a feasible pending batch exists and refuses with a
    closed reason when no pending batch can close it, never substituting a
    batch that would leave the gap open.
    """
    facts = _ledger_facts(accepted_batches)
    try:
        census = _closed_digest(state.census_digest)
        eco_policy = _closed_digest(expected_ecosystem_policy_digest)
        gt_policy = _closed_digest(expected_ground_truth_policy_digest)
    except (AttributeError, TypeError, ValueError) as error:
        raise CohortSelectionStateError(CohortSelectionStateReason.STATE_MISMATCH) from error
    if _census_refused(facts, census):
        return _refused(
            CohortSelectionReason.CENSUS_MISMATCH,
            facts,
            census_digest=census,
            ecosystem_policy_digest=eco_policy,
            ground_truth_policy_digest=gt_policy,
        )
    if _policy_refused(facts, (eco_policy, gt_policy)):
        return _refused(
            CohortSelectionReason.POLICY_MISMATCH,
            facts,
            census_digest=census,
            ecosystem_policy_digest=eco_policy,
            ground_truth_policy_digest=gt_policy,
        )
    return _fourth_decision(state, accepted_batches, facts, census=census, eco_policy=eco_policy, gt_policy=gt_policy)


def _require_selection_binding(
    selection: CohortSelectionV1,
    state: SourcingQueueStateV1,
    expected_ecosystem_policy_digest: str,
    expected_ground_truth_policy_digest: str,
) -> EcosystemReviewQueueV1:
    if selection.status is not CohortSelectionStatus.SELECTED or selection.ecosystem not in COHORT_SELECTION_ECOSYSTEMS:
        raise _mismatch()
    if (
        selection.census_digest != state.census_digest
        or selection.ecosystem_policy_digest != expected_ecosystem_policy_digest
        or selection.ground_truth_policy_digest != expected_ground_truth_policy_digest
    ):
        raise _mismatch()
    full = _queue_for(state, selection.ecosystem)
    if selection.queue_digest != full.queue_digest:
        raise _mismatch()
    return full


def _narrowed_queue(selection: CohortSelectionV1, full: EcosystemReviewQueueV1) -> EcosystemReviewQueueV1:
    wanted = set(selection.selected_entries)
    kept = tuple(entry for entry in full.entries if entry.entry_digest in wanted)
    if {entry.entry_digest for entry in kept} != wanted:
        raise _mismatch()
    return ecosystem_review_queue(full.ecosystem, cap=full.cap, policy_digest=full.policy_digest, entries=kept)


def _selection_state(
    selection: CohortSelectionV1,
    state: SourcingQueueStateV1,
    *,
    expected_ecosystem_policy_digest: str,
    expected_ground_truth_policy_digest: str,
) -> SourcingQueueStateV1:
    """Narrow the selected ecosystem queue to exactly the selected entries."""
    try:
        full = _require_selection_binding(
            selection, state, expected_ecosystem_policy_digest, expected_ground_truth_policy_digest
        )
        narrowed = _narrowed_queue(selection, full)
        python_queue = narrowed if selection.ecosystem == "python" else state.python_queue
        javascript_queue = narrowed if selection.ecosystem == "javascript" else state.javascript_queue
        return sourcing_queue_state(
            python_queue=python_queue,
            javascript_queue=javascript_queue,
            exclusions=state.exclusions,
            census_digest=state.census_digest,
            policy_digest=state.policy_digest,
        )
    except CohortSelectionStateError:
        raise
    except (AttributeError, TypeError, ValueError) as error:
        raise CohortSelectionStateError(CohortSelectionStateReason.STATE_MISMATCH) from error


def _ingest_selected_cohort_batch(
    records: Sequence[bytes],
    *,
    selection: CohortSelectionV1,
    state: SourcingQueueStateV1,
    candidates_by_digest: Mapping[str, FixSiteCandidateV1],
    expected_ecosystem_policy_digest: str,
    expected_ground_truth_policy_digest: str,
) -> CohortBatchOutcomeV1:
    """Ingest one selected bounded cohort batch through the committed machinery."""
    narrowed = _selection_state(
        selection,
        state,
        expected_ecosystem_policy_digest=expected_ecosystem_policy_digest,
        expected_ground_truth_policy_digest=expected_ground_truth_policy_digest,
    )
    ingest = ingest_python_cohort_batch if selection.ecosystem == "python" else ingest_javascript_cohort_batch
    return ingest(
        records,
        state=narrowed,
        candidates_by_digest=candidates_by_digest,
        expected_ecosystem_policy_digest=expected_ecosystem_policy_digest,
        expected_ground_truth_policy_digest=expected_ground_truth_policy_digest,
    )


def ingest_third_cohort_batch(
    records: Sequence[bytes],
    *,
    selection: CohortSelectionV1,
    state: SourcingQueueStateV1,
    candidates_by_digest: Mapping[str, FixSiteCandidateV1],
    expected_ecosystem_policy_digest: str,
    expected_ground_truth_policy_digest: str,
) -> CohortBatchOutcomeV1:
    """Ingest the selected bounded third cohort through the committed machinery."""
    return _ingest_selected_cohort_batch(
        records,
        selection=selection,
        state=state,
        candidates_by_digest=candidates_by_digest,
        expected_ecosystem_policy_digest=expected_ecosystem_policy_digest,
        expected_ground_truth_policy_digest=expected_ground_truth_policy_digest,
    )


def ingest_fourth_cohort_batch(
    records: Sequence[bytes],
    *,
    selection: CohortSelectionV1,
    state: SourcingQueueStateV1,
    candidates_by_digest: Mapping[str, FixSiteCandidateV1],
    expected_ecosystem_policy_digest: str,
    expected_ground_truth_policy_digest: str,
) -> CohortBatchOutcomeV1:
    """Ingest the selected bounded fourth cohort under the unchanged review policy.

    Scope verification never moves: acceptance still flows only through the
    committed review authorities over the narrowed selected queue.
    """
    return _ingest_selected_cohort_batch(
        records,
        selection=selection,
        state=state,
        candidates_by_digest=candidates_by_digest,
        expected_ecosystem_policy_digest=expected_ecosystem_policy_digest,
        expected_ground_truth_policy_digest=expected_ground_truth_policy_digest,
    )


__all__ = [
    "COHORT_SELECTION_ECOSYSTEMS",
    "COHORT_SELECTION_SCHEMA",
    "CohortSelectionReason",
    "CohortSelectionStateError",
    "CohortSelectionStateReason",
    "CohortSelectionStatus",
    "CohortSelectionV1",
    "REQUIRED_DISTINCT_FAMILIES",
    "cohort_selection",
    "cohort_selection_bytes",
    "cohort_selection_value",
    "ingest_fourth_cohort_batch",
    "ingest_third_cohort_batch",
    "select_fourth_cohort_batch",
    "select_third_cohort_batch",
]
