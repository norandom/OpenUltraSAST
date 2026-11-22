"""Bounded ingestion of the third independently reviewed replacement cohort."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cohort_ingestion_fixtures import (  # noqa: E402
    COMBINED_PYTHON_NAMES,
    ECOSYSTEM_POLICY,
    GROUND_TRUTH_POLICY,
    SINGLE_FAMILY_PYTHON_NAMES,
    THIRD_JAVASCRIPT_NAMES,
    THIRD_PYTHON_NAMES,
    candidate_for,
    ingested_replacement_ledger,
    model_only_assistance_digest,
    replacement_cohort_state,
    reviewed_record,
)

from benchmarks.valid.cohort_ingestion import (  # noqa: E402
    COHORT_BATCH_CAP,
    MINIMUM_ACCEPTED_POSITIVES,
    CohortBatchStatus,
    CohortInsufficientReason,
    cohort_batch_bytes,
)
from benchmarks.valid.cohort_selection import (  # noqa: E402
    CohortSelectionStateError,
    CohortSelectionStateReason,
    CohortSelectionStatus,
    cohort_selection,
    cohort_selection_bytes,
    ingest_third_cohort_batch,
    select_third_cohort_batch,
)
from benchmarks.valid.ground_truth_review import VerifiedScope  # noqa: E402
from openultrasast.core.canonical import bytes_digest  # noqa: E402


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("network or SZZ was invoked")

    import socket

    from benchmarks.unseen import extract

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(extract, "introducing", forbidden)
    monkeypatch.setattr(extract.Git, "blame", forbidden)


def _select(state, ledger):
    return select_third_cohort_batch(
        state=state,
        accepted_batches=ledger,
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )


def _candidates(resolved, names):
    candidates = {}
    for name in names:
        candidate = candidate_for(name, resolved)
        candidates[candidate.candidate_digest] = candidate
    return candidates


def _prepared():
    state, resolved = replacement_cohort_state()
    ledger = ingested_replacement_ledger(state, resolved)
    selection = _select(state, ledger)
    candidates = _candidates(resolved, (*THIRD_PYTHON_NAMES, *THIRD_JAVASCRIPT_NAMES))
    return state, resolved, ledger, selection, candidates


def _selected_entries(state, selection):
    wanted = set(selection.selected_entries)
    queue = state.python_queue if selection.ecosystem == "python" else state.javascript_queue
    return [entry for entry in queue.entries if entry.entry_digest in wanted]


def _ingest(records, selection, state, candidates):
    return ingest_third_cohort_batch(
        records,
        selection=selection,
        state=state,
        candidates_by_digest=candidates,
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )


def test_third_cohort_contributes_ten_accepted_reachable_positives_and_replays():
    state, resolved, ledger, selection, candidates = _prepared()
    assert selection.status is CohortSelectionStatus.SELECTED
    entries = _selected_entries(state, selection)
    assert MINIMUM_ACCEPTED_POSITIVES <= len(entries) <= COHORT_BATCH_CAP
    records = [reviewed_record(entry, candidates[entry.candidate_digest])[0] for entry in entries]

    outcome = _ingest(records, selection, state, candidates)

    assert outcome.status is CohortBatchStatus.ACCEPTED
    assert outcome.insufficient_reason is None
    assert len(outcome.accepted_positives) == len(entries) >= MINIMUM_ACCEPTED_POSITIVES
    assert outcome.pending_entries == ()
    assert all(item.status.value == "accepted" for item in outcome.record_outcomes)
    assert all(
        scope.ecosystem.value == "python" for positive in outcome.accepted_positives for scope in positive.verified_scopes
    )
    assert {scope.vulnerability_family for p in outcome.accepted_positives for scope in p.verified_scopes} == {
        "deserialization",
        "ssrf",
    }
    assert outcome.census_digest == state.census_digest
    assert outcome.queue_digest != state.python_queue.queue_digest

    replayed = _ingest(list(reversed(records)), selection, state, candidates)
    assert replayed == outcome
    assert replayed.batch_digest == outcome.batch_digest

    combined = [*ledger[0].accepted_positives, *ledger[1].accepted_positives, *outcome.accepted_positives]
    assert {batch.ecosystem for batch in ledger} == {"python", "javascript"}
    assert len({item.change_identity_digest for item in combined}) == len(combined) == 36
    assert len(combined) < 40
    assert dict(selection.accepted_by_ecosystem) == {"javascript": 12, "python": 12}


def test_third_cohort_stays_pending_without_external_records():
    state, resolved, ledger, selection, candidates = _prepared()
    entries = _selected_entries(state, selection)
    records = [reviewed_record(entry, candidates[entry.candidate_digest])[0] for entry in entries]

    empty = _ingest([], selection, state, candidates)
    assert empty.status is CohortBatchStatus.INSUFFICIENT
    assert empty.insufficient_reason is CohortInsufficientReason.BATCH_EMPTY
    assert empty.accepted_positives == ()
    assert empty.pending_entries == selection.selected_entries

    partial = _ingest(records[:3], selection, state, candidates)
    assert partial.status is CohortBatchStatus.INSUFFICIENT
    assert partial.insufficient_reason is CohortInsufficientReason.INSUFFICIENT_ACCEPTED_POSITIVES
    assert len(partial.accepted_positives) == 3
    answered = {item.queue_entry_digest for item in partial.record_outcomes if item.queue_entry_digest is not None}
    assert partial.pending_entries == tuple(sorted(set(selection.selected_entries) - answered))


def test_records_outside_the_selected_batch_are_excluded_closed():
    python_names = (*COMBINED_PYTHON_NAMES, *THIRD_PYTHON_NAMES, *SINGLE_FAMILY_PYTHON_NAMES)
    state, resolved = replacement_cohort_state(python_names=python_names)
    ledger = ingested_replacement_ledger(state, resolved)
    selection = _select(state, ledger)
    candidates = _candidates(resolved, python_names)

    entries = _selected_entries(state, selection)
    assert len(entries) == COHORT_BATCH_CAP
    python_batch = next(batch for batch in ledger if batch.ecosystem == "python")
    outside = [
        entry
        for entry in state.python_queue.entries
        if entry.entry_digest in set(python_batch.pending_entries)
        and entry.entry_digest not in set(selection.selected_entries)
    ]
    assert len(outside) == 4
    assert {entry.family.vulnerability_family for entry in outside} == {"injection"}
    outsider = reviewed_record(outside[0], candidates[outside[0].candidate_digest])[0]
    records = [reviewed_record(entry, candidates[entry.candidate_digest])[0] for entry in entries[:-1]] + [outsider]

    outcome = _ingest(records, selection, state, candidates)

    assert outcome.status is CohortBatchStatus.ACCEPTED
    assert len(outcome.accepted_positives) == COHORT_BATCH_CAP - 1
    unknown = [item for item in outcome.record_outcomes if item.reason == "queue_entry_unknown"]
    assert len(unknown) == 1
    assert unknown[0].queue_entry_digest == outside[0].entry_digest
    assert unknown[0].record_digest == bytes_digest(outsider)
    assert outside[0].entry_digest not in outcome.pending_entries


def test_every_accepted_and_excluded_record_replays_from_external_evidence():
    state, resolved, ledger, selection, candidates = _prepared()
    entries = _selected_entries(state, selection)
    weakened = [
        {"conflict_disclosed": False},
        {"defect_present": None},
        {"in_repository_reachable": False},
        {"verified_scopes": ()},
        {"policy_satisfied": False},
        {"reviewer_identity": f"producer-{entries[5].family.advisory_locator}@example.invalid"},
        {
            "defect_present": None,
            "fix_addresses": None,
            "in_repository_reachable": None,
            "model_assistance_digest": model_only_assistance_digest(),
        },
        {"verified_scopes": (VerifiedScope("injection", "javascript"),)},
    ]
    records = []
    expected = {}
    for index, entry in enumerate(entries):
        changes = weakened[index] if index < len(weakened) else None
        if index == len(entries) - 1:
            own = entry.family.vulnerability_family
            second = "ssrf" if own != "ssrf" else "deserialization"
            changes = {"verified_scopes": (VerifiedScope(own, "python"), VerifiedScope(second, "python"))}
        content, review = reviewed_record(entry, candidates[entry.candidate_digest], gt_changes=changes)
        records.append(content)
        expected[entry.entry_digest] = review

    outcome = _ingest(records, selection, state, candidates)
    replayed = _ingest(list(reversed(records)), selection, state, candidates)
    assert replayed == outcome
    assert replayed.batch_digest == outcome.batch_digest

    by_entry = {item.queue_entry_digest: item for item in outcome.record_outcomes if item.queue_entry_digest is not None}
    for entry in entries:
        review = expected[entry.entry_digest]
        item = by_entry[entry.entry_digest]
        assert item.ground_truth_review_digest == review.review_digest
        if review.verified_scopes:
            assert item.status.value == "accepted"
            assert review.in_repository_reachable is True
        else:
            assert item.status.value == "excluded"
            assert item.reason == review.exclusion_reason.value

    assert outcome.status is CohortBatchStatus.INSUFFICIENT
    assert outcome.insufficient_reason is CohortInsufficientReason.INSUFFICIENT_ACCEPTED_POSITIVES
    multi_scope = [positive for positive in outcome.accepted_positives if len(positive.verified_scopes) == 2]
    assert len(multi_scope) == 1
    families = {scope.vulnerability_family for scope in multi_scope[0].verified_scopes}
    assert len(families) == 2 and families <= {"deserialization", "ssrf"}
    assert all(scope.ecosystem.value == "python" for scope in multi_scope[0].verified_scopes)
    assert len({item.change_identity_digest for item in outcome.accepted_positives}) == len(outcome.accepted_positives)


def test_selection_binding_guard_refuses_mismatched_selections():
    state, resolved, ledger, selection, candidates = _prepared()
    refused = _select(state, ledger)
    assert refused.status is CohortSelectionStatus.SELECTED

    other, _ = replacement_cohort_state(python_names=(*COMBINED_PYTHON_NAMES,))
    with pytest.raises(CohortSelectionStateError) as error:
        _ingest([], selection, other, candidates)
    assert error.value.reason is CohortSelectionStateReason.STATE_MISMATCH

    forged_entry = cohort_selection(
        ecosystem="python",
        selected_entries=("f" * 64,),
        targeted_families=("deserialization",),
        queue_digest=selection.queue_digest,
        census_digest=selection.census_digest,
        ecosystem_policy_digest=ECOSYSTEM_POLICY,
        ground_truth_policy_digest=GROUND_TRUTH_POLICY,
        prior_batch_digests=selection.prior_batch_digests,
        accepted_families=selection.accepted_families,
        accepted_by_ecosystem=dict(selection.accepted_by_ecosystem),
        status=CohortSelectionStatus.SELECTED,
        reason=selection.reason,
    )
    wrong_queue = cohort_selection(
        ecosystem="python",
        selected_entries=selection.selected_entries,
        targeted_families=selection.targeted_families,
        queue_digest="e" * 64,
        census_digest=selection.census_digest,
        ecosystem_policy_digest=ECOSYSTEM_POLICY,
        ground_truth_policy_digest=GROUND_TRUTH_POLICY,
        prior_batch_digests=selection.prior_batch_digests,
        accepted_families=selection.accepted_families,
        accepted_by_ecosystem=dict(selection.accepted_by_ecosystem),
        status=CohortSelectionStatus.SELECTED,
        reason=selection.reason,
    )
    for bad in (forged_entry, wrong_queue):
        with pytest.raises(CohortSelectionStateError) as error:
            _ingest([], bad, state, candidates)
        assert error.value.reason is CohortSelectionStateReason.STATE_MISMATCH


def test_third_cohort_outputs_carry_no_out_of_scope_machinery():
    state, resolved, ledger, selection, candidates = _prepared()
    entries = _selected_entries(state, selection)
    records = [reviewed_record(entry, candidates[entry.candidate_digest])[0] for entry in entries]
    outcome = _ingest(records, selection, state, candidates)
    assert outcome.status is CohortBatchStatus.ACCEPTED

    for content in (cohort_batch_bytes(outcome), cohort_selection_bytes(selection)):
        for forbidden in (b"admission", b"detector", b"observation", b"label", b"verdict", b"score"):
            assert forbidden not in content
