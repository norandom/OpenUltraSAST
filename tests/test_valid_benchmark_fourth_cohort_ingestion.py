"""Bounded ingestion of the fourth independently reviewed cohort closes the positive set."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cohort_ingestion_fixtures import (  # noqa: E402
    COMBINED_JAVASCRIPT_NAMES,
    COMBINED_PYTHON_NAMES,
    ECOSYSTEM_POLICY,
    FOURTH_JAVASCRIPT_NAMES,
    FOURTH_PYTHON_NAMES,
    GROUND_TRUTH_POLICY,
    SINGLE_FAMILY_JAVASCRIPT_NAMES,
    SINGLE_FAMILY_PYTHON_NAMES,
    THIRD_PYTHON_NAMES,
    authority,
    candidate_for,
    ingested_replacement_ledger,
    replacement_cohort_state,
    resolver,
    reviewed_record,
)

from benchmarks.valid.cohort_ingestion import (  # noqa: E402
    COHORT_BATCH_CAP,
    MINIMUM_ACCEPTED_POSITIVES,
    CohortBatchStatus,
    CohortInsufficientReason,
)
from benchmarks.valid.cohort_selection import (  # noqa: E402
    CohortSelectionReason,
    CohortSelectionStateError,
    CohortSelectionStateReason,
    CohortSelectionStatus,
    cohort_selection,
    cohort_selection_bytes,
    ingest_fourth_cohort_batch,
    ingest_third_cohort_batch,
    select_fourth_cohort_batch,
    select_third_cohort_batch,
)
from benchmarks.valid.cohort_selection_store import decode_cohort_selection  # noqa: E402
from benchmarks.valid.positive_set_closure import (  # noqa: E402
    COMBINED_POSITIVE_FLOOR,
    PositiveSetClosureReason,
    PositiveSetClosureStatus,
    positive_set_closure_bytes,
    project_positive_set_closure,
)
from benchmarks.valid.reservation import legacy_reservation_source  # noqa: E402
from openultrasast.core.canonical import content_digest  # noqa: E402

CLOSED_PYTHON_NAMES = (*COMBINED_PYTHON_NAMES, *THIRD_PYTHON_NAMES)
CLOSED_JAVASCRIPT_NAMES = (*COMBINED_JAVASCRIPT_NAMES, *FOURTH_JAVASCRIPT_NAMES)


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


def _select_fourth(state, ledger, *, eco=ECOSYSTEM_POLICY, gt=GROUND_TRUTH_POLICY):
    return select_fourth_cohort_batch(
        state=state,
        accepted_batches=ledger,
        expected_ecosystem_policy_digest=eco,
        expected_ground_truth_policy_digest=gt,
    )


def _candidates(resolved, names):
    candidates = {}
    for name in names:
        candidate = candidate_for(name, resolved)
        candidates[candidate.candidate_digest] = candidate
    return candidates


def _selected_entries(state, selection):
    wanted = set(selection.selected_entries)
    queue = state.python_queue if selection.ecosystem == "python" else state.javascript_queue
    return [entry for entry in queue.entries if entry.entry_digest in wanted]


def _ingest_fourth(records, selection, state, candidates):
    return ingest_fourth_cohort_batch(
        records,
        selection=selection,
        state=state,
        candidates_by_digest=candidates,
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )


def _prepared():
    state, resolved = replacement_cohort_state(python_names=CLOSED_PYTHON_NAMES, javascript_names=CLOSED_JAVASCRIPT_NAMES)
    candidates = _candidates(resolved, (*CLOSED_PYTHON_NAMES, *CLOSED_JAVASCRIPT_NAMES))
    first_two = ingested_replacement_ledger(state, resolved)
    third_selection = select_third_cohort_batch(
        state=state,
        accepted_batches=first_two,
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )
    entries = _selected_entries(state, third_selection)
    records = [reviewed_record(entry, candidates[entry.candidate_digest])[0] for entry in entries]
    third = ingest_third_cohort_batch(
        records,
        selection=third_selection,
        state=state,
        candidates_by_digest=candidates,
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )
    return state, resolved, (*first_two, third), candidates


def test_fourth_cohort_closes_the_combined_positive_set():
    state, resolved, ledger, candidates = _prepared()
    selection = _select_fourth(state, ledger)

    assert selection.status is CohortSelectionStatus.SELECTED
    assert selection.ecosystem == "javascript"
    assert selection.reason is CohortSelectionReason.BALANCED_PROGRESS_SELECTED
    assert dict(selection.accepted_by_ecosystem) == {"javascript": 12, "python": 24}
    assert selection.targeted_families == ("redos", "type_confusion")
    entries = _selected_entries(state, selection)
    assert MINIMUM_ACCEPTED_POSITIVES <= len(entries) <= COHORT_BATCH_CAP
    records = [reviewed_record(entry, candidates[entry.candidate_digest], ecosystem="javascript")[0] for entry in entries]

    outcome = _ingest_fourth(records, selection, state, candidates)

    assert outcome.status is CohortBatchStatus.ACCEPTED
    assert outcome.insufficient_reason is None
    assert len(outcome.accepted_positives) == len(entries) >= MINIMUM_ACCEPTED_POSITIVES
    assert outcome.pending_entries == ()
    assert all(
        scope.ecosystem.value == "javascript" for positive in outcome.accepted_positives for scope in positive.verified_scopes
    )
    assert all(positive.verified_scopes for positive in outcome.accepted_positives)

    closure = project_positive_set_closure((*ledger, outcome))
    assert closure.status is PositiveSetClosureStatus.CLOSED
    assert closure.reason is PositiveSetClosureReason.ALL_GAPS_CLOSED
    assert closure.total_accepted_positives == 48 >= COMBINED_POSITIVE_FLOOR
    assert dict(closure.positives_by_ecosystem) == {"javascript": 24, "python": 24}
    assert {"injection", "path_traversal", "output_encoding", "deserialization", "ssrf"} <= set(closure.accepted_families)
    assert closure.accepted_batch_digests == tuple(sorted(batch.batch_digest for batch in (*ledger, outcome)))

    replayed = _ingest_fourth(list(reversed(records)), selection, state, candidates)
    assert replayed == outcome
    assert replayed.batch_digest == outcome.batch_digest
    assert project_positive_set_closure((*ledger, replayed)) == closure


def test_fourth_cohort_stays_pending_without_external_records():
    state, resolved, ledger, candidates = _prepared()
    selection = _select_fourth(state, ledger)
    entries = _selected_entries(state, selection)
    records = [reviewed_record(entry, candidates[entry.candidate_digest], ecosystem="javascript")[0] for entry in entries]

    empty = _ingest_fourth([], selection, state, candidates)
    assert empty.status is CohortBatchStatus.INSUFFICIENT
    assert empty.insufficient_reason is CohortInsufficientReason.BATCH_EMPTY
    assert empty.accepted_positives == ()
    assert empty.pending_entries == selection.selected_entries
    empty_closure = project_positive_set_closure((*ledger, empty))
    assert empty_closure.status is PositiveSetClosureStatus.INSUFFICIENT
    assert empty_closure.reason is PositiveSetClosureReason.INSUFFICIENT_TOTAL_POSITIVES
    assert empty_closure.total_accepted_positives == 36 < COMBINED_POSITIVE_FLOOR
    assert empty_closure.accepted_batch_digests == tuple(sorted(batch.batch_digest for batch in ledger))

    partial = _ingest_fourth(records[:3], selection, state, candidates)
    assert partial.status is CohortBatchStatus.INSUFFICIENT
    assert partial.insufficient_reason is CohortInsufficientReason.INSUFFICIENT_ACCEPTED_POSITIVES
    assert len(partial.accepted_positives) == 3
    answered = {item.queue_entry_digest for item in partial.record_outcomes if item.queue_entry_digest is not None}
    assert partial.pending_entries == tuple(sorted(set(selection.selected_entries) - answered))
    partial_closure = project_positive_set_closure((*ledger, partial))
    assert partial_closure.status is PositiveSetClosureStatus.INSUFFICIENT
    assert partial_closure.reason is PositiveSetClosureReason.INSUFFICIENT_TOTAL_POSITIVES
    assert partial_closure.total_accepted_positives == 36


def test_fourth_selection_refuses_a_gap_it_cannot_close():
    state, resolved = replacement_cohort_state(
        python_names=("py-01", *SINGLE_FAMILY_PYTHON_NAMES),
        javascript_names=("js-01", *SINGLE_FAMILY_JAVASCRIPT_NAMES),
    )
    ledger = ingested_replacement_ledger(
        state,
        resolved,
        python_names=SINGLE_FAMILY_PYTHON_NAMES,
        javascript_names=SINGLE_FAMILY_JAVASCRIPT_NAMES,
    )
    selection = _select_fourth(state, ledger)
    assert selection.status is CohortSelectionStatus.REFUSED
    assert selection.reason is CohortSelectionReason.GAP_UNCLOSABLE
    assert selection.ecosystem is None
    assert selection.selected_entries == () and selection.targeted_families == ()
    assert decode_cohort_selection(cohort_selection_bytes(selection)) == selection
    closure = project_positive_set_closure(ledger)
    assert closure.status is PositiveSetClosureStatus.INSUFFICIENT
    assert closure.accepted_families == ("injection",)
    assert closure.total_accepted_positives == 24 < COMBINED_POSITIVE_FLOOR

    unbalanced, resolved_two = replacement_cohort_state(
        python_names=(*COMBINED_PYTHON_NAMES, *THIRD_PYTHON_NAMES),
        javascript_names=("js-00", "js-01", "js-02", "js-03"),
    )
    python_ledger = ingested_replacement_ledger(unbalanced, resolved_two, javascript_names=())
    refused = _select_fourth(unbalanced, python_ledger)
    assert refused.status is CohortSelectionStatus.REFUSED
    assert refused.reason is CohortSelectionReason.GAP_UNCLOSABLE
    assert refused.selected_entries == () and refused.targeted_families == ()


def test_fourth_selection_closes_a_remaining_family_gap():
    state, resolved = replacement_cohort_state(
        python_names=("py-01", *SINGLE_FAMILY_PYTHON_NAMES, *THIRD_PYTHON_NAMES),
        javascript_names=("js-01", *SINGLE_FAMILY_JAVASCRIPT_NAMES),
    )
    ledger = ingested_replacement_ledger(
        state,
        resolved,
        python_names=SINGLE_FAMILY_PYTHON_NAMES,
        javascript_names=SINGLE_FAMILY_JAVASCRIPT_NAMES,
    )
    candidates = _candidates(resolved, ("py-01", *SINGLE_FAMILY_PYTHON_NAMES, *THIRD_PYTHON_NAMES))

    selection = _select_fourth(state, ledger)

    assert selection.status is CohortSelectionStatus.SELECTED
    assert selection.ecosystem == "python"
    assert selection.reason is CohortSelectionReason.CLOSURE_GAP_SELECTED
    entries = _selected_entries(state, selection)
    assert len(entries) == 13
    assert {entry.family.vulnerability_family for entry in entries} == {"path_traversal", "deserialization", "ssrf"}
    assert selection.targeted_families == ("deserialization", "path_traversal", "ssrf")

    records = [reviewed_record(entry, candidates[entry.candidate_digest])[0] for entry in entries]
    outcome = _ingest_fourth(records, selection, state, candidates)
    assert outcome.status is CohortBatchStatus.ACCEPTED
    assert len(outcome.accepted_positives) == 13 >= MINIMUM_ACCEPTED_POSITIVES

    closure = project_positive_set_closure((*ledger, outcome))
    assert closure.status is PositiveSetClosureStatus.INSUFFICIENT
    assert closure.reason is PositiveSetClosureReason.INSUFFICIENT_TOTAL_POSITIVES
    assert closure.total_accepted_positives == 37 < COMBINED_POSITIVE_FLOOR
    assert {"injection", "path_traversal", "deserialization", "ssrf"} <= set(closure.accepted_families)


def test_fourth_selection_targets_a_missing_ecosystem_to_close_it():
    state, resolved = replacement_cohort_state()
    ledger = ingested_replacement_ledger(state, resolved, javascript_names=())

    selection = _select_fourth(state, ledger)

    assert selection.status is CohortSelectionStatus.SELECTED
    assert selection.ecosystem == "javascript"
    assert selection.reason is CohortSelectionReason.MISSING_ECOSYSTEM_SELECTED
    pending = sorted(state.javascript_queue.entries, key=lambda entry: entry.entry_digest)
    assert selection.selected_entries == tuple(entry.entry_digest for entry in pending[:COHORT_BATCH_CAP])


def test_fourth_selection_ignores_how_many_reviews_passed():
    state, resolved = replacement_cohort_state()
    full = ingested_replacement_ledger(state, resolved, javascript_names=())
    thinned = ingested_replacement_ledger(state, resolved, javascript_names=(), weakened_python=2)
    assert len(thinned[0].accepted_positives) < len(full[0].accepted_positives)

    chosen = _select_fourth(state, full)
    other = _select_fourth(state, thinned)

    assert (chosen.status, chosen.reason, chosen.ecosystem) == (other.status, other.reason, other.ecosystem)
    assert chosen.selected_entries == other.selected_entries
    assert chosen.targeted_families == other.targeted_families
    assert chosen.selection_digest != other.selection_digest


def test_fourth_selection_refuses_reweighted_policy_and_stale_census():
    state, resolved = replacement_cohort_state()
    ledger = ingested_replacement_ledger(state, resolved, javascript_names=())

    changed = _select_fourth(state, ledger, eco=content_digest({"policy": "reweighted-after-outcomes"}))
    assert changed.status is CohortSelectionStatus.REFUSED
    assert changed.reason is CohortSelectionReason.POLICY_MISMATCH

    reserved = legacy_reservation_source(
        resolved, repository="https://github.com/fixture/cohort-py4-00", source_digest="c" * 64
    )
    stale_state, _ = replacement_cohort_state(
        python_names=(*COMBINED_PYTHON_NAMES, *FOURTH_PYTHON_NAMES),
        javascript_names=(),
        authority_=authority(resolver(), legacy=(reserved,)),
    )
    assert stale_state.census_digest != state.census_digest
    stale = _select_fourth(stale_state, ledger)
    assert stale.status is CohortSelectionStatus.REFUSED
    assert stale.reason is CohortSelectionReason.CENSUS_MISMATCH
    assert decode_cohort_selection(cohort_selection_bytes(stale)) == stale


def test_fourth_binding_guard_refuses_mismatched_selections():
    state, resolved, ledger, candidates = _prepared()
    selection = _select_fourth(state, ledger)
    assert selection.status is CohortSelectionStatus.SELECTED

    other, _ = replacement_cohort_state(python_names=(*COMBINED_PYTHON_NAMES,))
    with pytest.raises(CohortSelectionStateError) as error:
        _ingest_fourth([], selection, other, candidates)
    assert error.value.reason is CohortSelectionStateReason.STATE_MISMATCH

    refused = _select_fourth(state, ledger, gt=content_digest({"policy": "changed"}))
    with pytest.raises(CohortSelectionStateError) as error:
        _ingest_fourth([], refused, state, candidates)
    assert error.value.reason is CohortSelectionStateReason.STATE_MISMATCH

    forged = cohort_selection(
        ecosystem=selection.ecosystem,
        selected_entries=(*selection.selected_entries[:-1], "f" * 64),
        targeted_families=selection.targeted_families,
        queue_digest=selection.queue_digest,
        census_digest=selection.census_digest,
        ecosystem_policy_digest=selection.ecosystem_policy_digest,
        ground_truth_policy_digest=selection.ground_truth_policy_digest,
        prior_batch_digests=selection.prior_batch_digests,
        accepted_families=selection.accepted_families,
        accepted_by_ecosystem=dict(selection.accepted_by_ecosystem),
        status=CohortSelectionStatus.SELECTED,
        reason=selection.reason,
    )
    with pytest.raises(CohortSelectionStateError) as error:
        _ingest_fourth([], forged, state, candidates)
    assert error.value.reason is CohortSelectionStateReason.STATE_MISMATCH


def test_fourth_round_modules_and_outputs_carry_no_out_of_scope_machinery():
    root = Path(__file__).resolve().parents[1]
    for name in (
        "benchmarks/valid/cohort_selection.py",
        "benchmarks/valid/positive_set_closure.py",
        "benchmarks/valid/positive_set_closure_store.py",
    ):
        source = (root / name).read_bytes()
        for forbidden in (b"admission", b"detector", b"observation", b"label", b"verdict", b"score"):
            assert forbidden not in source, f"{name} references out-of-scope machinery: {forbidden!r}"

    state, resolved, ledger, candidates = _prepared()
    selection = _select_fourth(state, ledger)
    closure = project_positive_set_closure(ledger)
    for content in (cohort_selection_bytes(selection), positive_set_closure_bytes(closure)):
        for forbidden in (b"admission", b"detector", b"observation", b"label", b"verdict", b"score"):
            assert forbidden not in content
