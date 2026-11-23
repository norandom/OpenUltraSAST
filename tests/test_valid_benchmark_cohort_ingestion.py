"""Bounded ingestion of the first independently reviewed Python cohort."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cohort_ingestion_fixtures import (  # noqa: E402
    ECOSYSTEM_POLICY,
    GROUND_TRUTH_POLICY,
    PYTHON_COUNT,
    FakeReader,
    authority,
    candidates_for,
    model_only_assistance_digest,
    python_cohort_state,
    python_entries,
    request_for,
    resolver,
    reviewed_record,
)

from benchmarks.valid.cohort_ingestion import (  # noqa: E402
    COHORT_BATCH_CAP,
    MINIMUM_ACCEPTED_POSITIVES,
    CohortBatchStatus,
    CohortInsufficientReason,
    cohort_batch_bytes,
    ingest_python_cohort_batch,
)
from benchmarks.valid.ecosystem_review import EcosystemReviewDecision  # noqa: E402
from benchmarks.valid.ground_truth_review import GroundTruthStatus, VerifiedScope  # noqa: E402
from benchmarks.valid.reservation import legacy_reservation_source  # noqa: E402
from benchmarks.valid.sourcing_queue import SourcingQueueReason, sourcing_queue_policy  # noqa: E402
from benchmarks.valid.sourcing_queue_build import InsufficientFamiliesRefusal, build_sourcing_queue  # noqa: E402
from openultrasast.core.canonical import bytes_digest  # noqa: E402

ENUMERATION_ACTOR = "sourcing-operator@example.invalid"
ENUMERATION_REVIEWER = "enumeration-reviewer@example.invalid"


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


def _ingest(records, state, candidates):
    return ingest_python_cohort_batch(
        records,
        state=state,
        candidates_by_digest=candidates,
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )


def _prepared():
    state, resolved = python_cohort_state()
    requests = [request_for(f"py-{index:02d}") for index in range(PYTHON_COUNT)] + [request_for("js-00")]
    return state, candidates_for(requests, resolved)


def _good_records(state, candidates):
    return [reviewed_record(entry, candidates[entry.candidate_digest])[0] for entry in python_entries(state)]


def _by_reason(outcome):
    return {item.reason: item for item in outcome.record_outcomes if item.reason is not None}


def _built(requests, *, cap=20, authority_=None, resolver_=None):
    resolved = resolver_ or resolver()
    return build_sourcing_queue(
        requests,
        reader=FakeReader(),
        resolver=resolved,
        authority=authority_ or authority(resolved),
        policy=sourcing_queue_policy(per_ecosystem_cap=cap, required_families=2),
        enumeration_actor=ENUMERATION_ACTOR,
        enumeration_reviewer=ENUMERATION_REVIEWER,
    )


def test_first_bounded_python_batch_reaches_ten_accepted_reachable_positives():
    state, candidates = _prepared()
    records = _good_records(state, candidates)

    assert len(records) == PYTHON_COUNT <= COHORT_BATCH_CAP
    outcome = _ingest(records, state, candidates)

    assert outcome.status is CohortBatchStatus.ACCEPTED
    assert outcome.insufficient_reason is None
    assert len(outcome.accepted_positives) == PYTHON_COUNT >= MINIMUM_ACCEPTED_POSITIVES
    assert outcome.pending_entries == ()
    assert all(item.status.value == "accepted" for item in outcome.record_outcomes)
    families = {scope.vulnerability_family for positive in outcome.accepted_positives for scope in positive.verified_scopes}
    assert len(families) >= 2
    assert all(scope.ecosystem.value == "python" for positive in outcome.accepted_positives for scope in positive.verified_scopes)
    assert outcome.census_digest == state.census_digest
    assert outcome.queue_digest == state.python_queue.queue_digest

    shuffled = list(reversed(records))
    replayed = _ingest(shuffled, state, candidates)
    assert replayed == outcome
    assert replayed.batch_digest == outcome.batch_digest


def test_every_accepted_and_excluded_candidate_replays_from_external_review_evidence():
    state, candidates = _prepared()
    entries = python_entries(state)
    weak = {
        "conflict_disclosure_missing": {"conflict_disclosed": False},
        "judgment_missing": {"defect_present": None},
        "judgment_rejected": {"in_repository_reachable": False},
        "missing_scope": {"verified_scopes": ()},
        "policy_unsatisfied": {"policy_satisfied": False},
    }
    records = []
    expected = {}
    for index, entry in enumerate(entries):
        key = sorted(weak)[index] if index < len(weak) else None
        changes = dict(weak[key]) if key else None
        if index == len(weak):
            changes = {"reviewer_identity": f"producer-{entry.family.advisory_locator}@example.invalid"}
        content, review = reviewed_record(entry, candidates[entry.candidate_digest], gt_changes=changes)
        records.append(content)
        expected[entry.entry_digest] = review
    unknown = reviewed_record(entries[0], candidates[entries[0].candidate_digest], entry_digest="0" * 64)[0]
    records.append(unknown)

    outcome = _ingest(records, state, candidates)
    replayed = _ingest(list(reversed(records)), state, candidates)
    assert replayed == outcome
    assert replayed.batch_digest == outcome.batch_digest
    assert any(item.record_digest == bytes_digest(unknown) for item in outcome.record_outcomes)

    by_entry = {item.queue_entry_digest: item for item in outcome.record_outcomes if item.queue_entry_digest is not None}
    for entry in entries:
        review = expected[entry.entry_digest]
        item = by_entry[entry.entry_digest]
        assert item.ground_truth_review_digest == review.review_digest
        if review.status is GroundTruthStatus.ACCEPTED:
            assert item.status.value == "accepted"
            assert review.in_repository_reachable is True
        else:
            assert item.status.value == "excluded"
            assert item.reason == review.exclusion_reason.value


def test_review_policy_failures_are_recorded_never_fabricated():
    state, candidates = _prepared()
    entries = python_entries(state)

    def self_review_for(entry):
        return {"reviewer_identity": f"producer-{entry.family.advisory_locator}@example.invalid"}

    cases = [
        ({"decision": EcosystemReviewDecision.JAVASCRIPT}, lambda entry: {}),
        (None, self_review_for),
        (None, lambda entry: {"conflict_disclosed": False}),
        (None, lambda entry: {"policy_satisfied": False}),
        (None, lambda entry: {"defect_present": None}),
        (None, lambda entry: {"in_repository_reachable": False}),
        (
            None,
            lambda entry: {
                "defect_present": None,
                "fix_addresses": None,
                "in_repository_reachable": None,
                "model_assistance_digest": model_only_assistance_digest(),
            },
        ),
        (None, lambda entry: {"verified_scopes": ()}),
        (None, lambda entry: {"verified_scopes": (VerifiedScope("injection", "javascript"),)}),
    ]
    records = []
    expected_reasons = []
    for entry, (eco_changes, gt_builder) in zip(entries, cases, strict=False):
        content, review = reviewed_record(entry, candidates[entry.candidate_digest], eco_changes=eco_changes, gt_changes=gt_builder(entry))
        records.append(content)
        expected_reasons.append(review.exclusion_reason.value)

    outcome = _ingest(records, state, candidates)

    assert outcome.status is CohortBatchStatus.INSUFFICIENT
    assert outcome.insufficient_reason is CohortInsufficientReason.INSUFFICIENT_ACCEPTED_POSITIVES
    assert outcome.accepted_positives == ()
    assert sorted(expected_reasons) == sorted(item.reason for item in outcome.record_outcomes)
    assert outcome.pending_entries == tuple(sorted(entry.entry_digest for entry in entries[len(cases) :]))


def test_unknown_entry_missing_candidate_and_duplicate_records_are_closed():
    state, candidates = _prepared()
    entries = python_entries(state)
    js_entry = state.javascript_queue.entries[0]
    js_record = reviewed_record(js_entry, candidates[js_entry.candidate_digest])[0]
    unknown = reviewed_record(entries[0], candidates[entries[0].candidate_digest], entry_digest="1" * 64)[0]
    good, _ = reviewed_record(entries[1], candidates[entries[1].candidate_digest])
    thinned = dict(candidates)
    del thinned[entries[2].candidate_digest]
    missing, _ = reviewed_record(entries[2], candidates[entries[2].candidate_digest])

    outcome = _ingest([js_record, unknown, good, good, missing], state, thinned)

    reasons = _by_reason(outcome)
    unknown_digests = {item.queue_entry_digest for item in outcome.record_outcomes if item.reason == "queue_entry_unknown"}
    assert unknown_digests == {js_entry.entry_digest, "1" * 64}
    assert reasons["duplicate_record"].queue_entry_digest == entries[1].entry_digest
    assert reasons["candidate_evidence_missing"].queue_entry_digest == entries[2].entry_digest
    assert entries[0].entry_digest in outcome.pending_entries
    assert len(outcome.pending_entries) == len(entries) - 1


def test_stale_review_evidence_is_refused_closed():
    state, candidates = _prepared()
    entries = python_entries(state)
    stale, _ = reviewed_record(
        entries[0], candidates[entries[0].candidate_digest], gt_changes={"candidate_digest": "2" * 64}, derive_review=False
    )
    wrong_policy, _ = reviewed_record(
        entries[1], candidates[entries[1].candidate_digest], gt_changes={"policy_digest": ECOSYSTEM_POLICY}, derive_review=False
    )

    outcome = _ingest([stale, wrong_policy], state, candidates)

    reasons = _by_reason(outcome)
    assert reasons["review_evidence_invalid"].queue_entry_digest == entries[0].entry_digest
    assert [item.reason for item in outcome.record_outcomes].count("review_evidence_invalid") == 2


def test_external_records_are_hostile_decoded_and_label_blind():
    state, candidates = _prepared()
    entries = python_entries(state)
    good, _ = reviewed_record(entries[0], candidates[entries[0].candidate_digest])
    spaced = json.dumps(json.loads(good), sort_keys=True, indent=1).encode("utf-8")
    wrong_schema = json.dumps({**json.loads(good), "schema_version": "other.v1"}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    labeled = json.dumps({**json.loads(good), "verdict": "accepted"}, sort_keys=True, separators=(",", ":")).encode("utf-8")

    outcome = _ingest(
        [
            b"",
            b"not json at all",
            b'{"x":NaN}',
            b'{"x":1e999}',
            b'{"k":' + b"[" * 20000 + b"]" * 20000 + b"}",
            spaced,
            wrong_schema,
            labeled,
        ],
        state,
        candidates,
    )

    assert outcome.record_outcomes and all(item.status.value == "excluded" for item in outcome.record_outcomes)
    assert sum(1 for item in outcome.record_outcomes if item.reason == "record_unreadable") == 6
    assert sum(1 for item in outcome.record_outcomes if item.reason == "record_schema_mismatch") == 2
    assert outcome.pending_entries == tuple(sorted(entry.entry_digest for entry in entries))
    assert outcome.status is CohortBatchStatus.INSUFFICIENT
    assert outcome.insufficient_reason is CohortInsufficientReason.INSUFFICIENT_ACCEPTED_POSITIVES


def test_ingestion_module_and_outputs_are_label_blind():
    root = Path(__file__).resolve().parents[1]
    for name in ("benchmarks/valid/cohort_ingestion.py", "benchmarks/valid/cohort_ingestion_store.py"):
        source = (root / name).read_bytes()
        for forbidden in (b"admission", b"detector", b"observation", b"label", b"verdict", b"score"):
            assert forbidden not in source, f"{name} references out-of-scope machinery: {forbidden!r}"
    state, candidates = _prepared()
    content = cohort_batch_bytes(_ingest(_good_records(state, candidates), state, candidates))
    for forbidden in (b"admission", b"detector", b"observation", b"label", b"verdict", b"score"):
        assert forbidden not in content


def test_zero_input_batches_are_refused_not_clean():
    state, candidates = _prepared()
    empty = _ingest([], state, candidates)
    assert empty.status is CohortBatchStatus.INSUFFICIENT
    assert empty.insufficient_reason is CohortInsufficientReason.BATCH_EMPTY
    assert empty.record_outcomes == () and empty.accepted_positives == ()

    js_only, js_resolver = python_cohort_state([request_for("js-00"), request_for("js-01")])
    assert js_only.python_queue.entries == ()
    js_candidates = candidates_for([request_for("js-00"), request_for("js-01")], js_resolver)
    entry = js_only.javascript_queue.entries[0]
    record, _ = reviewed_record(entry, js_candidates[entry.candidate_digest])
    outcome = _ingest([record], js_only, js_candidates)
    assert outcome.status is CohortBatchStatus.INSUFFICIENT
    assert outcome.insufficient_reason is CohortInsufficientReason.PYTHON_QUEUE_EMPTY


def test_batch_cap_refuses_over_twenty_records_with_every_record_ledgered():
    state, candidates = _prepared()
    records = _good_records(state, candidates)
    while len(records) <= COHORT_BATCH_CAP:
        records.append(records[0])
    records = records[: COHORT_BATCH_CAP + 1]

    outcome = _ingest(records, state, candidates)

    assert outcome.status is CohortBatchStatus.INSUFFICIENT
    assert outcome.insufficient_reason is CohortInsufficientReason.BATCH_CAP_EXCEEDED
    assert len(outcome.record_outcomes) == COHORT_BATCH_CAP + 1
    assert {item.reason for item in outcome.record_outcomes} == {"batch_unit_refused"}
    assert outcome.accepted_positives == ()
    assert outcome.pending_entries == tuple(sorted(entry.entry_digest for entry in python_entries(state)))


def test_reserved_repositories_cannot_reenter_through_a_record():
    resolved = resolver()
    py_url = "https://github.com/fixture/cohort-py-00"
    legacy = (legacy_reservation_source(resolved, repository=py_url, source_digest="a" * 64),)
    reserved_authority = authority(resolved, legacy=legacy)
    requests = [request_for(f"py-{index:02d}") for index in range(1, PYTHON_COUNT)] + [request_for("js-00")]
    state = _built(requests, authority_=reserved_authority, resolver_=resolved)
    candidates = candidates_for(requests, resolved)
    assert len(reserved_authority.current_census().reserved_network_digests) == 1
    assert py_url not in {entry.canonical_repository for entry in python_entries(state)}

    reserved_candidate = next(iter(candidates_for([request_for("py-00")], resolved).values()))
    entry = python_entries(state)[0]
    forged, _ = reviewed_record(entry, reserved_candidate)
    good_without_entry = [reviewed_record(item, candidates[item.candidate_digest])[0] for item in python_entries(state)[1:]]
    outcome = _ingest([forged, *good_without_entry], state, candidates)

    assert outcome.status is CohortBatchStatus.ACCEPTED
    assert len(outcome.accepted_positives) == PYTHON_COUNT - 2
    assert all(positive.candidate_digest != reserved_candidate.candidate_digest for positive in outcome.accepted_positives)
    assert outcome.census_digest == state.census_digest
    assert _by_reason(outcome)["review_evidence_invalid"].queue_entry_digest == entry.entry_digest
    assert entry.entry_digest in outcome.pending_entries


def test_insufficient_families_refusal_carries_its_attempt_exclusions():
    requests = [request_for("py-00"), request_for("py-00"), request_for("py-02")]
    with pytest.raises(InsufficientFamiliesRefusal) as error:
        _built(requests)
    assert error.value.reason is SourcingQueueReason.INSUFFICIENT_FAMILIES
    attempt = error.value.attempt_exclusions
    assert len(attempt) == 1
    assert attempt[0].reason is SourcingQueueReason.DUPLICATE_CANDIDATE


def test_tied_but_distinct_requests_order_by_remaining_content_digests():
    from benchmarks.valid.sourcing_queue import pending_queue_identities

    first = request_for("py-00", advisory_text="Tied advisory body one.")
    second = request_for("py-00", advisory_text="Tied advisory body two.")
    assert first.family.advisory_digest != second.family.advisory_digest

    forward = _built([first, second, request_for("js-01")], cap=1)
    backward = _built([second, first, request_for("js-01")], cap=1)

    assert forward.state_digest == backward.state_digest
    assert pending_queue_identities(forward) == pending_queue_identities(backward)
    assert forward.exclusions == backward.exclusions
    assert len(forward.python_queue.entries) == 1
    assert {item.reason for item in forward.exclusions} == {SourcingQueueReason.QUEUE_CAP_EXCEEDED}
