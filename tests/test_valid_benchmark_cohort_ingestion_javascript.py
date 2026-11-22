"""Bounded ingestion of the first independently reviewed JavaScript/TypeScript cohort."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cohort_ingestion_fixtures import (  # noqa: E402
    ECOSYSTEM_POLICY,
    GROUND_TRUTH_POLICY,
    JAVASCRIPT_COUNT,
    JAVASCRIPT_NAMES,
    PYTHON_COUNT,
    READ_POLICY,
    TYPESCRIPT_NAMES,
    _Client,
    _read_authority,
    _settings,
    authority,
    candidates_for,
    javascript_cohort_state,
    javascript_entries,
    python_cohort_state,
    request_for,
    resolver,
    reviewed_record,
)

from benchmarks.valid import (
    cohort_ingestion,  # noqa: E402
    cohort_ingestion_store,  # noqa: E402
)
from benchmarks.valid.artifact_repository import S3ArtifactRepository  # noqa: E402
from benchmarks.valid.cohort_ingestion import (  # noqa: E402
    COHORT_BATCH_CAP,
    JAVASCRIPT_COHORT_BATCH_SCHEMA,
    MINIMUM_ACCEPTED_POSITIVES,
    CohortBatchStatus,
    CohortInsufficientReason,
    CohortStateError,
    CohortStateReason,
    cohort_batch,
    cohort_batch_bytes,
    cohort_batch_value,
    ingest_javascript_cohort_batch,
)
from benchmarks.valid.ecosystem_review import EcosystemReviewDecision  # noqa: E402
from benchmarks.valid.ground_truth_review import GroundTruthReviewError, GroundTruthStatus, VerifiedScope  # noqa: E402
from benchmarks.valid.replacement_artifact_contract import ArtifactKind  # noqa: E402
from benchmarks.valid.reservation import legacy_reservation_source  # noqa: E402
from openultrasast.core.canonical import bytes_digest  # noqa: E402

JAVASCRIPT_REQUEST_NAMES = (*JAVASCRIPT_NAMES, *TYPESCRIPT_NAMES)


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
    return ingest_javascript_cohort_batch(
        records,
        state=state,
        candidates_by_digest=candidates,
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )


def _prepared():
    state, resolved = javascript_cohort_state()
    requests = [request_for(name) for name in JAVASCRIPT_REQUEST_NAMES]
    return state, candidates_for(requests, resolved)


def _js_records(state, candidates):
    return [
        reviewed_record(entry, candidates[entry.candidate_digest], ecosystem="javascript")[0]
        for entry in javascript_entries(state)
    ]


def _by_reason(outcome):
    return {item.reason: item for item in outcome.record_outcomes if item.reason is not None}


def _tampered_bytes(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def test_first_bounded_javascript_batch_reaches_ten_accepted_reachable_positives():
    state, candidates = _prepared()
    records = _js_records(state, candidates)

    assert len(records) == JAVASCRIPT_COUNT <= COHORT_BATCH_CAP
    assert all(records)
    outcome = _ingest(records, state, candidates)

    assert outcome.status is CohortBatchStatus.ACCEPTED
    assert outcome.insufficient_reason is None
    assert outcome.ecosystem == "javascript"
    assert len(outcome.accepted_positives) == JAVASCRIPT_COUNT >= MINIMUM_ACCEPTED_POSITIVES
    assert outcome.pending_entries == ()
    assert all(item.status.value == "accepted" for item in outcome.record_outcomes)
    families = {scope.vulnerability_family for positive in outcome.accepted_positives for scope in positive.verified_scopes}
    assert len(families) >= 2
    assert all(scope.ecosystem.value == "javascript" for positive in outcome.accepted_positives for scope in positive.verified_scopes)
    assert outcome.census_digest == state.census_digest
    assert outcome.queue_digest == state.javascript_queue.queue_digest
    assert cohort_batch_value(outcome)["schema_version"] == JAVASCRIPT_COHORT_BATCH_SCHEMA

    shuffled = list(reversed(records))
    replayed = _ingest(shuffled, state, candidates)
    assert replayed == outcome
    assert replayed.batch_digest == outcome.batch_digest


def test_typescript_stays_observed_language_evidence_under_the_javascript_ecosystem():
    state, candidates = _prepared()
    entries = javascript_entries(state)
    typescript_entries = [entry for entry in entries if entry.observed_language == "typescript"]
    assert len(typescript_entries) == len(TYPESCRIPT_NAMES) >= 1
    assert {entry.canonical_ecosystem for entry in typescript_entries} == {"javascript"}
    assert {entry.observed_language for entry in entries} == {"javascript", "typescript"}

    records = _js_records(state, candidates)
    outcome = _ingest(records, state, candidates)
    assert outcome.status is CohortBatchStatus.ACCEPTED

    by_entry = {item.queue_entry_digest: item for item in outcome.record_outcomes}
    assert all(by_entry[entry.entry_digest].status.value == "accepted" for entry in typescript_entries)
    typescript_candidates = {entry.candidate_digest for entry in typescript_entries}
    for positive in outcome.accepted_positives:
        if positive.candidate_digest in typescript_candidates:
            assert all(scope.ecosystem.value == "javascript" for scope in positive.verified_scopes)

    index = entries.index(typescript_entries[0])
    minted_payload = json.loads(records[index])
    minted_payload["ground_truth_attestation"]["verified_scopes"] = [
        {"vulnerability_family": typescript_entries[0].family.vulnerability_family, "ecosystem": "typescript"}
    ]
    minted = list(records)
    minted[index] = _tampered_bytes(minted_payload)
    refused = _ingest(minted, state, candidates)
    item = next(item for item in refused.record_outcomes if item.queue_entry_digest == typescript_entries[0].entry_digest)
    assert item.status.value == "excluded"
    assert item.reason == "record_schema_mismatch"
    assert typescript_entries[0].entry_digest in refused.pending_entries

    with pytest.raises(CohortStateError) as error:
        cohort_batch(
            ecosystem="typescript",
            queue_digest="0" * 64,
            census_digest="0" * 64,
            ecosystem_policy_digest="0" * 64,
            ground_truth_policy_digest="0" * 64,
            record_outcomes=(),
            pending_entries=(),
            accepted_positives=(),
            status=CohortBatchStatus.INSUFFICIENT,
            insufficient_reason=CohortInsufficientReason.BATCH_EMPTY,
        )
    assert error.value.reason is CohortStateReason.STATE_MISMATCH


def test_every_accepted_and_excluded_javascript_candidate_replays_from_external_review_evidence():
    state, candidates = _prepared()
    entries = javascript_entries(state)
    cases = [
        ({"decision": EcosystemReviewDecision.PYTHON}, lambda entry: {}),
        (None, lambda entry: {"reviewer_identity": f"producer-{entry.family.advisory_locator}@example.invalid"}),
        (None, lambda entry: {"conflict_disclosed": False}),
        (None, lambda entry: {"policy_satisfied": False}),
        (None, lambda entry: {"defect_present": None}),
        (None, lambda entry: {"in_repository_reachable": False}),
        (None, lambda entry: {"verified_scopes": ()}),
        (None, lambda entry: {"verified_scopes": (VerifiedScope("injection", "python"),)}),
    ]
    records = []
    expected = {}
    for index, entry in enumerate(entries):
        eco_changes, gt_builder = cases[index] if index < len(cases) else (None, None)
        content, review = reviewed_record(
            entry,
            candidates[entry.candidate_digest],
            ecosystem="javascript",
            eco_changes=eco_changes,
            gt_changes=gt_builder(entry) if index < len(cases) else None,
        )
        records.append(content)
        expected[entry.entry_digest] = review
    unknown = reviewed_record(
        entries[0], candidates[entries[0].candidate_digest], ecosystem="javascript", entry_digest="3" * 64
    )[0]
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


def test_missing_external_decisions_leave_the_javascript_cohort_pending():
    state, candidates = _prepared()
    entries = javascript_entries(state)

    empty = _ingest([], state, candidates)
    assert empty.status is CohortBatchStatus.INSUFFICIENT
    assert empty.insufficient_reason is CohortInsufficientReason.BATCH_EMPTY
    assert empty.record_outcomes == () and empty.accepted_positives == ()
    assert empty.pending_entries == tuple(sorted(entry.entry_digest for entry in entries))

    partial = _js_records(state, candidates)[: MINIMUM_ACCEPTED_POSITIVES - 1]
    outcome = _ingest(partial, state, candidates)
    assert outcome.status is CohortBatchStatus.INSUFFICIENT
    assert outcome.insufficient_reason is CohortInsufficientReason.INSUFFICIENT_ACCEPTED_POSITIVES
    assert all(item.status.value == "accepted" for item in outcome.record_outcomes)
    assert outcome.pending_entries == tuple(sorted(entry.entry_digest for entry in entries[MINIMUM_ACCEPTED_POSITIVES - 1 :]))

    python_requests = [request_for(f"py-{index:02d}") for index in range(PYTHON_COUNT)]
    python_only, python_resolver = python_cohort_state(python_requests)
    assert python_only.javascript_queue.entries == ()
    python_candidates = candidates_for(python_requests, python_resolver)
    python_entry = python_only.python_queue.entries[0]
    python_record = reviewed_record(python_entry, python_candidates[python_entry.candidate_digest])[0]
    refused = _ingest([python_record], python_only, python_candidates)
    assert refused.status is CohortBatchStatus.INSUFFICIENT
    assert refused.insufficient_reason is CohortInsufficientReason.JAVASCRIPT_QUEUE_EMPTY
    assert refused.accepted_positives == ()


def test_javascript_records_are_hostile_decoded_and_label_blind():
    state, candidates = _prepared()
    entries = javascript_entries(state)
    good, _ = reviewed_record(entries[0], candidates[entries[0].candidate_digest], ecosystem="javascript")
    spaced = json.dumps(json.loads(good), sort_keys=True, indent=1).encode("utf-8")
    wrong_schema = json.dumps({**json.loads(good), "schema_version": "other.v1"}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    labeled = json.dumps({**json.loads(good), "verdict": "accepted"}, sort_keys=True, separators=(",", ":")).encode("utf-8")

    outcome = _ingest(
        [b"", b"not json at all", b'{"x":NaN}', b'{"x":1e999}', b'{"k":' + b"[" * 20000 + b"]" * 20000 + b"}",
         spaced, wrong_schema, labeled],
        state,
        candidates,
    )

    assert outcome.record_outcomes and all(item.status.value == "excluded" for item in outcome.record_outcomes)
    assert sum(1 for item in outcome.record_outcomes if item.reason == "record_unreadable") == 6
    assert sum(1 for item in outcome.record_outcomes if item.reason == "record_schema_mismatch") == 2
    assert outcome.pending_entries == tuple(sorted(entry.entry_digest for entry in entries))
    assert outcome.status is CohortBatchStatus.INSUFFICIENT
    assert outcome.insufficient_reason is CohortInsufficientReason.INSUFFICIENT_ACCEPTED_POSITIVES
    content = cohort_batch_bytes(outcome)
    for forbidden in (b"admission", b"detector", b"observation", b"label", b"verdict", b"score"):
        assert forbidden not in content


def test_unknown_duplicate_missing_and_reserved_javascript_records_stay_closed():
    state, candidates = _prepared()
    entries = javascript_entries(state)
    unknown = reviewed_record(
        entries[0], candidates[entries[0].candidate_digest], ecosystem="javascript", entry_digest="4" * 64
    )[0]
    good, _ = reviewed_record(entries[1], candidates[entries[1].candidate_digest], ecosystem="javascript")
    thinned = dict(candidates)
    del thinned[entries[2].candidate_digest]
    missing, _ = reviewed_record(entries[2], candidates[entries[2].candidate_digest], ecosystem="javascript")

    outcome = _ingest([unknown, good, good, missing], state, thinned)

    reasons = _by_reason(outcome)
    assert reasons["duplicate_record"].queue_entry_digest == entries[1].entry_digest
    assert reasons["candidate_evidence_missing"].queue_entry_digest == entries[2].entry_digest
    assert entries[0].entry_digest in outcome.pending_entries
    assert len(outcome.pending_entries) == len(entries) - 1

    resolved = resolver()
    js_url = "https://github.com/fixture/cohort-js-00"
    legacy = (legacy_reservation_source(resolved, repository=js_url, source_digest="b" * 64),)
    reserved_authority = authority(resolved, legacy=legacy)
    names = [name for name in JAVASCRIPT_REQUEST_NAMES if name != "js-00"]
    reserved_requests = [request_for(name) for name in names]
    reserved_state, _ = javascript_cohort_state(
        reserved_requests, resolver_=resolved, authority_=reserved_authority
    )
    reserved_candidates = candidates_for(reserved_requests, resolved)
    assert js_url not in {entry.canonical_repository for entry in javascript_entries(reserved_state)}
    reserved_candidate = next(iter(candidates_for([request_for("js-00")], resolved).values()))
    entry = javascript_entries(reserved_state)[0]
    forged, _ = reviewed_record(entry, reserved_candidate, ecosystem="javascript")
    good_without_entry = [
        reviewed_record(item, reserved_candidates[item.candidate_digest], ecosystem="javascript")[0]
        for item in javascript_entries(reserved_state)[1:]
    ]
    reserved_outcome = _ingest([forged, *good_without_entry], reserved_state, reserved_candidates)

    assert reserved_outcome.status is CohortBatchStatus.ACCEPTED
    assert len(reserved_outcome.accepted_positives) == JAVASCRIPT_COUNT - 2
    assert all(positive.candidate_digest != reserved_candidate.candidate_digest for positive in reserved_outcome.accepted_positives)
    assert _by_reason(reserved_outcome)["review_evidence_invalid"].queue_entry_digest == entry.entry_digest
    assert entry.entry_digest in reserved_outcome.pending_entries


def test_javascript_batch_cap_refuses_over_twenty_records_with_every_record_ledgered():
    state, candidates = _prepared()
    records = _js_records(state, candidates)
    while len(records) <= COHORT_BATCH_CAP:
        records.append(records[0])
    records = records[: COHORT_BATCH_CAP + 1]

    outcome = _ingest(records, state, candidates)

    assert outcome.status is CohortBatchStatus.INSUFFICIENT
    assert outcome.insufficient_reason is CohortInsufficientReason.BATCH_CAP_EXCEEDED
    assert len(outcome.record_outcomes) == COHORT_BATCH_CAP + 1
    assert {item.reason for item in outcome.record_outcomes} == {"batch_unit_refused"}
    assert outcome.accepted_positives == ()
    assert outcome.pending_entries == tuple(sorted(entry.entry_digest for entry in javascript_entries(state)))


def test_javascript_batch_persists_resumes_and_replays_from_durable_evidence():
    client = _Client()
    store = S3ArtifactRepository(_settings(), client)
    state, candidates = _prepared()
    records = _js_records(state, candidates)
    outcome = _ingest(records, state, candidates)
    assert outcome.status is CohortBatchStatus.ACCEPTED

    record_references = cohort_ingestion_store.publish_external_review_records(store, records)
    reference = cohort_ingestion_store.persist_cohort_batch(store, outcome)
    assert cohort_ingestion_store.persist_cohort_batch(store, outcome) == reference
    accepted = store.get(
        reference, expected_kind=ArtifactKind.REVIEW, authority=_read_authority(), expected_access_policy_digest=READ_POLICY
    )
    assert accepted.artifact.payload["ecosystem"] == "javascript"

    restarted = S3ArtifactRepository(_settings(), client)
    resumed = cohort_ingestion_store.resume_cohort_batch(
        restarted, reference, authority=_read_authority(), expected_access_policy_digest=READ_POLICY
    )
    assert resumed == outcome
    assert cohort_batch_bytes(resumed) == cohort_batch_bytes(outcome)

    reread = cohort_ingestion_store.read_external_review_records(
        restarted, record_references, authority=_read_authority(), expected_access_policy_digest=READ_POLICY
    )
    replayed = _ingest(reread, state, candidates)
    assert replayed == outcome
    assert replayed.batch_digest == outcome.batch_digest


def test_decode_cohort_batch_closes_forged_digest_and_ecosystem_fields():
    state, candidates = _prepared()
    partial = _js_records(state, candidates)[: JAVASCRIPT_COUNT - 2]
    outcome = _ingest(partial, state, candidates)
    content = cohort_batch_bytes(outcome)
    decode = cohort_ingestion_store.decode_cohort_batch

    forged_pending = json.loads(content)
    forged_pending["pending_entries"] = ["not-a-digest"]
    with pytest.raises(CohortStateError):
        decode(_tampered_bytes(forged_pending))

    forged_entry_digest = json.loads(content)
    forged_entry_digest["record_outcomes"][0]["queue_entry_digest"] = "typescript"
    with pytest.raises(CohortStateError):
        decode(_tampered_bytes(forged_entry_digest))

    forged_review_digest = json.loads(content)
    forged_review_digest["record_outcomes"][0]["ground_truth_review_digest"] = "javascript"
    with pytest.raises(CohortStateError):
        decode(_tampered_bytes(forged_review_digest))

    minted_ecosystem = json.loads(content)
    minted_ecosystem["ecosystem"] = "typescript"
    with pytest.raises(CohortStateError):
        decode(_tampered_bytes(minted_ecosystem))

    assert decode(content) == outcome


def test_projection_failure_is_a_closed_state_refusal(monkeypatch):
    state, candidates = _prepared()
    records = _js_records(state, candidates)[:1]

    def refusing(*args, **kwargs):
        raise GroundTruthReviewError("projection diverged from the reviewed inputs")

    monkeypatch.setattr(cohort_ingestion, "project_accepted_ground_truth", refusing)
    with pytest.raises(CohortStateError) as error:
        _ingest(records, state, candidates)
    assert error.value.reason is CohortStateReason.STATE_MISMATCH
